//go:build darwin

package engine

import (
	"context"
	"encoding/binary"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// RunMonitor is the real Bandwidth Monitor engine for macOS. Like the Linux
// version it generates no traffic: it reads the kernel's per-interface byte
// counters (the same source as netstat -ib) and derives the actual download /
// upload throughput of the whole machine from byte deltas between samples.
// It runs until ctx is cancelled.
//
// Source: the net.link.generic.ifdata.<index>.1 sysctl (IFDATA_GENERAL).
// Each call returns a struct ifmibdata whose ifmd_data (if_data64) holds
// cumulative 64-bit received (ifi_ibytes) and sent (ifi_obytes) octets.
//
// This sysctl is used instead of the NET_RT_IFLIST2 routing dump because
// the latter quantises counters to 1 KiB steps and truncates them to 32
// bits for non-Apple-signed processes (anti-fingerprinting; see
// rdar://106029568), which would corrupt the rates.
//
// Scope: every "up" interface except loopback is summed, so the numbers
// reflect total machine throughput (Wi-Fi, Ethernet, VPN, LAN, ...).
func RunMonitor(ctx context.Context, p *Progress, sampleInterval time.Duration) {
	// Set the source label before signalling "connected" so the UI's
	// phaseMsg handler sees the name and renders the "watching <adapters>"
	// header (it would otherwise drop it on a to-the-tick race).
	p.ServerName = discoverAdaptersDarwin()
	sendPhase(p, PhaseConnected)

	prev := map[string]counters{}

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			if last.IsZero() {
				_, _ = readCountersDarwin(prev)
				last = t
				continue
			}
			elapsed := t.Sub(last).Seconds()
			last = t
			if elapsed <= 0 {
				continue
			}

			total, names := readCountersDarwin(nil)
			if len(names) > 0 {
				p.ServerName = strings.Join(names, ", ")
			}

			var rx, tx uint64
			for iface, c := range total {
				base, ok := prev[iface]
				if !ok {
					prev[iface] = c
					continue
				}
				rx += safeDelta(base.rx, c.rx)
				tx += safeDelta(base.tx, c.tx)
				prev[iface] = c
			}

			_ = sendSample(p, Sample{Phase: PhaseDownload, Rate: float64(rx) / elapsed, At: t})
			_ = sendSample(p, Sample{Phase: PhaseUpload, Rate: float64(tx) / elapsed, At: t})
		}
	}
}

const (
	darwinIFTLoop       = 24 // IFT_LOOP from <net/if_types.h> (loopback)
	darwinIfdataGeneral = 1  // IFDATA_GENERAL selector

	// Offsets of the fixed header fields of the kernel's struct ifmibdata
	// (<net/if_mib.h>): ifmd_name[IFNAMSIZ] then ifmd_pcount, ifmd_flags.
	darwinOffName  = 0
	darwinOffFlags = 20

	// Offsets inside struct if_data64, taken from the cgo-generated
	// unix.IfData64 (its layout is generated from the SDK headers and thus
	// matches the kernel ABI field-for-field).
	darwinOffIfType   = int(unsafe.Offsetof(unix.IfData64{}.Type))
	darwinOffIfIbytes = int(unsafe.Offsetof(unix.IfData64{}.Ibytes))
	darwinOffIfObytes = int(unsafe.Offsetof(unix.IfData64{}.Obytes))
	darwinSizeIfData  = int(unsafe.Sizeof(unix.IfData64{}))
)

// readCountersDarwin reads cumulative rx/tx byte counters for every up,
// non-loopback interface. When seen is non-nil it is populated with the
// counters; it always returns the full map and the interface names.
//
// Note on layout: the kernel (xnu) packs the trailing if_data64 block right
// after the header fields, while the userland SDK header pads it to an
// 8-byte boundary — the sysctl therefore returns 180 bytes, not the 184 the
// SDK struct suggests. Instead of assuming an offset, the if_data64 block
// is located at the end of the reply (len - sizeof(if_data64)), which keeps
// the parser correct on either layout. Values were verified to match
// netstat -ib byte for byte.
func readCountersDarwin(seen map[string]counters) (map[string]counters, []string) {
	total := map[string]counters{}
	var names []string

	for idx := 1; ; idx++ {
		raw, err := unix.SysctlRaw("net.link.generic.ifdata", idx, darwinIfdataGeneral)
		if err != nil {
			break // past the highest interface index; we are done
		}
		base := len(raw) - darwinSizeIfData
		if base < darwinOffFlags+4 || len(raw) < darwinSizeIfData {
			continue // unexpected kernel ABI; skip rather than misread
		}

		name := strings.TrimRight(string(raw[darwinOffName:darwinOffName+16]), "\x00")
		if name == "" || name == "lo0" {
			continue
		}
		flags := binary.LittleEndian.Uint32(raw[darwinOffFlags:])
		if flags&unix.IFF_UP == 0 {
			continue // not operationally up
		}
		if raw[base+darwinOffIfType] == darwinIFTLoop {
			continue
		}

		rx := binary.LittleEndian.Uint64(raw[base+darwinOffIfIbytes:])
		tx := binary.LittleEndian.Uint64(raw[base+darwinOffIfObytes:])
		c := counters{rx: rx, tx: tx}
		total[name] = c
		if seen != nil {
			seen[name] = c
		}
		names = append(names, name)
	}
	return total, names
}

// discoverAdaptersDarwin returns a friendly comma-separated label of the up,
// non-loopback interfaces (used as the monitor's "source" name).
func discoverAdaptersDarwin() string {
	_, names := readCountersDarwin(nil)
	if len(names) == 0 {
		return "no active interfaces"
	}
	return strings.Join(names, ", ")
}
