//go:build darwin

package engine

import (
	"context"
	"encoding/binary"
	"net"
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
// Source: the NET_RT_IFLIST2 routing sysctl. It dumps one RTM_IFINFO2
// message per interface, each carrying a struct if_msghdr2 whose ifm_data
// (if_data64) holds cumulative 64-bit received (ifi_ibytes) and sent
// (ifi_obytes) octets.
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

const darwinIFTLoop = 24 // IFT_LOOP from <net/if_types.h> (loopback)

// Field offsets inside the kernel's struct if_msghdr2 / if_data64. They are
// derived from the cgo-mirrored unix.IfMsghdr2 (whose layout is generated
// from the SDK headers), so they follow the real kernel ABI — including the
// alignment padding that a packed decoder like encoding/binary would skip.
var (
	darwinOffFlags  = unsafe.Offsetof(unix.IfMsghdr2{}.Flags)
	darwinOffIndex  = unsafe.Offsetof(unix.IfMsghdr2{}.Index)
	darwinOffData   = unsafe.Offsetof(unix.IfMsghdr2{}.Data)
	darwinOffType   = darwinOffData + unsafe.Offsetof(unix.IfData64{}.Type)
	darwinOffIbytes = darwinOffData + unsafe.Offsetof(unix.IfData64{}.Ibytes)
	darwinOffObytes = darwinOffData + unsafe.Offsetof(unix.IfData64{}.Obytes)
)

// readCountersDarwin reads cumulative rx/tx byte counters for every up,
// non-loopback interface from the NET_RT_IFLIST2 routing sysctl. When seen
// is non-nil it is populated with the counters; it always returns the full
// map and the interface names.
func readCountersDarwin(seen map[string]counters) (map[string]counters, []string) {
	total := map[string]counters{}
	var names []string

	// MIB: CTL_NET, PF_ROUTE, protocol 0, extra 0, NET_RT_IFLIST2, seq 0.
	rib, err := unix.SysctlRaw("net", unix.AF_ROUTE, 0, 0, unix.NET_RT_IFLIST2, 0)
	if err != nil {
		return total, names
	}

	for off, n := 0, len(rib); off+4 <= n; {
		msglen := int(binary.LittleEndian.Uint16(rib[off : off+2]))
		if msglen < 4 || off+msglen > n {
			break // malformed trailer; keep what we collected so far
		}
		msg := rib[off : off+msglen]
		off += msglen

		// Only interface-info messages are of interest here.
		if msg[2] != unix.RTM_VERSION || msg[3] != unix.RTM_IFINFO2 {
			continue
		}
		if len(msg) <= int(darwinOffObytes)+8 {
			continue // shorter than a full if_msghdr2; skip
		}

		flags := int32(binary.LittleEndian.Uint32(msg[darwinOffFlags:]))
		name := ifNameFromMessage(msg, int(darwinOffData))
		if name == "" {
			// Fall back to the interfaces table if the message carried
			// no AF_LINK address (should not happen for RTM_IFINFO2).
			idx := binary.LittleEndian.Uint16(msg[darwinOffIndex:])
			if iface, err := net.InterfaceByIndex(int(idx)); err == nil {
				name = iface.Name
			}
		}
		if name == "" || name == "lo0" {
			continue
		}
		if flags&unix.IFF_UP == 0 {
			continue // not operationally up
		}
		if msg[darwinOffType] == darwinIFTLoop {
			continue
		}

		rx := binary.LittleEndian.Uint64(msg[darwinOffIbytes:])
		tx := binary.LittleEndian.Uint64(msg[darwinOffObytes:])
		c := counters{rx: rx, tx: tx}
		total[name] = c
		if seen != nil {
			seen[name] = c
		}
		names = append(names, name)
	}
	return total, names
}

// ifNameFromMessage extracts the interface name from the AF_LINK sockaddr
// that follows the if_msghdr2 header in a routing message. The name is the
// first sdl_nlen bytes of sockaddr_dl's sdl_data (e.g. "en0", "utun3").
func ifNameFromMessage(msg []byte, start int) string {
	for off := start; off+8 <= len(msg); {
		saLen := int(msg[off])
		if saLen < 8 || off+saLen > len(msg) {
			return ""
		}
		if msg[off+1] == unix.AF_LINK {
			nlen := int(msg[off+5]) // sdl_nlen
			if 8+nlen <= saLen {
				return string(msg[off+8 : off+8+nlen])
			}
			return ""
		}
		off += (saLen + 3) &^ 3 // sockaddrs are padded to 4-byte boundaries
	}
	return ""
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
