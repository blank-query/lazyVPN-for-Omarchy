package netlink

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// InterfaceStats holds traffic statistics for an interface
type InterfaceStats struct {
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
	Timestamp time.Time
}

// GetInterfaceStats retrieves current statistics for an interface using netlink
func GetInterfaceStats(name string) (*InterfaceStats, error) {
	link, err := nlLinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %w", err)
	}

	attrs := link.Attrs()
	if attrs == nil || attrs.Statistics == nil {
		// Fallback to /proc/net/dev
		return getStatsFromProc(name)
	}

	return &InterfaceStats{
		RxBytes:   attrs.Statistics.RxBytes,
		TxBytes:   attrs.Statistics.TxBytes,
		RxPackets: attrs.Statistics.RxPackets,
		TxPackets: attrs.Statistics.TxPackets,
		Timestamp: time.Now(),
	}, nil
}

// getStatsFromProc reads interface statistics from /proc/net/dev
func getStatsFromProc(name string) (*InterfaceStats, error) {
	file, err := os.Open(procNetDevPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", procNetDevPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip header lines
		if strings.Contains(line, "|") {
			continue
		}

		// Parse interface line: "  eth0: 12345 67 ..."
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		ifaceName := strings.TrimSpace(parts[0])
		if ifaceName != name {
			continue
		}

		// Parse statistics fields
		// Format: bytes packets errs drop fifo frame compressed multicast | bytes packets ...
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}

		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[9], 10, 64)

		return &InterfaceStats{
			RxBytes:   rxBytes,
			TxBytes:   txBytes,
			RxPackets: rxPackets,
			TxPackets: txPackets,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("interface %s not found in /proc/net/dev", name)
}

// FormatBytes formats bytes into human-readable string
func FormatBytes(bytes float64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", bytes/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", bytes/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", bytes/KB)
	default:
		return fmt.Sprintf("%.0f B", bytes)
	}
}

// FormatBitsPerSec formats bytes/sec into human-readable bits/sec string
func FormatBitsPerSec(bps float64) string {
	bits := bps * 8
	const (
		Kbit = 1000
		Mbit = Kbit * 1000
		Gbit = Mbit * 1000
	)

	switch {
	case bits >= Gbit:
		return fmt.Sprintf("%.2f Gbps", bits/Gbit)
	case bits >= Mbit:
		return fmt.Sprintf("%.2f Mbps", bits/Mbit)
	case bits >= Kbit:
		return fmt.Sprintf("%.2f Kbps", bits/Kbit)
	default:
		return fmt.Sprintf("%.0f bps", bits)
	}
}

// FormatBytesPerSec formats bytes/sec into human-readable string
func FormatBytesPerSec(bps float64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bps >= GB:
		return fmt.Sprintf("%.2f GB/s", bps/GB)
	case bps >= MB:
		return fmt.Sprintf("%.2f MB/s", bps/MB)
	case bps >= KB:
		return fmt.Sprintf("%.2f KB/s", bps/KB)
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}
