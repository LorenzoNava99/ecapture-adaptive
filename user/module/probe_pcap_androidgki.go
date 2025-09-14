//go:build androidgki

package module

import (
	"bytes"
	"net"
	"sync"
	"time"

	manager "github.com/gojue/ebpfmanager"
)

// Stub implementation for Android GKI - pcap functionality disabled
// The real pcap functionality is not available on Android due to libpcap dependency

// TcPacket stub for Android
type TcPacket struct {
	data      []byte
	timestamp time.Time
}

// MTCProbe stub for Android - provides minimal interface compatibility
type MTCProbe struct {
	Module
	// Fields needed for compilation compatibility
	pcapngFilename  string
	ifIdex          int
	ifName          string
	startTime       uint64
	bootTime        uint64
	tcPackets       []*TcPacket
	masterKeyBuffer *bytes.Buffer
	tcPacketLocker  *sync.Mutex
	tcPacketsChan   chan *TcPacket
}

// Required stub methods to satisfy interfaces
func (t *MTCProbe) writePacket(length uint32, timestamp time.Time, payload []byte) error {
	// No-op for Android
	return nil
}

func (t *MTCProbe) dumpTcSkb(tcEvent interface{}) error {
	// No-op for Android
	return nil
}

func (t *MTCProbe) savePcapngSslKeyLog(sslKey interface{}) error {
	// No-op for Android
	return nil
}

func (t *MTCProbe) createPcapng(netIfs []net.Interface) error {
	// No-op for Android
	return nil
}

func (t *MTCProbe) ServePcap() {
	// No-op for Android
}

// prepareInsnPatchers stub for Android
func prepareInsnPatchers(m *manager.Manager, ebpfFuncs []string, pcapFilter string) []manager.InstructionPatcherFunc {
	// No-op for Android - return empty slice
	return []manager.InstructionPatcherFunc{}
}