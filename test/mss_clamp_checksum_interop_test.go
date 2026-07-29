package test

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

func TestOpenVPNInteropClampedUnalignedMSSOptionKeepsTCPChecksumValid(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "mss-alignment-server.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		DataCiphersDirective: "data-ciphers",
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "mss-alignment-server.log")),
	})
	serverContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-mss-alignment-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "mss-alignment-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "mss-alignment-server.log"), "Initialization Sequence Completed", 20*time.Second)

	clientContext, cancelClient := context.WithTimeout(context.Background(), 60*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:     clientContext,
		Mode:        openvpn.ModeTLS,
		Transport:   clientTransportOptions(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4"),
		DataChannel: openvpn.ClientDataChannelOptions{MSSFix: 1200},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancelClient()
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 20*time.Second)
	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	sourceAddress, destinationAddress := tunnelEchoAddresses(configuration)

	const (
		alignedSourcePort        = 40001
		alignedDestinationPort   = 7
		unalignedSourcePort      = 40002
		unalignedDestinationPort = 9
		clampedMSS               = 1136
	)
	alignedSYN := buildIPv4TCPSYNPacket(t, sourceAddress, destinationAddress, alignedSourcePort, alignedDestinationPort, 1460, 0)
	writeClientDataPacket(t, client, alignedSYN, 10*time.Second)
	awaitTunnelTCPReset(t, client, alignedSourcePort, alignedDestinationPort, 10*time.Second, "aligned MSS option")

	capture := startInteropPacketCapture(t, serverContainer, workspace, "unaligned-mss",
		fmt.Sprintf("tcp dst port %d and tcp[tcpflags] & tcp-syn != 0", unalignedDestinationPort))
	unalignedSYN := buildIPv4TCPSYNPacket(t, sourceAddress, destinationAddress, unalignedSourcePort, unalignedDestinationPort, 1460, 1)
	writeClientDataPacket(t, client, unalignedSYN, 10*time.Second)
	decodedPackets := capture.Decode(t)
	expectedMSS := fmt.Sprintf("mss %d", clampedMSS)
	if !strings.Contains(decodedPackets, expectedMSS) {
		t.Fatalf("expected %q in peer TUN capture:\n%s", expectedMSS, decodedPackets)
	}
	if !strings.Contains(decodedPackets, "cksum 0x") {
		t.Fatalf("tcpdump did not verify the TCP checksum of the captured SYN:\n%s", decodedPackets)
	}
	if !strings.Contains(decodedPackets, "(correct)") {
		t.Fatalf("clamped SYN reached the peer TUN with an invalid checksum:\n%s", decodedPackets)
	}
	awaitTunnelTCPReset(t, client, unalignedSourcePort, unalignedDestinationPort, 10*time.Second, "unaligned MSS option")
}

func awaitTunnelTCPReset(t *testing.T, client *openvpn.Client, requestSourcePort uint16, requestDestinationPort uint16, timeout time.Duration, description string) {
	t.Helper()
	readContext, cancelRead := context.WithTimeout(context.Background(), timeout)
	defer cancelRead()
	for {
		packet, err := client.ReadDataPacket(readContext)
		if err != nil {
			t.Fatalf("the peer stack never answered the SYN carrying an %s: %v", description, err)
		}
		if isTCPResetPacket(packet, requestDestinationPort, requestSourcePort) {
			return
		}
	}
}

func isTCPResetPacket(packet []byte, sourcePort uint16, destinationPort uint16) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 6 {
		return false
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || len(packet) < headerLength+20 {
		return false
	}
	segment := packet[headerLength:]
	if binary.BigEndian.Uint16(segment[0:2]) != sourcePort || binary.BigEndian.Uint16(segment[2:4]) != destinationPort {
		return false
	}
	return segment[13]&0x04 != 0
}
