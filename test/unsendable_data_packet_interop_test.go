package test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

// forward.c process_incoming_tun runs encrypt_sign only for a tun buffer with
// len > 0, fragment_outgoing zeroes the buffer of a datagram it cannot frame,
// and process_outgoing_link writes nothing for a buffer of length zero.  Both
// drops are per datagram: the packets queued behind them still reach the link.
const (
	unsendableDataPacketFragment = 600
	unsendableDataPacketLength   = 20000
)

func TestOpenVPNInteropEmptyAndUnframeableDataPacketsDropWithoutTheBatch(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	serverPort := reserveInteropPort(t, "udp")
	serverConfiguration := fmt.Sprintf(`port %d
proto udp4
dev tun
topology subnet
server 10.50.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
fragment %d
persist-key
persist-tun
verb 4
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		unsendableDataPacketFragment,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "unsendable-packet-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "unsendable-packet-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write unsendable packet server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-unsendable-packet-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "unsendable-packet-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "unsendable-packet-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	clientPort := reserveInteropPort(t, "udp")
	packetLengthRecorder := new(interopPacketLengthRecorder)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 90*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4")},
			DialContext: bindPortDialContextWithRecorder(clientPort, packetLengthRecorder),
			Protocol:    "udp4",
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Fragment: unsendableDataPacketFragment,
			Cipher:   "AES-256-GCM",
			Ciphers:  []string{"AES-256-GCM"},
			Auth:     "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
			RemoteCertificateTLS: "server",
		},
		Pull:   openvpn.ClientPullOptions{Enabled: true},
		Timing: openvpn.ClientTimingOptions{HandWindow: 10 * time.Second},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create unsendable packet interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close unsendable packet interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start unsendable packet interop client: %v", err)
	}

	configuration := waitForClientIfconfig(t, client, 20*time.Second)
	localAddress := configuration.LocalIPv4[0].Addr()
	remoteAddress := netip.MustParseAddr("10.50.0.1")

	establishedRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5010, 1, bytes.Repeat([]byte{0x5a}, 64))
	writeClientDataPacket(t, client, establishedRequest, 20*time.Second)
	awaitClientICMPEchoReply(t, client, establishedRequest, 20*time.Second)

	// --fragment 600 leaves 572 payload bytes per fragment, and MAX_FRAGS is 32,
	// so a 20000 byte datagram is the one fragment_outgoing reports as needing
	// too many fragments.
	unframeableRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5010, 2,
		bytes.Repeat([]byte{0x5a}, unsendableDataPacketLength-28))
	survivingRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5010, 3, bytes.Repeat([]byte{0x5a}, 64))

	packetLengthRecorder.Begin()
	writeErr := client.WriteDataPackets([][]byte{{}, unframeableRequest, survivingRequest})
	if writeErr != nil {
		t.Fatalf("a data packet the link cannot carry failed the whole batch write: %v", writeErr)
	}
	awaitClientICMPEchoReply(t, client, survivingRequest, 20*time.Second)
	_, clientToServerPacketLengths := packetLengthRecorder.End()
	if len(clientToServerPacketLengths) != 1 {
		t.Fatalf("expected the batch to put exactly one datagram on the link, got %d: %v",
			len(clientToServerPacketLengths), clientToServerPacketLengths)
	}
}
