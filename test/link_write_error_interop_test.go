package test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

// forward.c process_outgoing_link hands the result of link_socket_write to
// check_status, which only logs it.  A datagram the kernel refuses is dropped
// and the link socket, the key state and the session all survive it.
const refusedLinkWriteTunnelPacketLength = 65500

func TestOpenVPNInteropRefusedDatagramLinkWriteKeepsSessionEstablished(t *testing.T) {
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
server 10.49.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
keepalive 5 60
persist-key
persist-tun
verb 4
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "link-write-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "link-write-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write link write server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-link-write-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "link-write-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "link-write-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	var dialCount atomic.Uint32
	dialContext := func(ctx context.Context, network string, address string) (net.Conn, error) {
		dialCount.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	clientContext, cancelClient := context.WithTimeout(context.Background(), 90*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4")},
			DialContext: dialContext,
			Protocol:    "udp4",
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher:  "AES-256-GCM",
			Ciphers: []string{"AES-256-GCM"},
			Auth:    "SHA256",
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
		t.Fatalf("create link write interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close link write interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start link write interop client: %v", err)
	}

	configuration := waitForClientIfconfig(t, client, 20*time.Second)
	localAddress := configuration.LocalIPv4[0].Addr()
	remoteAddress := netip.MustParseAddr("10.49.0.1")

	establishedRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5150, 1, bytes.Repeat([]byte{0x5a}, 64))
	writeClientDataPacket(t, client, establishedRequest, 20*time.Second)
	awaitClientICMPEchoReply(t, client, establishedRequest, 20*time.Second)
	establishedDialCount := dialCount.Load()

	// An IPv4 UDP datagram cannot carry more than 65507 bytes, so the encoded
	// tunnel packet is refused by the kernel with EMSGSIZE without ever leaving
	// the host, exactly as a transient ENOBUFS would be.
	refusedRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5150, 2,
		bytes.Repeat([]byte{0x5a}, refusedLinkWriteTunnelPacketLength-28))
	writeErr := client.WriteDataPacket(refusedRequest)
	if writeErr == nil {
		t.Fatal("the link accepted an oversized datagram, the refused write is no longer exercised")
	}
	if !errors.Is(writeErr, syscall.EMSGSIZE) {
		t.Fatalf("expected the refused link write to report EMSGSIZE, got: %v", writeErr)
	}

	if !client.Ready() {
		t.Fatal("client lost readiness after a refused datagram link write")
	}
	survivingRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5150, 3, bytes.Repeat([]byte{0x5a}, 64))
	writeClientDataPacket(t, client, survivingRequest, 20*time.Second)
	awaitClientICMPEchoReply(t, client, survivingRequest, 20*time.Second)
	redialCount := dialCount.Load() - establishedDialCount
	if redialCount != 0 {
		t.Fatalf("expected the refused link write to keep the established link socket, got %d redials", redialCount)
	}
}

func awaitClientICMPEchoReply(t *testing.T, client *openvpn.Client, request []byte, timeout time.Duration) {
	t.Helper()
	replyContext, cancelReply := context.WithTimeout(context.Background(), timeout)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatalf("read tunnel echo reply: %v", readErr)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			return
		}
	}
}
