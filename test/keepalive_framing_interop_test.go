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

// Upstream ping.c ping_string identifies a data channel keepalive, and ping.c
// check_ping_send_dowork hands it to encrypt_sign with comp_frag enabled, so the
// keepalive carries compression and fragment framing like any tunnel packet.
var openVPNInteropPingString = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

type framedKeepaliveInteropCase struct {
	name                        string
	serverCompressionDirectives string
	allowCompression            string
}

func TestOpenVPNInteropFramedKeepalivePing(t *testing.T) {
	testCases := []framedKeepaliveInteropCase{
		{
			name: "comp_lzo_yes",
			serverCompressionDirectives: `allow-compression yes
comp-lzo yes
push "comp-lzo yes"`,
			allowCompression: "asym",
		},
		{
			name: "compress_stub",
			serverCompressionDirectives: `allow-compression no
compress stub
push "compress stub"`,
			allowCompression: "no",
		},
	}
	env := requireInteropEnvironmentVersion(t, "2.6.14")
	for _, testCase := range testCases {
		t.Run(testCase.name, func(caseTest *testing.T) {
			runFramedKeepaliveInteropCase(caseTest, env, testCase)
		})
	}
}

func runFramedKeepaliveInteropCase(t *testing.T, env interopEnvironment, testCase framedKeepaliveInteropCase) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveUDPPort(t)
	serverConfiguration := fmt.Sprintf(`port %d
proto udp4
dev tun
topology subnet
server 10.47.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
keepalive 1 20
%s
persist-key
persist-tun
verb 7
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		testCase.serverCompressionDirectives,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "keepalive-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "keepalive-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write keepalive server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-keepalive-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "keepalive-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "keepalive-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	clientPort := reserveUDPPort(t)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 60*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4")},
			DialContext: bindPortDialContextWithRecorder(clientPort, nil),
			Protocol:    "udp4",
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher:           "AES-256-GCM",
			Ciphers:          []string{"AES-256-GCM"},
			Auth:             "SHA256",
			AllowCompression: testCase.allowCompression,
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
		t.Fatalf("create keepalive interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close keepalive interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start keepalive interop client: %v", err)
	}

	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	request := buildStaticICMPEchoRequest(t,
		configuration.LocalIPv4[0].Addr(),
		netip.MustParseAddr("10.47.0.1"),
		0x4710,
		1,
		bytes.Repeat([]byte{0x5a}, 64),
	)
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatalf("read keepalive interop reply: %v", readErr)
		}
		assertTunnelDataPacket(t, reply)
		if validateStaticICMPEchoReply(request, reply) == nil {
			break
		}
	}

	waitForLogOccurrences(t, serverLogPath, "SENT PING", 3, 10*time.Second)

	idleContext, cancelIdle := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelIdle()
	for {
		packet, readErr := client.ReadDataPacket(idleContext)
		if readErr != nil {
			if E.IsCanceled(readErr) {
				break
			}
			t.Fatalf("read idle tunnel packet: %v", readErr)
		}
		assertTunnelDataPacket(t, packet)
	}
}

func assertTunnelDataPacket(t *testing.T, packet []byte) {
	t.Helper()
	if bytes.Equal(packet, openVPNInteropPingString) {
		t.Fatalf("keepalive ping was delivered as a tunnel packet: %x", packet)
	}
	if len(packet) < 20 {
		t.Fatalf("non-ip packet was delivered as a tunnel packet: %x", packet)
	}
	version := packet[0] >> 4
	if version != 4 && version != 6 {
		t.Fatalf("non-ip packet was delivered as a tunnel packet: %x", packet)
	}
}
