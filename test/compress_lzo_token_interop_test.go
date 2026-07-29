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

type compressLZOTokenInteropCase struct {
	name             string
	allowCompression string
	expectRejection  bool
}

func TestOpenVPNInteropPushedCompressLZOUsesLZOFraming(t *testing.T) {
	t.Parallel()
	testCases := []compressLZOTokenInteropCase{
		{
			name:             "asym",
			allowCompression: "asym",
		},
		{
			name:             "no",
			allowCompression: "no",
			expectRejection:  true,
		},
	}
	for _, version := range []string{"2.5.11", "2.6.14"} {
		t.Run("openvpn_"+version, func(versionTest *testing.T) {
			versionTest.Parallel()
			env := requireInteropEnvironmentVersion(versionTest, version)
			for _, testCase := range testCases {
				versionTest.Run(testCase.name, func(caseTest *testing.T) {
					caseTest.Parallel()
					runCompressLZOTokenInteropCase(caseTest, env, testCase)
				})
			}
		})
	}
}

func runCompressLZOTokenInteropCase(t *testing.T, env interopEnvironment, testCase compressLZOTokenInteropCase) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
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
allow-compression yes
compress lzo
push "compress lzo"
persist-key
persist-tun
verb 7
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "compress-lzo-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "compress-lzo-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write compress lzo server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-compress-lzo-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "compress-lzo-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "compress-lzo-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	clientPort := reserveInteropPort(t, "udp")
	packetLengthRecorder := new(interopPacketLengthRecorder)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 30*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4")},
			DialContext: bindPortDialContextWithRecorder(clientPort, packetLengthRecorder),
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
		t.Fatalf("create compress lzo interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close compress lzo interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		if testCase.expectRejection && E.IsMulti(err, openvpn.ErrCompressionPushRejected) {
			return
		}
		t.Fatalf("start compress lzo interop client: %v", err)
	}
	if testCase.expectRejection {
		waitForClientTerminalError(t, client, 10*time.Second, openvpn.ErrCompressionPushRejected)
		rejection := client.CompressionPushRejection()
		if rejection != "compress lzo" {
			t.Fatalf("expected recorded rejection %q, got %q", "compress lzo", rejection)
		}
		return
	}

	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	request := buildStaticICMPEchoRequest(t,
		configuration.LocalIPv4[0].Addr(),
		netip.MustParseAddr("10.47.0.1"),
		0x4710,
		1,
		bytes.Repeat([]byte{0x5a}, 1152),
	)
	packetLengthRecorder.Begin()
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatalf("read compress lzo interop reply: %v", readErr)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			break
		}
	}
	serverToClientPacketLengths, clientToServerPacketLengths := packetLengthRecorder.End()
	assertCompressionNegotiationPacketLengths(t, "server to library", serverToClientPacketLengths, len(request), true)
	assertCompressionNegotiationPacketLengths(t, "library to server", clientToServerPacketLengths, len(request), false)
}
