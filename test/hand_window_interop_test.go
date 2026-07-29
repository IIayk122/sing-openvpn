package test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

// slow_check_userpass.sh keeps OpenVPN blocked inside key_method_2_read for
// this long before it answers with its own key-method-2 record.
const interopSlowAuthScriptDelay = 9 * time.Second

func TestOpenVPNInteropKeyMethodReplyAwaitedForRemainingHandWindow(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "slow-auth-server.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		RequireUserPass:      true,
		AuthScriptPath:       filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "slow_check_userpass.sh")),
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "slow-auth-server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-slow-auth-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "slow-auth-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "slow-auth-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	clientContext, cancelClient := context.WithTimeout(context.Background(), 90*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4"),
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher:  "AES-256-GCM",
			Ciphers: []string{"AES-256-GCM"},
			Auth:    "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Authentication: openvpn.ClientAuthenticationOptions{Username: "test-user", Password: "test-password"},
		Pull:           openvpn.ClientPullOptions{Enabled: true},
		Timing:         openvpn.ClientTimingOptions{HandWindow: 40 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancelClient()
		_ = client.Close()
	})
	handshakeStart := time.Now()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 30*time.Second)
	handshakeDuration := time.Since(handshakeStart)
	if handshakeDuration < interopSlowAuthScriptDelay {
		t.Fatalf("server answered the key method exchange in %s, so the slow reply was never exercised", handshakeDuration)
	}

	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	request := buildStaticICMPEchoRequest(t,
		configuration.LocalIPv4[0].Addr(),
		netip.MustParseAddr("10.8.0.1"),
		0x4610,
		1,
		[]byte("slow-key-method-reply"),
	)
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			return
		}
	}
}
