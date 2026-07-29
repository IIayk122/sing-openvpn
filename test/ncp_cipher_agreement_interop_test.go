package test

import (
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

const (
	unannouncedCipherServerCiphers = "AES-256-GCM"
	unannouncedCipherClientCiphers = "CHACHA20-POLY1305:AES-256-GCM"
	// Upstream do_deferred_p2p_ncp (init.c) refuses the session with this line.
	unannouncedCipherUpstreamP2PRefusal = "failed to negotiate cipher with peer and --data-ciphers-fallback not enabled"
	// A pulling peer reaches check_session_cipher (ssl_ncp.c) instead: the
	// pushed protocol-flags option carries OPT_P_NCP, so check_pull_client_ncp
	// returns early and leaves the ciphername at the BF-CBC default that
	// options_postprocess_cipher installed, which --data-ciphers does not list
	// and no --data-ciphers-fallback covers.
	unannouncedCipherUpstreamPullRefusal = "negotiated cipher not allowed - BF-CBC not in "
)

var unannouncedCipherClientCipherList = []string{"CHACHA20-POLY1305", "AES-256-GCM"}

// A --mode server peer sends no peer info at all (init.c sets
// push_peer_info_detail to 0 for MODE_SERVER), so it announces no IV_CIPHERS,
// and with no --cipher directive its ciphername stays at the BF-CBC default,
// which options_string (options.c) refuses to announce because --data-ciphers
// does not list it. A peer of this shape names no data cipher anywhere, so a
// client that reaches the data channel without pulling one has invented it.
func TestOpenVPNInteropUnannouncedPeerCipherAbortsWithoutFallback(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "server-tls.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               unannouncedCipherFixturePath("ca.crt"),
		CertPath:             unannouncedCipherFixturePath("server.crt"),
		KeyPath:              unannouncedCipherFixturePath("server.key"),
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          unannouncedCipherServerCiphers,
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-unannounced-cipher-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "server-tls.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpHostGatewayPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	t.Run("repo_p2p_client_refuses_the_session", func(t *testing.T) {
		runUnannouncedCipherRepoClient(t, serverPort)
	})
	t.Run("real_p2p_client_refuses_the_session", func(t *testing.T) {
		runUnannouncedCipherRealClient(t, env, workspace, serverPort)
	})
	t.Run("repo_pulling_client_refuses_a_dropped_cipher_push", func(t *testing.T) {
		runUnannouncedCipherFilteredRepoClient(t, serverPort)
	})
	t.Run("real_pulling_client_refuses_a_dropped_cipher_push", func(t *testing.T) {
		runUnannouncedCipherFilteredRealClient(t, env, workspace, serverPort)
	})
	t.Run("pushed_cipher_still_keys_the_data_channel", func(t *testing.T) {
		runUnannouncedCipherPullingRepoClient(t, serverPort)
	})
}

func unannouncedCipherFixturePath(fileName string) string {
	return filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", fileName))
}

func runUnannouncedCipherRepoClient(t *testing.T, serverPort int) {
	t.Helper()
	clientContext, cancelClient := context.WithTimeout(context.Background(), 40*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4"),
		DataChannel: openvpn.ClientDataChannelOptions{
			Ciphers: unannouncedCipherClientCipherList,
			Auth:    "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
			RemoteCertificateTLS: "server",
		},
		Pull:   openvpn.ClientPullOptions{Enabled: false},
		Tunnel: openvpn.ClientTunnelOptions{LocalAddress: []netip.Prefix{netip.MustParsePrefix("10.8.0.9/24")}},
		Timing: openvpn.ClientTimingOptions{HandWindow: 10 * time.Second},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		if E.IsMulti(err, openvpn.ErrCipherNegotiationFailed) {
			return
		}
		t.Fatalf("start client: %v", err)
	}
	waitForClientTerminalError(t, client, 25*time.Second, openvpn.ErrCipherNegotiationFailed)
	if client.Ready() {
		t.Fatal("client kept a data channel keyed with a cipher the peer never announced")
	}
}

func runUnannouncedCipherRealClient(t *testing.T, env interopEnvironment, workspace interopWorkspace, serverPort int) {
	t.Helper()
	clientConfiguration := fmt.Sprintf(`dev tun
proto udp4
remote host.docker.internal %d
nobind
tls-client
remote-cert-tls server
ca %s
cert %s
key %s
ifconfig 10.8.0.9 10.8.0.10
data-ciphers %s
auth SHA256
verb 4
log %s
`, serverPort,
		unannouncedCipherFixturePath("ca.crt"),
		unannouncedCipherFixturePath("client.crt"),
		unannouncedCipherFixturePath("client.key"),
		unannouncedCipherClientCiphers,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "p2p-real-client.log")),
	)
	clientConfigurationPath := filepath.Join(workspace.renderedDir, "p2p-real-client.conf")
	err := os.WriteFile(clientConfigurationPath, []byte(clientConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write real client config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-unannounced-cipher-real-client-" + uniqueDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "p2p-real-client.conf"))},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	clientLogPath := filepath.Join(workspace.logsDir, "p2p-real-client.log")
	waitForLogLine(t, clientLogPath, unannouncedCipherUpstreamP2PRefusal, 40*time.Second)
	assertLogDoesNotContain(t, clientLogPath, "Initialization Sequence Completed")
}

// A pull-filter that drops the pushed cipher leaves the pulling client in the
// same position as a peer that never pushed one: upstream check_pull_client_ncp
// then has neither a pushed nor an OCC cipher to adopt.
func runUnannouncedCipherFilteredRepoClient(t *testing.T, serverPort int) {
	t.Helper()
	clientContext, cancelClient := context.WithTimeout(context.Background(), 40*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4"),
		DataChannel: openvpn.ClientDataChannelOptions{
			Ciphers: unannouncedCipherClientCipherList,
			Auth:    "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
			RemoteCertificateTLS: "server",
		},
		Pull: openvpn.ClientPullOptions{
			Enabled: true,
			Filters: []openvpn.PullFilter{{Action: "ignore", Text: "cipher "}},
		},
		Timing: openvpn.ClientTimingOptions{HandWindow: 10 * time.Second},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create filtering client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close filtering client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		if E.IsMulti(err, openvpn.ErrCipherNegotiationFailed) {
			return
		}
		t.Fatalf("start filtering client: %v", err)
	}
	waitForClientTerminalError(t, client, 25*time.Second, openvpn.ErrCipherNegotiationFailed)
	if client.Ready() {
		t.Fatal("client kept a data channel keyed with a cipher it had dropped from the push reply")
	}
}

func runUnannouncedCipherFilteredRealClient(t *testing.T, env interopEnvironment, workspace interopWorkspace, serverPort int) {
	t.Helper()
	clientConfiguration := fmt.Sprintf(`client
dev tun
proto udp4
remote host.docker.internal %d
nobind
remote-cert-tls server
ca %s
cert %s
key %s
pull-filter ignore "cipher "
data-ciphers %s
auth SHA256
verb 4
log %s
`, serverPort,
		unannouncedCipherFixturePath("ca.crt"),
		unannouncedCipherFixturePath("client.crt"),
		unannouncedCipherFixturePath("client.key"),
		unannouncedCipherClientCiphers,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "pull-real-client.log")),
	)
	clientConfigurationPath := filepath.Join(workspace.renderedDir, "pull-real-client.conf")
	err := os.WriteFile(clientConfigurationPath, []byte(clientConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write real pulling client config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-unannounced-cipher-real-pull-client-" + uniqueDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "pull-real-client.conf"))},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	clientLogPath := filepath.Join(workspace.logsDir, "pull-real-client.log")
	waitForLogLine(t, clientLogPath, unannouncedCipherUpstreamPullRefusal, 40*time.Second)
	assertLogDoesNotContain(t, clientLogPath, "Initialization Sequence Completed")
}

func runUnannouncedCipherPullingRepoClient(t *testing.T, serverPort int) {
	t.Helper()
	clientContext, cancelClient := context.WithTimeout(context.Background(), 40*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4"),
		DataChannel: openvpn.ClientDataChannelOptions{
			Ciphers: unannouncedCipherClientCipherList,
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
		t.Fatalf("create pulling client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close pulling client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start pulling client: %v", err)
	}
	configuration := waitForClientIfconfig(t, client, 20*time.Second)
	exchangeTLSClientEcho(t, client, configuration, 1, 0)
}
