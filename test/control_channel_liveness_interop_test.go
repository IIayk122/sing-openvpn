package test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// Longer than the renegotiation cycle of the first case and than the
	// PUSH_REQUEST resend interval of the second one, so the control channel
	// gap never reaches it while the data channel stays completely idle.
	controlLivenessPingRestart           = 7 * time.Second
	controlLivenessRenegotiationInterval = 3 * time.Second
	// Two ping-restart timeouts of an idle data channel.
	controlLivenessIdleObservation = 16 * time.Second
	// The delay deferred_silent_auth.sh keeps the authentication pending,
	// during which the server answers nothing but the acknowledgments of the
	// resent PUSH_REQUEST.
	controlLivenessDeferredAuthDelay = 14 * time.Second
)

func countingDialContext(dialCount *atomic.Int64) func(ctx context.Context, network string, address string) (net.Conn, error) {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		dialCount.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}

func TestOpenVPNInteropControlChannelTrafficKeepsClientPingRestartAlive(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("renegotiation_of_idle_tunnel", func(caseTest *testing.T) {
		caseTest.Parallel()
		runControlLivenessRenegotiationCase(caseTest, env)
	})
	t.Run("push_request_acknowledgment_during_deferred_auth", func(caseTest *testing.T) {
		caseTest.Parallel()
		runControlLivenessDeferredAuthCase(caseTest, env)
	})
}

// A server without --keepalive never sends a data channel ping, so the
// renegotiation the client drives is the only traffic that reaches it.
func runControlLivenessRenegotiationCase(t *testing.T, env interopEnvironment) {
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "liveness-reneg-server.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "liveness-reneg-server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-liveness-reneg-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "liveness-reneg-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "liveness-reneg-server.log"), "Initialization Sequence Completed", 20*time.Second)

	dialCount := new(atomic.Int64)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 90*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{{Host: "127.0.0.1", Port: uint16(serverPort), Protocol: "udp4"}},
			DialContext: countingDialContext(dialCount),
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
		Pull: openvpn.ClientPullOptions{Enabled: true},
		Timing: openvpn.ClientTimingOptions{
			HandWindow:            20 * time.Second,
			PingRestart:           controlLivenessPingRestart,
			RenegotiationInterval: controlLivenessRenegotiationInterval,
		},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create control liveness client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close control liveness client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start control liveness client: %v", err)
	}
	configuration := waitForClientIfconfig(t, client, 20*time.Second)
	exchangeControlLivenessEcho(t, client, configuration, 1)

	time.Sleep(controlLivenessIdleObservation)

	sessionCount := dialCount.Load()
	if sessionCount != 1 {
		t.Fatalf("client opened %d sessions while the renegotiating control channel kept the peer alive", sessionCount)
	}
	if !client.Ready() {
		t.Fatal("client is not ready after an idle data channel with a renegotiating control channel")
	}
	exchangeControlLivenessEcho(t, client, configuration, 2)
}

// The server acknowledges every resent PUSH_REQUEST while the deferred
// authentication runs, and answers nothing else until it completes.
func runControlLivenessDeferredAuthCase(t *testing.T, env interopEnvironment) {
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "liveness-deferred-server.conf"), tlsServerTemplateData{
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
		AuthScriptPath:       filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "deferred_silent_auth.sh")),
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "liveness-deferred-server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-liveness-deferred-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "liveness-deferred-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "liveness-deferred-server.log"), "Initialization Sequence Completed", 20*time.Second)

	dialCount := new(atomic.Int64)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 90*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{{Host: "127.0.0.1", Port: uint16(serverPort), Protocol: "udp4"}},
			DialContext: countingDialContext(dialCount),
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
		Authentication: openvpn.ClientAuthenticationOptions{Username: "test-user", Password: "test-password"},
		Pull:           openvpn.ClientPullOptions{Enabled: true},
		Timing: openvpn.ClientTimingOptions{
			HandWindow:  40 * time.Second,
			PingRestart: controlLivenessPingRestart,
		},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create deferred auth liveness client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close deferred auth liveness client: %v", closeErr)
		}
	})
	pullStart := time.Now()
	err = client.Start()
	if err != nil {
		t.Fatalf("start deferred auth liveness client: %v", err)
	}
	configuration := waitForClientIfconfig(t, client, 30*time.Second)
	pullDuration := time.Since(pullStart)
	if pullDuration < controlLivenessDeferredAuthDelay {
		t.Fatalf("the pull phase completed in %s, so the deferred authentication was never awaited", pullDuration)
	}
	sessionCount := dialCount.Load()
	if sessionCount != 1 {
		t.Fatalf("client opened %d sessions while the acknowledged PUSH_REQUEST kept the peer alive", sessionCount)
	}
	exchangeControlLivenessEcho(t, client, configuration, 1)
}

func exchangeControlLivenessEcho(
	t *testing.T,
	client *openvpn.Client,
	configuration openvpn.TunnelConfiguration,
	sequence uint16,
) {
	t.Helper()
	request := buildStaticICMPEchoRequest(t,
		configuration.LocalIPv4[0].Addr(),
		netip.MustParseAddr("10.8.0.1"),
		0x4820,
		sequence,
		bytes.Repeat([]byte{0x63}, 32),
	)
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatalf("read control liveness echo reply %d: %v", sequence, readErr)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			return
		}
	}
}
