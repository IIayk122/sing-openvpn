package test

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// OpenVPN 2.6.14 reads pushed second counts with positive_atoi (options.c),
	// which keeps only the low 32 bits: --ping-restart 18446744074 leaves
	// ping_rec_timeout = 1266874890 in its "Current Parameter Settings" dump.
	pushedTimerSecondsAboveIntegerRange = "18446744074"
	pushedTimerTruncatedInterval        = 1266874890 * time.Second
	// Longer than several keepalive ticks, and long enough for the reconnect a
	// dropped session would start to reach the counting dialer.
	pushedTimerIdleObservation = 5 * time.Second
)

func TestOpenVPNInteropPushedTimersAboveIntegerRangeKeepTheSessionAlive(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("ping_restart", func(caseTest *testing.T) {
		caseTest.Parallel()
		configuration := runPushedTimerTruncationCase(caseTest, env, "pushed-timer-ping-restart", []string{
			"ping-restart " + pushedTimerSecondsAboveIntegerRange,
		})
		if configuration.PingRestart != pushedTimerTruncatedInterval {
			caseTest.Fatalf("pushed ping-restart became %s, want %s", configuration.PingRestart, pushedTimerTruncatedInterval)
		}
	})
	t.Run("inactive_and_session_timeout", func(caseTest *testing.T) {
		caseTest.Parallel()
		configuration := runPushedTimerTruncationCase(caseTest, env, "pushed-timer-inactive", []string{
			"inactive " + pushedTimerSecondsAboveIntegerRange,
			"session-timeout " + pushedTimerSecondsAboveIntegerRange,
		})
		if configuration.InactiveTimeout != pushedTimerTruncatedInterval {
			caseTest.Fatalf("pushed inactive became %s, want %s", configuration.InactiveTimeout, pushedTimerTruncatedInterval)
		}
		if configuration.SessionTimeout != pushedTimerTruncatedInterval {
			caseTest.Fatalf("pushed session-timeout became %s, want %s", configuration.SessionTimeout, pushedTimerTruncatedInterval)
		}
	})
}

// The server carries no --keepalive, so nothing reaches the client while the
// observation window runs and every pushed timer is free to expire.
func runPushedTimerTruncationCase(
	t *testing.T,
	env interopEnvironment,
	name string,
	pushLines []string,
) openvpn.TunnelConfiguration {
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, name+"-server.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		PushLines:            pushLines,
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", name+"-server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-" + name + "-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", name+"-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, name+"-server.log"), "Initialization Sequence Completed", 20*time.Second)

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
		Pull:   openvpn.ClientPullOptions{Enabled: true},
		Timing: openvpn.ClientTimingOptions{HandWindow: 20 * time.Second},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create pushed timer client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close pushed timer client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start pushed timer client: %v", err)
	}
	configuration := waitForClientIfconfig(t, client, 20*time.Second)
	exchangePushedTimerEcho(t, client, configuration, 1)
	establishedDialCount := dialCount.Load()

	time.Sleep(pushedTimerIdleObservation)

	reconnectCount := dialCount.Load() - establishedDialCount
	if reconnectCount != 0 {
		t.Fatalf("client reconnected %d times while every pushed timer was far from expiry", reconnectCount)
	}
	if !client.Ready() {
		t.Fatalf("client left the session after %s of idle time", pushedTimerIdleObservation)
	}
	exchangePushedTimerEcho(t, client, configuration, 2)
	return client.TunnelConfiguration()
}

func exchangePushedTimerEcho(
	t *testing.T,
	client *openvpn.Client,
	configuration openvpn.TunnelConfiguration,
	sequence uint16,
) {
	t.Helper()
	request := buildStaticICMPEchoRequest(t,
		configuration.LocalIPv4[0].Addr(),
		netip.MustParseAddr("10.8.0.1"),
		0x5311,
		sequence,
		bytes.Repeat([]byte{0x71}, 32),
	)
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatalf("read pushed timer echo reply %d: %v", sequence, readErr)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			return
		}
	}
}
