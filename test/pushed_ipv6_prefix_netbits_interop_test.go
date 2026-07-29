package test

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

// OpenVPN 2.6.14 reads the local endpoint of a pushed ifconfig-ipv6 and the
// destination of a pushed route-ipv6 with get_ipv6_addr (options.c), which
// leaves a token carrying no "/bits" suffix at /64. add_option (options.c) then
// refuses an ifconfig-ipv6 whose netbits leave 64..124 with
// "Options error: ifconfig-ipv6: /netbits must be between 64 and 124, not
// '/128'" and keeps the whole option out of the pulled configuration.
func TestOpenVPNInteropPushedIPv6PrefixWithoutNetbitsSpansTheOnLinkSlash64(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("without_netbits", func(caseTest *testing.T) {
		caseTest.Parallel()
		configuration := runPushedIPv6PrefixCase(caseTest, env, "pushed-ipv6-bare-prefix",
			[]string{
				"ifconfig-ipv6 fd00::2 fd00::1",
				"route-ipv6 fd10::",
			},
			[]string{
				"ip -o -6 address show dev tun0 | grep -F 'inet6 fd00::2/64'",
				"ip -6 route show fd10::/64 | grep -F 'dev tun0'",
			},
			nil,
		)
		expectedLocalIPv6 := []netip.Prefix{netip.MustParsePrefix("fd00::2/64")}
		if !slices.Equal(configuration.LocalIPv6, expectedLocalIPv6) {
			caseTest.Fatalf("pushed ifconfig-ipv6 became %v, want %v", configuration.LocalIPv6, expectedLocalIPv6)
		}
		expectedGateway := netip.MustParseAddr("fd00::1")
		if configuration.VPNGatewayIPv6 != expectedGateway {
			caseTest.Fatalf("pushed ifconfig-ipv6 peer became %v, want %v", configuration.VPNGatewayIPv6, expectedGateway)
		}
		expectedRoute := openvpn.TunnelRoute{
			Prefix:  netip.MustParsePrefix("fd10::/64"),
			Gateway: expectedGateway,
		}
		if !slices.Contains(configuration.IPv6Routes, expectedRoute) {
			caseTest.Fatalf("pushed route-ipv6 became %v, want %v", configuration.IPv6Routes, expectedRoute)
		}
	})
	t.Run("netbits_outside_64_to_124", func(caseTest *testing.T) {
		caseTest.Parallel()
		configuration := runPushedIPv6PrefixCase(caseTest, env, "pushed-ipv6-refused-prefix",
			[]string{"ifconfig-ipv6 fd00::2/128 fd00::1"},
			[]string{"! ip -o -6 address show dev tun0 | grep -qF 'fd00::'"},
			[]string{"ifconfig-ipv6: /netbits must be between 64 and 124, not '/128'"},
		)
		if len(configuration.LocalIPv6) != 0 {
			caseTest.Fatalf("refused ifconfig-ipv6 reached the tunnel configuration as %v", configuration.LocalIPv6)
		}
		if configuration.VPNGatewayIPv6.IsValid() {
			caseTest.Fatalf("refused ifconfig-ipv6 left peer %v behind", configuration.VPNGatewayIPv6)
		}
	})
}

// A real client reads the same push first and reports what upstream derives
// from it in the kernel, then the repository client reads it from the same
// server.
func runPushedIPv6PrefixCase(
	t *testing.T,
	env interopEnvironment,
	name string,
	pushLines []string,
	realClientChecks []string,
	expectedClientLogLines []string,
) openvpn.TunnelConfiguration {
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	serverLogName := name + "-server.log"
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
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", serverLogName)),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-" + name + "-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", name+"-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpHostGatewayPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, serverLogName), "Initialization Sequence Completed", 30*time.Second)

	clientLogName := name + "-client.log"
	dockerClientLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", clientLogName))
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, name+"-client.conf"), tlsClientTemplateData{
		Protocol:             "udp4",
		RemoteHost:           "host.docker.internal",
		RemotePort:           serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		LogPath:              dockerClientLogPath,
	})
	realClientCommand := "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", name+"-client.conf")) +
		" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, name+"-client.pid")) +
		" && until grep -q 'Initialization Sequence Completed' " + dockerClientLogPath + "; do sleep 0.1; done"
	for _, check := range realClientChecks {
		realClientCommand += " && " + check
	}
	realClient := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-" + name + "-real-client-" + uniqueDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"bash", "-lc", realClientCommand},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	waitResult := realClient.Wait(t, 60*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN client failed: %s", waitResult.Logs)
	}
	assertLogContains(t, filepath.Join(workspace.logsDir, clientLogName), expectedClientLogLines)

	clientContext, cancelClient := context.WithTimeout(context.Background(), 60*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:  []openvpn.Remote{{Host: "127.0.0.1", Port: uint16(serverPort), Protocol: "udp4"}},
			Protocol: "udp4",
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
		t.Fatalf("create pushed ipv6 prefix client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close pushed ipv6 prefix client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start pushed ipv6 prefix client: %v", err)
	}
	return waitForClientIfconfig(t, client, 30*time.Second)
}
