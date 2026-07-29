package test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

const (
	mssFixUnderflowValue         = 60
	mssFixUnderflowAdvertisedMSS = 65535
)

type mssFixUnderflowPhase struct {
	name                 string
	serverMSSFix         uint32
	serverMSSFixMode     string
	serverMSSFixDisabled bool
	clientDataChannel    openvpn.ClientDataChannelOptions
	sourcePort           uint16
	destinationPort      uint16
}

func TestOpenVPNInteropMSSFixBelowChannelOverheadMatchesUpstreamClamp(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	upstreamMSS := observeMSSFixClampOnPeerTUN(t, env, mssFixUnderflowPhase{
		name:             "mssfix-underflow-upstream",
		serverMSSFix:     mssFixUnderflowValue,
		serverMSSFixMode: "mtu",
		clientDataChannel: openvpn.ClientDataChannelOptions{
			Ciphers:        []string{"AES-256-GCM"},
			MSSFixDisabled: true,
		},
		sourcePort:      41001,
		destinationPort: 7,
	})
	if upstreamMSS == mssFixUnderflowAdvertisedMSS {
		t.Fatalf("OpenVPN %s left the advertised MSS untouched, so the phase carries no upstream clamp to compare against", env.version)
	}
	t.Logf("OpenVPN %s clamps an advertised MSS of %d to %d under --mssfix %d mtu", env.version, mssFixUnderflowAdvertisedMSS, upstreamMSS, mssFixUnderflowValue)
	portMSS := observeMSSFixClampOnPeerTUN(t, env, mssFixUnderflowPhase{
		name:                 "mssfix-underflow-port",
		serverMSSFixDisabled: true,
		clientDataChannel: openvpn.ClientDataChannelOptions{
			Ciphers:    []string{"AES-256-GCM"},
			MSSFix:     mssFixUnderflowValue,
			MSSFixMode: openvpn.MSSFixModeMTU,
		},
		sourcePort:      41002,
		destinationPort: 9,
	})
	if portMSS != upstreamMSS {
		t.Fatalf("--mssfix %d clamped the advertised MSS to %d, OpenVPN %s clamps it to %d",
			mssFixUnderflowValue, portMSS, env.version, upstreamMSS)
	}
}

func observeMSSFixClampOnPeerTUN(t *testing.T, env interopEnvironment, phase mssFixUnderflowPhase) uint16 {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, phase.name+".conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		MSSFix:               phase.serverMSSFix,
		MSSFixMode:           phase.serverMSSFixMode,
		MSSFixDisabled:       phase.serverMSSFixDisabled,
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", phase.name+".log")),
	})
	serverContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-" + phase.name + "-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", phase.name+".conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, phase.name+".log"), "Initialization Sequence Completed", 20*time.Second)

	clientContext, cancelClient := context.WithTimeout(context.Background(), 60*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:     clientContext,
		Mode:        openvpn.ModeTLS,
		Transport:   clientTransportOptions(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4"),
		DataChannel: phase.clientDataChannel,
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("create client with MSSFix %d: %v", phase.clientDataChannel.MSSFix, err)
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

	capture := startInteropPacketCapture(t, serverContainer, workspace, phase.name,
		fmt.Sprintf("tcp dst port %d and tcp[tcpflags] & tcp-syn != 0", phase.destinationPort))
	synPacket := buildIPv4TCPSYNPacket(t, sourceAddress, destinationAddress, phase.sourcePort, phase.destinationPort, mssFixUnderflowAdvertisedMSS, 0)
	writeClientDataPacket(t, client, synPacket, 10*time.Second)
	decodedPackets := capture.Decode(t)
	if !strings.Contains(decodedPackets, "(correct)") {
		t.Fatalf("the SYN reached the peer TUN with an invalid TCP checksum:\n%s", decodedPackets)
	}
	return parseCapturedMSSOption(t, decodedPackets)
}

var capturedMSSOptionPattern = regexp.MustCompile(`mss (\d+)`)

func parseCapturedMSSOption(t *testing.T, decodedPackets string) uint16 {
	t.Helper()
	match := capturedMSSOptionPattern.FindStringSubmatch(decodedPackets)
	if match == nil {
		t.Fatalf("no TCP MSS option in peer TUN capture:\n%s", decodedPackets)
	}
	segmentSize, err := strconv.ParseUint(match[1], 10, 16)
	if err != nil {
		t.Fatalf("unreadable TCP MSS option %q: %v", match[1], err)
	}
	return uint16(segmentSize)
}
