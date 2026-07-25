package test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
	E "github.com/sagernet/sing/common/exceptions"
)

// Upstream multi.c drops already encrypted packets from tcp_link_out_deferred
// once mbuf_add_item saturates the queue bounded by --tcp-queue-limit, so a TCP
// peer observes a hole in the data channel packet id sequence without any
// reordering or duplication.
type droppingFrameConn struct {
	net.Conn
	access        sync.Mutex
	readBuffer    []byte
	pendingStream []byte
	readyFrames   []byte
	armed         atomic.Bool
	dropped       atomic.Bool
}

func (c *droppingFrameConn) Arm() {
	c.armed.Store(true)
}

func (c *droppingFrameConn) Dropped() bool {
	return c.dropped.Load()
}

func (c *droppingFrameConn) Read(packet []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	for {
		if len(c.readyFrames) > 0 {
			n := copy(packet, c.readyFrames)
			c.readyFrames = c.readyFrames[n:]
			return n, nil
		}
		n, err := c.Conn.Read(c.readBuffer)
		if n > 0 {
			c.pendingStream = append(c.pendingStream, c.readBuffer[:n]...)
			c.extractFrames()
		}
		if len(c.readyFrames) > 0 {
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (c *droppingFrameConn) extractFrames() {
	for len(c.pendingStream) >= 2 {
		frameLength := int(binary.BigEndian.Uint16(c.pendingStream[:2]))
		if len(c.pendingStream) < 2+frameLength {
			return
		}
		frame := c.pendingStream[:2+frameLength]
		c.pendingStream = c.pendingStream[2+frameLength:]
		if frameLength > 0 && c.armed.Load() && !c.dropped.Load() {
			opcode := proto.Opcode(frame[2] >> 3)
			if opcode == proto.OpcodeDataV1 || opcode == proto.OpcodeDataV2 {
				c.dropped.Store(true)
				continue
			}
		}
		c.readyFrames = append(c.readyFrames, frame...)
	}
}

func droppingFrameDialContext(localPort int, target **droppingFrameConn) func(ctx context.Context, network string, address string) (net.Conn, error) {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, E.New("unsupported network: ", network)
		}
		dialer := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: net.IPv4zero, Port: localPort},
		}
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		droppingConn := &droppingFrameConn{Conn: conn, readBuffer: make([]byte, 65535)}
		*target = droppingConn
		return droppingConn, nil
	}
}

func TestOpenVPNInteropTCPPacketIDGapRecovery(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, "2.6.14")
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveTCPPort(t)
	serverConfiguration := fmt.Sprintf(`port %d
proto tcp4-server
dev tun
topology subnet
server 10.48.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
keepalive 60 300
persist-key
persist-tun
verb 4
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "replay-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "replay-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write replay server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-replay-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "replay-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: tcpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "replay-server.log"), "Initialization Sequence Completed", 20*time.Second)

	clientPort := reserveTCPPort(t)
	var droppingConn *droppingFrameConn
	clientContext, cancelClient := context.WithTimeout(context.Background(), 60*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "tcp4")},
			DialContext: droppingFrameDialContext(clientPort, &droppingConn),
			Protocol:    "tcp4",
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
		t.Fatalf("create replay interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close replay interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start replay interop client: %v", err)
	}

	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	clientAddress := configuration.LocalIPv4[0].Addr()
	serverAddress := netip.MustParseAddr("10.48.0.1")
	exchangeInteropEcho(t, client, clientAddress, serverAddress, 1, 10*time.Second)

	if droppingConn == nil {
		t.Fatal("transport connection was not captured")
	}
	droppingConn.Arm()
	exchangeInteropEchoWithoutReply(t, client, clientAddress, serverAddress, 2, 5*time.Second, droppingConn)
	exchangeInteropEcho(t, client, clientAddress, serverAddress, 3, 10*time.Second)
}

func exchangeInteropEcho(t *testing.T, client *openvpn.Client, source netip.Addr, destination netip.Addr, sequence uint16, timeout time.Duration) {
	t.Helper()
	request := buildStaticICMPEchoRequest(t, source, destination, 0x4810, sequence, bytes.Repeat([]byte{0x5a}, 64))
	writeClientDataPacket(t, client, request, timeout)
	replyContext, cancelReply := context.WithTimeout(context.Background(), timeout)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatalf("read icmp echo reply %d: %v", sequence, readErr)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			return
		}
	}
}

func exchangeInteropEchoWithoutReply(t *testing.T, client *openvpn.Client, source netip.Addr, destination netip.Addr, sequence uint16, timeout time.Duration, droppingConn *droppingFrameConn) {
	t.Helper()
	request := buildStaticICMPEchoRequest(t, source, destination, 0x4810, sequence, bytes.Repeat([]byte{0x5a}, 64))
	writeClientDataPacket(t, client, request, timeout)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if droppingConn.Dropped() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no data channel packet was dropped from the transport stream")
}
