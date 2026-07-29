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
	"syscall"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

// link_socket_write_tcp (socket.c) hands the encapsulated length and the packet
// to one send, so a peer never has to complete a frame from the packet written
// behind it.  A socket that fails after taking part of a frame leaves the peer
// holding a body it will complete from whatever arrives next, and every
// encapsulated length it reads from then on comes from the middle of a packet.
const truncatedFrameMinimumLength = 600

type truncatingFrameConn struct {
	net.Conn
	access            sync.Mutex
	armed             atomic.Bool
	truncated         atomic.Bool
	truncatedBytes    atomic.Int64
	bytesBehindFrame  atomic.Int64
	closed            atomic.Bool
	truncationFailure error
}

func (c *truncatingFrameConn) Arm() {
	c.armed.Store(true)
}

func (c *truncatingFrameConn) Truncated() bool {
	return c.truncated.Load()
}

func (c *truncatingFrameConn) TruncatedBytes() int64 {
	return c.truncatedBytes.Load()
}

func (c *truncatingFrameConn) BytesBehindFrame() int64 {
	return c.bytesBehindFrame.Load()
}

func (c *truncatingFrameConn) Closed() bool {
	return c.closed.Load()
}

func (c *truncatingFrameConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *truncatingFrameConn) Write(payload []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.armed.Load() && !c.truncated.Load() {
		truncationPoint := dataFrameTruncationPoint(payload)
		if truncationPoint > 0 {
			written, err := c.Conn.Write(payload[:truncationPoint])
			c.truncated.Store(true)
			c.truncatedBytes.Store(int64(written))
			if err != nil {
				return written, err
			}
			return written, c.truncationFailure
		}
	}
	written, err := c.Conn.Write(payload)
	if c.truncated.Load() {
		c.bytesBehindFrame.Add(int64(written))
	}
	return written, err
}

func dataFrameTruncationPoint(payload []byte) int {
	offset := 0
	for offset+2 <= len(payload) {
		frameLength := int(binary.BigEndian.Uint16(payload[offset:]))
		if frameLength == 0 || offset+2+frameLength > len(payload) {
			return 0
		}
		opcode := proto.Opcode(payload[offset+2] >> 3)
		if frameLength >= truncatedFrameMinimumLength &&
			(opcode == proto.OpcodeDataV1 || opcode == proto.OpcodeDataV2) {
			return offset + 2 + frameLength/2
		}
		offset += 2 + frameLength
	}
	return 0
}

func TestOpenVPNInteropTCPTruncatedFrameWriteEndsClientLink(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	serverPort := reserveInteropPort(t, "tcp")
	serverConfiguration := fmt.Sprintf(`port %d
proto tcp4-server
dev tun
topology subnet
server 10.62.0.0 255.255.255.0
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
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "truncated-frame-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "truncated-frame-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write truncated frame server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-truncated-frame-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "truncated-frame-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: tcpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "truncated-frame-server.log"), "Initialization Sequence Completed", 20*time.Second)

	var linkAccess sync.Mutex
	var links []*truncatingFrameConn
	dialContext := func(ctx context.Context, network string, address string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, E.New("unsupported network: ", network)
		}
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, network, address)
		if dialErr != nil {
			return nil, dialErr
		}
		link := &truncatingFrameConn{Conn: conn, truncationFailure: syscall.ECONNRESET}
		linkAccess.Lock()
		links = append(links, link)
		linkAccess.Unlock()
		return link, nil
	}
	dialedLinks := func() (int, *truncatingFrameConn) {
		linkAccess.Lock()
		defer linkAccess.Unlock()
		if len(links) == 0 {
			return 0, nil
		}
		return len(links), links[len(links)-1]
	}

	clientContext, cancelClient := context.WithTimeout(context.Background(), 150*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "tcp4")},
			DialContext: dialContext,
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
		t.Fatalf("create truncated frame interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close truncated frame interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start truncated frame interop client: %v", err)
	}

	configuration := waitForClientIfconfig(t, client, 45*time.Second)
	localAddress := configuration.LocalIPv4[0].Addr()
	remoteAddress := netip.MustParseAddr("10.62.0.1")
	establishedRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x6201, 1,
		bytes.Repeat([]byte{0x62}, 1200))
	writeClientDataPacketBuffer(t, client, establishedRequest, 30*time.Second)
	awaitClientICMPEchoReply(t, client, establishedRequest, 30*time.Second)

	establishedLinkCount, establishedLink := dialedLinks()
	if establishedLink == nil {
		t.Fatal("the established session did not run over the instrumented link")
	}
	establishedLink.Arm()

	truncatedRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x6201, 2,
		bytes.Repeat([]byte{0x62}, 1200))
	writeErr := client.WriteDataPacketBuffers([]*buf.Buffer{buf.As(truncatedRequest)})
	if writeErr == nil {
		t.Fatal("the truncated link write was reported as complete")
	}
	if !establishedLink.Truncated() {
		t.Fatalf("no data channel frame was truncated on the instrumented link: %v", writeErr)
	}
	if establishedLink.TruncatedBytes() == 0 {
		t.Fatal("the truncated link write left no bytes of the frame on the wire")
	}

	trailingRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x6201, 3,
		bytes.Repeat([]byte{0x62}, 1200))
	_ = client.WriteDataPacketBuffers([]*buf.Buffer{buf.As(trailingRequest)})
	bytesBehindFrame := establishedLink.BytesBehindFrame()
	if bytesBehindFrame != 0 {
		t.Fatalf("the link carried %d bytes behind the frame it stopped inside", bytesBehindFrame)
	}
	if !establishedLink.Closed() {
		t.Fatal("the link that stopped inside a frame was left open")
	}

	restartDeadline := time.Now().Add(60 * time.Second)
	for {
		linkCount, _ := dialedLinks()
		if linkCount > establishedLinkCount {
			break
		}
		if !time.Now().Before(restartDeadline) {
			t.Fatal("the client kept the session after the link stopped inside a frame")
		}
		time.Sleep(interopPollInterval)
	}
	for !client.Ready() {
		if !time.Now().Before(restartDeadline) {
			t.Fatal("the client did not re-establish the tunnel after the truncated frame write")
		}
		time.Sleep(interopPollInterval)
	}
	restartedConfiguration := client.TunnelConfiguration()
	if len(restartedConfiguration.LocalIPv4) == 0 {
		t.Fatal("the re-established tunnel carries no pushed ifconfig")
	}
	restartedRequest := buildStaticICMPEchoRequest(t, restartedConfiguration.LocalIPv4[0].Addr(), remoteAddress,
		0x6201, 4, bytes.Repeat([]byte{0x62}, 1200))
	writeClientDataPacketBuffer(t, client, restartedRequest, 30*time.Second)
	awaitClientICMPEchoReply(t, client, restartedRequest, 30*time.Second)

	bytesBehindFrame = establishedLink.BytesBehindFrame()
	if bytesBehindFrame != 0 {
		t.Fatalf("the link carried %d bytes behind the frame it stopped inside", bytesBehindFrame)
	}
}

func writeClientDataPacketBuffer(t *testing.T, client *openvpn.Client, packet []byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := client.WriteDataPacketBuffers([]*buf.Buffer{buf.As(packet)})
		if err == nil {
			return
		}
		if !E.IsMulti(err, openvpn.ErrDataChannelNotReady) {
			t.Fatalf("write data packet buffer: %v", err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out waiting for client data channel: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
