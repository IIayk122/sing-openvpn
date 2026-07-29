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
	E "github.com/sagernet/sing/common/exceptions"
)

// A TCP link hands the reader whatever one socket read returned, so an
// encapsulated packet whose length prefix and body arrive in separate segments
// reaches the reader in separate reads and the short deadline every reader arms
// can expire between them. This link splits every encapsulated packet in two --
// once inside the length prefix, once inside the body -- and reports the gap
// between the pieces as an expired read deadline.
type splitFrameConn struct {
	net.Conn
	access        sync.Mutex
	readBuffer    []byte
	pendingStream []byte
	readyBytes    []byte
	heldTail      []byte
	holdingTail   bool
	splitInPrefix bool
	splitCount    atomic.Int64
}

func (c *splitFrameConn) SplitCount() int64 {
	return c.splitCount.Load()
}

func (c *splitFrameConn) Read(packet []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	for {
		c.splitFrames()
		if len(c.readyBytes) > 0 {
			readCount := copy(packet, c.readyBytes)
			c.readyBytes = c.readyBytes[readCount:]
			return readCount, nil
		}
		if c.holdingTail {
			c.holdingTail = false
			c.readyBytes = c.heldTail
			c.heldTail = nil
			return 0, os.ErrDeadlineExceeded
		}
		readCount, err := c.Conn.Read(c.readBuffer)
		if readCount > 0 {
			c.pendingStream = append(c.pendingStream, c.readBuffer[:readCount]...)
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (c *splitFrameConn) splitFrames() {
	for !c.holdingTail && len(c.pendingStream) >= 2 {
		frameLength := int(binary.BigEndian.Uint16(c.pendingStream[:2]))
		if len(c.pendingStream) < 2+frameLength {
			return
		}
		frame := c.pendingStream[:2+frameLength]
		c.pendingStream = c.pendingStream[2+frameLength:]
		splitPoint := 1
		if !c.splitInPrefix {
			splitPoint = 2 + frameLength/2
		}
		c.splitInPrefix = !c.splitInPrefix
		if frameLength == 0 || splitPoint >= len(frame) {
			c.readyBytes = append(c.readyBytes, frame...)
			continue
		}
		c.readyBytes = append(c.readyBytes, frame[:splitPoint]...)
		c.heldTail = append([]byte{}, frame[splitPoint:]...)
		c.holdingTail = true
		c.splitCount.Add(1)
	}
}

func TestOpenVPNInteropTCPFrameSplitAcrossReadsStaysFramed(t *testing.T) {
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
server 10.60.0.0 255.255.255.0
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
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "split-frame-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "split-frame-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write split frame server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-split-frame-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "split-frame-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: tcpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "split-frame-server.log"), "Initialization Sequence Completed", 20*time.Second)

	var linkAccess sync.Mutex
	var links []*splitFrameConn
	dialContext := func(ctx context.Context, network string, address string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, E.New("unsupported network: ", network)
		}
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, network, address)
		if dialErr != nil {
			return nil, dialErr
		}
		link := &splitFrameConn{Conn: conn, readBuffer: make([]byte, 65535)}
		linkAccess.Lock()
		links = append(links, link)
		linkAccess.Unlock()
		return link, nil
	}
	lastLink := func() *splitFrameConn {
		linkAccess.Lock()
		defer linkAccess.Unlock()
		if len(links) == 0 {
			return nil
		}
		return links[len(links)-1]
	}

	clientContext, cancelClient := context.WithTimeout(context.Background(), 120*time.Second)
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
		t.Fatalf("create split frame interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close split frame interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start split frame interop client: %v", err)
	}

	configuration := waitForClientIfconfig(t, client, 45*time.Second)
	localAddress := configuration.LocalIPv4[0].Addr()
	remoteAddress := netip.MustParseAddr("10.60.0.1")
	establishedLink := lastLink()
	if establishedLink == nil {
		t.Fatal("the established session did not run over the instrumented link")
	}
	handshakeSplits := establishedLink.SplitCount()
	if handshakeSplits == 0 {
		t.Fatal("the instrumented link delivered every control channel packet in one read")
	}

	for sequence := uint16(1); sequence <= 4; sequence++ {
		request := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x6001, sequence,
			bytes.Repeat([]byte{0x60}, 1200))
		writeClientDataPacket(t, client, request, 30*time.Second)
		awaitClientICMPEchoReply(t, client, request, 30*time.Second)
	}
	if establishedLink.SplitCount() <= handshakeSplits {
		t.Fatal("the instrumented link delivered every data channel packet in one read")
	}
	if lastLink() != establishedLink {
		t.Fatal("the client redialed the link while every encapsulated packet stayed framed")
	}
}
