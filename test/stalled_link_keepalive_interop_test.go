package test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

// check_coarse_timers (forward.c) runs check_ping_send, check_ping_restart,
// check_inactivity_timeout and check_session_timeout on every event loop pass,
// whether or not process_outgoing_link still holds a packet the link has not
// taken.  A link that stops accepting writes therefore still expires
// --ping-restart, and the connection restarts instead of standing dead.
type stalledLinkConn struct {
	net.Conn
	access    sync.Mutex
	stalled   bool
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *stalledLinkConn) stall() {
	c.access.Lock()
	c.stalled = true
	c.access.Unlock()
}

func (c *stalledLinkConn) isStalled() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.stalled
}

func (c *stalledLinkConn) Read(buffer []byte) (int, error) {
	for {
		readCount, err := c.Conn.Read(buffer)
		if err != nil || !c.isStalled() {
			return readCount, err
		}
	}
}

func (c *stalledLinkConn) Write(buffer []byte) (int, error) {
	if c.isStalled() {
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(buffer)
}

func (c *stalledLinkConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return c.Conn.Close()
}

func TestOpenVPNInteropStalledLinkWriteKeepsClientPingRestartArmed(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	serverPort := reserveInteropPort(t, "udp")
	serverConfiguration := fmt.Sprintf(`port %d
proto udp4
dev tun
topology subnet
server 10.51.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
keepalive 2 6
persist-key
persist-tun
verb 4
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "stalled-link-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "stalled-link-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write stalled link server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-stalled-link-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "stalled-link-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "stalled-link-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	var linkAccess sync.Mutex
	var links []*stalledLinkConn
	dialContext := func(ctx context.Context, network string, address string) (net.Conn, error) {
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, network, address)
		if dialErr != nil {
			return nil, dialErr
		}
		link := &stalledLinkConn{Conn: conn, closed: make(chan struct{})}
		linkAccess.Lock()
		links = append(links, link)
		linkAccess.Unlock()
		return link, nil
	}
	dialedLinks := func() (int, *stalledLinkConn) {
		linkAccess.Lock()
		defer linkAccess.Unlock()
		if len(links) == 0 {
			return 0, nil
		}
		return len(links), links[len(links)-1]
	}

	clientContext, cancelClient := context.WithTimeout(context.Background(), 120*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4")},
			DialContext: dialContext,
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
		Timing: openvpn.ClientTimingOptions{HandWindow: 10 * time.Second},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create stalled link interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close stalled link interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start stalled link interop client: %v", err)
	}

	configuration := waitForClientIfconfig(t, client, 20*time.Second)
	if configuration.PingRestart <= 0 || configuration.PingInterval <= 0 {
		t.Fatalf("expected the server to push a keepalive, got ping %v ping-restart %v",
			configuration.PingInterval, configuration.PingRestart)
	}
	localAddress := configuration.LocalIPv4[0].Addr()
	remoteAddress := netip.MustParseAddr("10.51.0.1")
	establishedRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5151, 1, bytes.Repeat([]byte{0x3c}, 64))
	writeClientDataPacket(t, client, establishedRequest, 20*time.Second)
	awaitClientICMPEchoReply(t, client, establishedRequest, 20*time.Second)

	establishedLinkCount, establishedLink := dialedLinks()
	if establishedLink == nil {
		t.Fatal("the established session did not run over the instrumented link")
	}
	establishedLink.stall()

	// The stalled tunnel packet owns the data write path across the link write,
	// which is the state the keepalive has to keep measuring through.
	stalledWriteRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5151, 2, bytes.Repeat([]byte{0x3c}, 64))
	stalledWriteDone := make(chan struct{})
	go func() {
		defer close(stalledWriteDone)
		_ = client.WriteDataPacket(stalledWriteRequest)
	}()
	select {
	case <-stalledWriteDone:
		t.Fatal("the instrumented link carried the tunnel packet, so no data write is stalled")
	case <-time.After(2 * time.Second):
	}

	restartDeadline := time.Now().Add(45 * time.Second)
	for {
		linkCount, _ := dialedLinks()
		if linkCount > establishedLinkCount {
			break
		}
		if !time.Now().Before(restartDeadline) {
			t.Fatal("the client never restarted the session: the stalled link write stopped its --ping-restart clock")
		}
		time.Sleep(interopPollInterval)
	}
	select {
	case <-stalledWriteDone:
	case <-time.After(20 * time.Second):
		t.Fatal("the session restart never released the tunnel packet stalled on the link")
	}

	for !client.Ready() {
		if !time.Now().Before(restartDeadline) {
			t.Fatal("the client did not re-establish the tunnel after the ping-restart")
		}
		time.Sleep(interopPollInterval)
	}
	restartedConfiguration := client.TunnelConfiguration()
	if len(restartedConfiguration.LocalIPv4) == 0 {
		t.Fatal("the re-established tunnel carries no pushed ifconfig")
	}
	restartedLocalAddress := restartedConfiguration.LocalIPv4[0].Addr()
	restartedRequest := buildStaticICMPEchoRequest(t, restartedLocalAddress, remoteAddress, 0x5151, 3, bytes.Repeat([]byte{0x3c}, 64))
	writeClientDataPacket(t, client, restartedRequest, 30*time.Second)
	awaitClientICMPEchoReply(t, client, restartedRequest, 30*time.Second)
}
