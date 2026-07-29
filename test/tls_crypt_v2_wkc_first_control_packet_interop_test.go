package test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

const (
	// Upstream TLS_CRYPT_V2_MAX_WKC_LEN, and the largest metadata a wrapped
	// client key of that length can carry: the 256 byte client key, the 32 byte
	// tag, the two length bytes and the one metadata type byte take the rest.
	tlsCryptV2MaximumWrappedClientKeyLength = 1024
	tlsCryptV2MaximumMetadataLength         = 733
	tlsCryptV2ClientKeyMaterialLength       = 256

	ethernetUDPPayloadLimit = 1500 - 20 - 8
)

// A UDP path which carries nothing larger than an Ethernet frame: an oversized
// datagram is reported as sent and then dropped, the way a link which refuses
// to fragment it behaves.
type ethernetPathConn struct {
	net.Conn
	access             sync.Mutex
	largestDatagram    int
	oversizedDatagrams int
}

func (c *ethernetPathConn) Write(packet []byte) (int, error) {
	c.access.Lock()
	c.largestDatagram = max(c.largestDatagram, len(packet))
	oversized := len(packet) > ethernetUDPPayloadLimit
	if oversized {
		c.oversizedDatagrams++
	}
	c.access.Unlock()
	if oversized {
		return len(packet), nil
	}
	return c.Conn.Write(packet)
}

type ethernetPathDialer struct {
	localPort int
	access    sync.Mutex
	conns     []*ethernetPathConn
}

func (d *ethernetPathDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: d.localPort}}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	pathConn := &ethernetPathConn{Conn: conn}
	d.access.Lock()
	d.conns = append(d.conns, pathConn)
	d.access.Unlock()
	return pathConn, nil
}

func (d *ethernetPathDialer) state() (int, int) {
	d.access.Lock()
	defer d.access.Unlock()
	largestDatagram := 0
	oversizedDatagrams := 0
	for _, pathConn := range d.conns {
		pathConn.access.Lock()
		largestDatagram = max(largestDatagram, pathConn.largestDatagram)
		oversizedDatagrams += pathConn.oversizedDatagrams
		pathConn.access.Unlock()
	}
	return largestDatagram, oversizedDatagrams
}

// A tls-crypt-v2 client appends its wrapped client key to the same datagram as
// the first reliable control packet, so upstream write_outgoing_tls_ciphertext
// shortens that packet's payload by the length of the key.  A key wrapped
// around the maximum metadata reaches TLS_CRYPT_V2_MAX_WKC_LEN, so a client
// which still fills that packet with a whole control channel payload sends more
// than two kilobytes in one datagram, which no Ethernet path carries unless it
// fragments the packet.
func TestOpenVPNInteropTLSCryptV2WrappedClientKeyShortensFirstControlPacket(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	serverPort := reserveInteropPort(t, "udp")
	clientPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "server-tls.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               dockerPath("fixtures", "ca.crt"),
		CertPath:             dockerPath("fixtures", "server.crt"),
		KeyPath:              dockerPath("fixtures", "server.key"),
		TLSCryptV2Path:       dockerPath("fixtures", "tls-crypt-v2-server.key"),
		TLSCryptV2Option:     "force-cookie",
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		LogPath:              dockerPath("logs", "server.log"),
	})

	clientKeyName := "tls-crypt-v2-client-max-metadata.key"
	metadata := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("M"), tlsCryptV2MaximumMetadataLength))
	dockerClientKeyPath := dockerPath("rendered", clientKeyName)
	generateClientKeyCommand := "openvpn --tls-crypt-v2 " + dockerPath("fixtures", "tls-crypt-v2-server.key") +
		" --genkey tls-crypt-v2-client " + dockerClientKeyPath + " " + metadata
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-wkc-first-control-server-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			generateClientKeyCommand + " && chmod 0644 " + dockerClientKeyPath +
				" && openvpn --config " + dockerPath("rendered", "server-tls.conf"),
		},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "server.log"), "Initialization Sequence Completed", 20*time.Second)

	clientKeyPath := filepath.Join(workspace.renderedDir, clientKeyName)
	wrappedClientKeyLength := readWrappedClientKeyLength(t, clientKeyPath)
	if wrappedClientKeyLength != tlsCryptV2MaximumWrappedClientKeyLength {
		t.Fatalf("expected a wrapped client key of %d bytes, got %d", tlsCryptV2MaximumWrappedClientKeyLength, wrappedClientKeyLength)
	}

	clientContext, cancelClient := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelClient()
	pathDialer := &ethernetPathDialer{localPort: clientPort}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		largestDatagram, oversizedDatagrams := pathDialer.state()
		t.Logf("client sent %d datagrams above the %d byte path limit, largest datagram %d bytes",
			oversizedDatagrams, ethernetUDPPayloadLimit, largestDatagram)
	})
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", serverPort)), "udp4")},
			DialContext: pathDialer.DialContext,
			Protocol:    "udp4",
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher: "AES-256-GCM",
			Auth:   "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
			CryptV2:              openvpn.Material{Path: clientKeyPath},
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()
	startErr := client.Start()
	if startErr != nil {
		t.Fatalf("start client: %v", startErr)
	}

	configuration := waitForClientIfconfig(t, client, 30*time.Second)
	exchangeTLSClientEcho(t, client, configuration, 1, 0)

	// The wrapped client key alone is larger than a whole control channel
	// packet, so the datagram carrying it stays the largest of the handshake;
	// a smaller one would mean the server never asked for the key to be resent
	// and the run proved nothing.
	largestDatagram, _ := pathDialer.state()
	if largestDatagram < wrappedClientKeyLength {
		t.Fatalf("no datagram carried the %d byte wrapped client key, largest was %d bytes", wrappedClientKeyLength, largestDatagram)
	}
}

func readWrappedClientKeyLength(t *testing.T, path string) int {
	t.Helper()
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated tls-crypt-v2 client key: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatalf("generated tls-crypt-v2 client key is not PEM: %q", keyPEM)
	}
	if len(block.Bytes) < tlsCryptV2ClientKeyMaterialLength {
		t.Fatalf("generated tls-crypt-v2 client key holds %d bytes", len(block.Bytes))
	}
	return len(block.Bytes) - tlsCryptV2ClientKeyMaterialLength
}
