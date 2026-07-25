package openvpn

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-openvpn/proto"
	E "github.com/sagernet/sing/common/exceptions"
)

type tlsRole uint8

const (
	tlsRoleClient tlsRole = iota
	tlsRoleServer
)

type tlsRoleCallbacks struct {
	deriveKeyMaterial func(session *tlsPeerSession) ([]byte, error)
	appendWrappedKey  func(session *tlsPeerSession, rawPacket []byte, opcode proto.Opcode) []byte
	onTerminate       func(session *tlsPeerSession)
	renegotiate       func(session *tlsPeerSession, channel *tlsControlChannel, initiator bool) (dataCodec, error)
	onRenegotiated    func(session *tlsPeerSession, keyID uint8)
}

type (
	dataWriteObserver       func(keyID uint8, packetID uint32, aeadBlockBytes int, accountedBytes int)
	dataReadCounterObserver func(keyID uint8, accountedBytes int)
	dataReadUsageObserver   func(keyID uint8, packetID uint32, aeadBlockBytes int)
)

func checkTLSKeySourcesComplete(session *tlsPeerSession) error {
	if len(session.clientKeySource.PreMaster) != 48 ||
		len(session.clientKeySource.Random1) != 32 || len(session.clientKeySource.Random2) != 32 ||
		len(session.serverKeySource.Random1) != 32 || len(session.serverKeySource.Random2) != 32 {
		return E.New("incomplete key source material for PRF derivation")
	}
	return nil
}

type tlsPeerSession struct {
	role          tlsRole
	roleCallbacks tlsRoleCallbacks
	hooks         tlsPeerHooks

	packetConnection        proto.PacketConnection
	sessionManager          *proto.SessionManager
	controlChannel          *tlsControlChannel
	tlsConnection           *tls.Conn
	controlReader           *tlsControlMessageReader
	dataCodec               dataCodec
	protection              tlsControlProtection
	dataTransportHeaderSize int
	lifecycleAccess         sync.Mutex
	closed                  bool

	// Upstream tls_pre_decrypt keeps recent key_states addressable by key_id.
	dataKeyAccess      sync.Mutex
	dataWriteAccess    sync.Mutex
	sendCodec          dataCodec
	sendKeyID          uint8
	sendSessionManager *proto.SessionManager
	receiveCodecs      []tlsReceiveCodec

	softResetAccess          sync.Mutex
	renegotiations           map[uint8]*tlsRenegotiationState
	renegotiationsClosed     bool
	renegotiationSequence    uint64
	promotedKeyStateSequence uint64

	closeOnce sync.Once
	closeErr  error

	clientKeySource tlsKeyMethodKeySource
	serverKeySource tlsKeyMethodKeySource

	peerInfo           string
	localOptionsString string
	wrappedClientKey   []byte

	peerID     *uint32
	dataAccess sync.Mutex

	dataWriteObserver       dataWriteObserver
	dataReadCounterObserver dataReadCounterObserver
	dataReadUsageObserver   dataReadUsageObserver
	readActivityObserver    func()
	readBytesObserver       func(payloadBytes int)
	writeActivityObserver   func()
	writeBytesObserver      func(payloadBytes int)

	authenticatedDataPacketObserver func() bool
}

// Upstream BUF_SIZE (ssl.c) bounds plaintext control payloads.
const tlsControlMessageMaxLength = 16384

// crypto/tls splits a single Write above maxPayloadSizeForWrite into several
// records and never merges records on Read, so a record boundary carries no
// message framing.  Upstream key_method_2_read consumes a fixed layout and
// send_control_channel_string NUL-terminates its payload; both are reassembled
// here across reads, and bytes belonging to the next message stay buffered.
type tlsControlMessageReader struct {
	connection   *tls.Conn
	peerIsServer bool
	pending      []byte
}

func (r *tlsControlMessageReader) read(timeout time.Duration) ([]byte, error) {
	readDeadline := time.Time{}
	if timeout > 0 {
		readDeadline = time.Now().Add(timeout)
	}
	err := r.connection.SetReadDeadline(readDeadline)
	if err != nil {
		return nil, err
	}
	readBuffer := make([]byte, tlsControlMessageMaxLength)
	for {
		messageLength, complete := tlsControlMessageLength(r.pending, r.peerIsServer)
		if complete {
			message := r.pending[:messageLength]
			r.pending = append([]byte(nil), r.pending[messageLength:]...)
			return message, nil
		}
		if len(r.pending) >= tlsControlMessageMaxLength {
			return nil, E.New("oversized tls control message")
		}
		readCount, readErr := r.connection.Read(readBuffer)
		r.pending = append(r.pending, readBuffer[:readCount]...)
		if readErr != nil {
			return nil, readErr
		}
	}
}

func tlsControlMessageLength(message []byte, peerIsServer bool) (int, bool) {
	if len(message) < 5 {
		return 0, false
	}
	if binary.BigEndian.Uint32(message[:4]) != 0 || message[4]&0x0f != tlsKeyMethod2 {
		nullIndex := bytes.IndexByte(message, 0)
		if nullIndex < 0 {
			return 0, false
		}
		return nullIndex + 1, true
	}
	// Upstream key_source2_read reads pre_master only from the client.
	messageLength := tlsKeyMethod2HeaderLength + 2*tlsKeyMethodRandomLength
	if !peerIsServer {
		messageLength += tlsKeyMethodPreMasterLength
	}
	for range tlsKeyMethod2StringCount {
		if len(message) < messageLength+2 {
			return 0, false
		}
		messageLength += 2 + int(binary.BigEndian.Uint16(message[messageLength:messageLength+2]))
	}
	if len(message) < messageLength {
		return 0, false
	}
	return messageLength, true
}

func (s *tlsPeerSession) handleIncomingHardReset(packet *proto.Packet) {
	if packet == nil || packet.KeyID != 0 || !s.validRemoteHardResetOpcode(packet.Opcode) {
		return
	}
	remoteSessionID, hasRemoteSessionID := s.sessionManager.RemoteSessionID()
	if hasRemoteSessionID && packet.LocalSessionID == remoteSessionID {
		return
	}
	// Upstream tls_pre_decrypt routes a hard reset whose session id matches no
	// live session to a fresh TM_INITIAL session and leaves TM_ACTIVE running.
	// Without tls-auth/tls-crypt nothing authenticated the packet, so acting on
	// it would let any forged datagram tear the tunnel down.
	if s.protection.crypt == nil && s.protection.auth == nil {
		return
	}
	// Upstream hard resets create a new tls_session and key_state.
	restartErr := ErrPeerRestart
	if s.role == tlsRoleClient {
		restartErr = ErrServerRestart
	}
	go s.hooks.sessionTerminated(restartErr)
}

func (s *tlsPeerSession) validRemoteHardResetOpcode(opcode proto.Opcode) bool {
	if s.role == tlsRoleClient {
		return opcode == proto.OpcodeControlHardResetServerV1 || opcode == proto.OpcodeControlHardResetServerV2
	}
	return opcode == proto.OpcodeControlHardResetClientV1 ||
		opcode == proto.OpcodeControlHardResetClientV2 ||
		opcode == proto.OpcodeControlHardResetClientV3
}

func (s *tlsPeerSession) Close() error {
	s.closeOnce.Do(func() {
		s.markClosing()
		s.lifecycleAccess.Lock()
		packetConnection := s.packetConnection
		tlsConnection := s.tlsConnection
		controlChannel := s.controlChannel
		s.lifecycleAccess.Unlock()
		if s.roleCallbacks.onTerminate != nil {
			s.roleCallbacks.onTerminate(s)
		}
		if packetConnection != nil {
			s.closeErr = E.Errors(s.closeErr, packetConnection.Close())
		}
		s.failAllRenegotiations(net.ErrClosed)
		if tlsConnection != nil {
			s.closeErr = E.Errors(s.closeErr, tlsConnection.Close())
		}
		if controlChannel != nil {
			s.closeErr = E.Errors(s.closeErr, controlChannel.Close())
		}
	})
	return s.closeErr
}

func (s *tlsPeerSession) markClosing() {
	s.lifecycleAccess.Lock()
	s.closed = true
	s.lifecycleAccess.Unlock()
	s.softResetAccess.Lock()
	s.renegotiationsClosed = true
	s.softResetAccess.Unlock()
}

func (s *tlsPeerSession) installInitialControlChannel(channel *tlsControlChannel, tlsConnection *tls.Conn) bool {
	if channel == nil || tlsConnection == nil {
		return false
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	if s.closed {
		return false
	}
	s.controlChannel = channel
	s.tlsConnection = tlsConnection
	s.controlReader = &tlsControlMessageReader{
		connection:   tlsConnection,
		peerIsServer: s.role == tlsRoleClient,
	}
	channel.loopWaitGroup.Add(2)
	go channel.runReader()
	go channel.runSender()
	return true
}

func (s *tlsPeerSession) installPacketConnection(packetConnection proto.PacketConnection) bool {
	if packetConnection == nil {
		return false
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	if s.closed {
		return false
	}
	s.packetConnection = packetConnection
	return true
}

func (s *tlsPeerSession) writeHandshakePacket(packet *proto.Packet) error {
	rawPacket, err := packet.Bytes()
	if err != nil {
		return err
	}
	if s.protection.crypt != nil {
		rawPacket = s.protection.crypt.encodeControlPacket(rawPacket)
	} else if s.protection.auth != nil {
		rawPacket = s.protection.auth.encodeControlPacket(rawPacket)
	}
	if s.roleCallbacks.appendWrappedKey != nil {
		rawPacket = s.roleCallbacks.appendWrappedKey(s, rawPacket, packet.Opcode)
	}
	return s.packetConnection.WritePacket(rawPacket)
}
