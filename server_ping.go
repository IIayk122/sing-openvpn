package openvpn

import (
	"context"
	"sync"
	"time"
)

type tlsServerPinger struct {
	session *tlsServerSession

	access sync.Mutex

	lastInboundTime  time.Time
	lastOutboundTime time.Time
	pingInterval     time.Duration
	pingRestart      time.Duration
}

func (p *tlsServerPinger) markActivity(inbound bool, outbound bool) {
	p.access.Lock()
	defer p.access.Unlock()
	now := time.Now()
	if inbound {
		p.lastInboundTime = now
	}
	if outbound {
		p.lastOutboundTime = now
	}
}

func (p *tlsServerPinger) snapshotActivity() (time.Time, time.Time) {
	p.access.Lock()
	defer p.access.Unlock()
	return p.lastInboundTime, p.lastOutboundTime
}

func (p *tlsServerPinger) runLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		lastInbound, lastOutbound := p.snapshotActivity()
		now := time.Now()
		if shouldExitForPingTimeout(lastInbound, now, p.pingRestart) {
			_ = p.session.Close()
			return
		}
		if p.pingInterval > 0 && now.Sub(lastOutbound) >= p.pingInterval {
			// Upstream check_ping_send_dowork never terminates the instance
			// because a keepalive could not be queued; tryWriteDataPacket also
			// reports plain contention on the data write lock.
			writeErr := p.session.tryWriteDataPacket(openVPNDataChannelPingPayload)
			if writeErr == nil {
				p.markActivity(false, true)
			}
		}
	}
}
