package transport

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type lazyDnsConn struct {
	maxConcurrentQuery int
	cancelDial         context.CancelFunc

	mu            sync.Mutex
	closed        bool
	reservedQuery int
	dialFinished  chan struct{}
	earlySlots    chan ReservedExchanger
	c             DnsConn
	dialErr       error

	// 1: dial completed and all early reserve call finished.
	// 2: dial failed.
	fastPath atomic.Uint32
}

var _ DnsConn = (*lazyDnsConn)(nil)

var (
	errLazyConnDialCanceled = errors.New("lazy dial canceled")
)

func newLazyDnsConn(
	dial func(ctx context.Context) (DnsConn, error),
	dialTimeout time.Duration,
	maxConcurrentQueryWhileDialing int, // must be valid, no default value
	logger *zap.Logger, // must non-nil
) *lazyDnsConn {
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	dialCtx, cancelDial := context.WithTimeout(context.Background(), dialTimeout)
	lc := &lazyDnsConn{
		maxConcurrentQuery: maxConcurrentQueryWhileDialing,
		cancelDial:         cancelDial,
		dialFinished:       make(chan struct{}),
	}

	go func() {
		dc, err := dial(dialCtx)
		cancelDial()
		if err != nil {
			logger.Check(zap.WarnLevel, "failed to dial dns conn").Write(zap.Error(err))
		}
		lc.mu.Lock()
		if lc.closed { // lc was closed and dial was canceled
			lc.mu.Unlock()
			if dc != nil {
				dc.Close()
			}
			return
		}

		lc.c = dc
		lc.dialErr = err
		if err != nil {
			lc.fastPath.Store(2)
		} else {
			lc.earlySlots = make(chan ReservedExchanger, lc.reservedQuery)
			for i := 0; i < lc.reservedQuery; i++ {
				rxc, closed := dc.ReserveNewQuery()
				if closed {
					for len(lc.earlySlots) > 0 {
						(<-lc.earlySlots).WithdrawReserved()
					}
					lc.dialErr = ErrClosedTransport
					lc.fastPath.Store(2)
					break
				}
				if rxc != nil {
					lc.earlySlots <- rxc
				}
			}
			if lc.dialErr == nil {
				lc.fastPath.Store(1)
			}
		}
		close(lc.dialFinished)
		lc.mu.Unlock()
	}()
	return lc
}

func (lc *lazyDnsConn) Close() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.closed {
		return nil
	}
	lc.closed = true

	if lc.c == nil && lc.dialErr == nil { // still dialing
		lc.cancelDial()
		lc.dialErr = errLazyConnDialCanceled
		lc.fastPath.Store(2)
		close(lc.dialFinished)
	} else {
		// close connection
		if lc.c != nil {
			lc.c.Close()
		}
	}
	return nil
}

func (lc *lazyDnsConn) ReserveNewQuery() (_ ReservedExchanger, closed bool) {
	switch lc.fastPath.Load() {
	case 1:
		return lc.c.ReserveNewQuery()
	case 2:
		return nil, true
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()

	select {
	case <-lc.dialFinished:
		if lc.dialErr != nil {
			return nil, true
		}
		return lc.c.ReserveNewQuery()
	default:
		if lc.reservedQuery >= lc.maxConcurrentQuery {
			return nil, false
		}
		lc.reservedQuery++
		return (*lazyDnsConnEarlyReservedExchanger)(lc), false
	}
}

type lazyDnsConnEarlyReservedExchanger lazyDnsConn

var _ ReservedExchanger = (*lazyDnsConnEarlyReservedExchanger)(nil)

func (ote *lazyDnsConnEarlyReservedExchanger) takeEarlySlot() (ReservedExchanger, error) {
	if ote.dialErr != nil {
		return nil, ote.dialErr
	}
	select {
	case rxc := <-ote.earlySlots:
		return rxc, nil
	default:
		return nil, ErrLazyConnCannotReserveQueryExchanger
	}
}

func (ote *lazyDnsConnEarlyReservedExchanger) ExchangeReserved(ctx context.Context, q []byte) (resp *[]byte, err error) {
	select {
	case <-ctx.Done():
		ote.WithdrawReserved()
		return nil, context.Cause(ctx)
	case <-ote.dialFinished:
		rxc, err := ote.takeEarlySlot()
		if err != nil {
			return nil, err
		}
		return rxc.ExchangeReserved(ctx, q)
	}
}

func (ote *lazyDnsConnEarlyReservedExchanger) WithdrawReserved() {
	ote.mu.Lock()
	select {
	case <-ote.dialFinished:
		ote.mu.Unlock()
		if rxc, _ := ote.takeEarlySlot(); rxc != nil {
			rxc.WithdrawReserved()
		}
	default:
		ote.reservedQuery--
		ote.mu.Unlock()
	}
}
