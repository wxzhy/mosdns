package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/quic-go/quic-go"
)

const (
	quicQueryTimeout = time.Second * 4
)

const (
	// RFC 9250 4.3. DoQ Error Codes
	_DOQ_REQUEST_CANCELLED = quic.StreamErrorCode(0x3)
)

var _ DnsConn = (*QuicDnsConn)(nil)

type QuicDnsConn struct {
	c *quic.Conn
}

func NewQuicDnsConn(c *quic.Conn) *QuicDnsConn {
	return &QuicDnsConn{c: c}
}

func (c *QuicDnsConn) Close() error {
	return c.c.CloseWithError(0, "")
}

func (c *QuicDnsConn) ReserveNewQuery() (_ ReservedExchanger, closed bool) {
	select {
	case <-c.c.Context().Done():
		return nil, true
	default:
	}
	s, err := c.c.OpenStream()
	// We just checked the connection is alive. So we are assuming the error
	// is caused by reaching the peer's stream limit.
	if err != nil {
		return nil, false
	}
	return &quicReservedExchanger{conn: c.c, stream: s}, false
}

type quicReservedExchanger struct {
	conn   *quic.Conn
	stream *quic.Stream
}

var _ ReservedExchanger = (*quicReservedExchanger)(nil)

func (ote *quicReservedExchanger) ExchangeReserved(ctx context.Context, q []byte) (*[]byte, error) {
	stream := ote.stream
	if ctx.Err() != nil {
		ote.WithdrawReserved()
		return nil, context.Cause(ctx)
	}
	if len(q) < dnsutils.DnsHeaderLen {
		ote.WithdrawReserved()
		return nil, dnsutils.ErrPayloadTooSmall
	}

	payload, err := copyMsgWithLenHdr(q)
	if err != nil {
		ote.WithdrawReserved()
		return nil, err
	}

	// 4.2.1.  DNS Message IDs
	//    When sending queries over a QUIC connection, the DNS Message ID MUST
	//    be set to 0.  The stream mapping for DoQ allows for unambiguous
	//    correlation of queries and responses, so the Message ID field is not
	//    required.
	orgQid := binary.BigEndian.Uint16((*payload)[2:])
	binary.BigEndian.PutUint16((*payload)[2:], 0)

	stop := context.AfterFunc(ctx, ote.WithdrawReserved)
	defer stop()
	stream.SetDeadline(time.Now().Add(quicQueryTimeout))
	n, err := stream.Write(*payload)
	if err == nil && n != len(*payload) {
		err = io.ErrShortWrite
	}
	pool.ReleaseBuf(payload)
	if err == nil {
		// Close sends FIN on the request side and leaves the response readable.
		err = stream.Close()
	}
	if err != nil {
		ote.WithdrawReserved()
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		return nil, err
	}

	resp, err := dnsutils.ReadDoQFrame(stream, true)
	if err != nil {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if errors.Is(err, dnsutils.ErrDoQProtocol) {
			ote.conn.CloseWithError(dnsutils.DoQProtocolErrorCode, err.Error())
		} else {
			stream.CancelRead(_DOQ_REQUEST_CANCELLED)
		}
		return nil, err
	}
	binary.BigEndian.PutUint16(*resp, orgQid)
	return resp, nil
}

func (ote *quicReservedExchanger) WithdrawReserved() {
	s := ote.stream
	s.CancelRead(_DOQ_REQUEST_CANCELLED)
	s.CancelWrite(_DOQ_REQUEST_CANCELLED)
}
