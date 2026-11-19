package dnsutils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
)

const DoQProtocolErrorCode = 0x2

var ErrDoQProtocol = errors.New("DoQ protocol error")

// ReadDoQFrame reads one DNS message followed by the peer's stream FIN.
// The caller owns the pooled payload on success.
func ReadDoQFrame(stream io.Reader, response bool) (*[]byte, error) {
	payload, err := ReadRawMsgFromTCP(stream)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrPayloadTooSmall) {
			return nil, fmt.Errorf("%w: invalid message framing: %w", ErrDoQProtocol, err)
		}
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			pool.ReleaseBuf(payload)
		}
	}()
	b := *payload
	if binary.BigEndian.Uint16(b) != 0 {
		return nil, fmt.Errorf("%w: nonzero message ID", ErrDoQProtocol)
	}
	if (b[2]&0x80 != 0) != response {
		return nil, fmt.Errorf("%w: unexpected DNS message direction", ErrDoQProtocol)
	}
	var extra [1]byte
	if _, err := io.ReadFull(stream, extra[:]); err != nil {
		if errors.Is(err, io.EOF) {
			keep = true
			return payload, nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, fmt.Errorf("%w: missing stream FIN: %w", ErrDoQProtocol, err)
		}
		return nil, err
	}
	return nil, fmt.Errorf("%w: data after the DNS message", ErrDoQProtocol)
}
