package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	devinproto "byos/internal/devin/proto"
	"byos/internal/provider"
)

var (
	ErrStreamTruncated     = errors.New("truncated Devin stream")
	ErrStreamFrameTooLarge = errors.New("Devin stream frame exceeds configured limit")
	ErrStreamLimit         = errors.New("Devin stream exceeds configured limit")
	ErrStreamIdleTimeout   = errors.New("Devin stream idle timeout")
)

type connectStream struct {
	body                                     io.ReadCloser
	cancel                                   context.CancelFunc
	ctx                                      context.Context
	idle                                     time.Duration
	maxCompressed, maxDecompressed, maxTotal int64
	total                                    int64
	mapper                                   *StreamMapper
	queue                                    []provider.Event
	ended                                    bool
	closeOnce                                sync.Once
}

// StreamChat performs a fresh bootstrap and opens one Connect server stream.
func (c *Client) StreamChat(ctx context.Context, sessionToken string, canonical provider.CanonicalRequest, selectedModel, responseID string) (provider.Stream, error) {
	if c == nil || c.httpClient == nil || c.streamIdleTimeout <= 0 || c.maxFrameCompressedBytes <= 0 || c.maxFrameDecompressedBytes <= 0 || c.maxStreamBytes <= 0 || c.maxToolArgumentBytes <= 0 {
		return nil, ErrInvalidClientConfig
	}
	wire, origin, err := c.PrepareChatRequest(ctx, sessionToken, canonical)
	if err != nil {
		return nil, err
	}
	return c.openChatStream(ctx, wire, origin, selectedModel, responseID)
}

func (c *Client) openChatStream(parent context.Context, message *devinproto.GetChatMessageRequest, origin *url.URL, selectedModel, responseID string) (provider.Stream, error) {
	payload, err := message.Marshal()
	if err != nil {
		return nil, ErrMalformedResponse
	}
	if int64(len(payload)) > c.maxFrameDecompressedBytes {
		return nil, ErrStreamFrameTooLarge
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err = zw.Write(payload); err == nil {
		err = zw.Close()
	} else {
		_ = zw.Close()
	}
	if err != nil {
		return nil, ErrMalformedResponse
	}
	if int64(compressed.Len()) > c.maxFrameCompressedBytes {
		return nil, ErrStreamFrameTooLarge
	}
	frame := make([]byte, 5+compressed.Len())
	frame[0] = 1
	binary.BigEndian.PutUint32(frame[1:5], uint32(compressed.Len()))
	copy(frame[5:], compressed.Bytes())
	ctx, cancel := context.WithCancel(parent)
	if c.streamDeadline > 0 {
		ctx, cancel = context.WithTimeout(parent, c.streamDeadline)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.String()+devinproto.APIServiceGetChatMessagePath, bytes.NewReader(frame))
	if err != nil {
		cancel()
		return nil, ErrMalformedResponse
	}
	req.Header.Set("Content-Type", "application/connect+proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Connect-Content-Encoding", "gzip")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "connect-go/1.18.1 (go1.26.3)")
	req.Header.Set("Connect-Accept-Encoding", "gzip")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		cancel()
		return nil, classifyStatus(resp.StatusCode, resp.Header, time.Now())
	}
	mapper, err := NewStreamMapper(selectedModel, responseID, c.maxToolArgumentBytes)
	if err != nil {
		_ = resp.Body.Close()
		cancel()
		return nil, err
	}
	return &connectStream{body: resp.Body, cancel: cancel, ctx: ctx, idle: c.streamIdleTimeout, maxCompressed: c.maxFrameCompressedBytes, maxDecompressed: c.maxFrameDecompressedBytes, maxTotal: c.maxStreamBytes, mapper: mapper}, nil
}

func (s *connectStream) Next(ctx context.Context) (provider.Event, error) {
	for {
		if len(s.queue) > 0 {
			ev := s.queue[0]
			s.queue = s.queue[1:]
			return ev, nil
		}
		if s.ended {
			return provider.Event{}, io.EOF
		}
		flag, payload, eof, err := s.readFrame(ctx)
		if err != nil {
			return provider.Event{}, err
		}
		if eof {
			s.queue, err = s.mapper.Finalize()
			s.ended = err == nil
			if err != nil {
				return provider.Event{}, err
			}
			continue
		}
		if flag&2 != 0 {
			var trailer struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if len(payload) > 0 && json.Unmarshal(payload, &trailer) != nil {
				return provider.Event{}, ErrMalformedStream
			}
			if trailer.Error != nil {
				return provider.Event{}, ErrMalformedStream
			}
			s.queue, err = s.mapper.Finalize()
			s.ended = err == nil
			if err != nil {
				return provider.Event{}, err
			}
			continue
		}
		var frame devinproto.GetChatMessageResponse
		if frame.Unmarshal(payload) != nil {
			return provider.Event{}, ErrMalformedStream
		}
		s.queue, err = s.mapper.Push(&frame)
		if err != nil {
			return provider.Event{}, err
		}
	}
}

func (s *connectStream) readFrame(caller context.Context) (byte, []byte, bool, error) {
	type result struct {
		flag    byte
		payload []byte
		eof     bool
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		var h [5]byte
		n, err := io.ReadFull(s.body, h[:])
		if err == io.EOF && n == 0 {
			ch <- result{eof: true}
			return
		}
		if err != nil {
			ch <- result{err: ErrStreamTruncated}
			return
		}
		flag := h[0]
		if flag > 3 {
			ch <- result{err: ErrMalformedStream}
			return
		}
		size := int64(binary.BigEndian.Uint32(h[1:]))
		if size > s.maxCompressed {
			ch <- result{err: ErrStreamFrameTooLarge}
			return
		}
		if flag&1 == 0 && size > s.maxDecompressed {
			ch <- result{err: ErrStreamFrameTooLarge}
			return
		}
		raw := make([]byte, size)
		if _, err = io.ReadFull(s.body, raw); err != nil {
			ch <- result{err: ErrStreamTruncated}
			return
		}
		decoded := raw
		if flag&1 != 0 {
			zr, e := gzip.NewReader(bytes.NewReader(raw))
			if e != nil {
				ch <- result{err: ErrMalformedStream}
				return
			}
			decoded, e = io.ReadAll(io.LimitReader(zr, s.maxDecompressed+1))
			closeErr := zr.Close()
			if e != nil || closeErr != nil {
				ch <- result{err: ErrMalformedStream}
				return
			}
			if int64(len(decoded)) > s.maxDecompressed {
				ch <- result{err: ErrStreamFrameTooLarge}
				return
			}
		}
		if int64(len(decoded)) > s.maxTotal-s.total {
			ch <- result{err: ErrStreamLimit}
			return
		}
		s.total += int64(len(decoded))
		ch <- result{flag: flag, payload: decoded}
	}()
	timer := time.NewTimer(s.idle)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.flag, r.payload, r.eof, r.err
	case <-caller.Done():
		_ = s.Close()
		return 0, nil, false, caller.Err()
	case <-s.ctx.Done():
		_ = s.Close()
		return 0, nil, false, s.ctx.Err()
	case <-timer.C:
		_ = s.Close()
		return 0, nil, false, ErrStreamIdleTimeout
	}
}

func (s *connectStream) Close() error {
	if s == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() { s.cancel(); err = s.body.Close() })
	return err
}
