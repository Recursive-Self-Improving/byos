// Portions adapted from CLIProxyAPI/v7 internal/runtime/executor/xai_executor.go (MIT): xAI SSE framing behavior.
// Upstream: https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.71/internal/runtime/executor/xai_executor.go

package xai

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"time"
)

type Event struct {
	Event string
	Data  []byte
}
type activityReader struct {
	reader   io.Reader
	activity chan<- struct{}
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		select {
		case r.activity <- struct{}{}:
		default:
		}
	}
	return n, err
}

type SSEParser struct {
	body     io.ReadCloser
	reader   *bufio.Reader
	idle     time.Duration
	activity chan struct{}
}

func NewSSEParser(body io.ReadCloser, idle time.Duration) *SSEParser {
	activity := make(chan struct{}, 1)
	return &SSEParser{body: body, reader: bufio.NewReaderSize(activityReader{reader: body, activity: activity}, 32<<10), idle: idle, activity: activity}
}
func (p *SSEParser) Next(ctx context.Context) (Event, error) {
	type result struct {
		event Event
		err   error
	}
	done := make(chan result, 1)
	go func() { event, err := p.readEvent(); done <- result{event, err} }()
	if p.idle <= 0 {
		select {
		case <-ctx.Done():
			_ = p.body.Close()
			return Event{}, ctx.Err()
		case value := <-done:
			return value.event, value.err
		}
	}
	timer := time.NewTimer(p.idle)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = p.body.Close()
			return Event{}, ctx.Err()
		case <-timer.C:
			_ = p.body.Close()
			return Event{}, errors.New("SSE idle timeout")
		case <-p.activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(p.idle)
		case value := <-done:
			return value.event, value.err
		}
	}
}
func (p *SSEParser) readEvent() (Event, error) {
	var event Event
	var data []string
	for {
		line, err := p.reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			if errors.Is(err, io.EOF) && len(data) > 0 {
				event.Data = []byte(strings.Join(data, "\n"))
				return event, nil
			}
			return Event{}, err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			if len(data) == 0 {
				if err != nil {
					return Event{}, err
				}
				continue
			}
			event.Data = []byte(strings.Join(data, "\n"))
			return event, nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			event.Event = value
		case "data":
			data = append(data, value)
		}
		if err != nil {
			if len(data) > 0 {
				event.Data = []byte(strings.Join(data, "\n"))
				return event, nil
			}
			return Event{}, err
		}
	}
}
