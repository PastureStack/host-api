package logs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PastureStack/websocket-proxy/common"
)

// Pause after PipeReader consumed/acknowledged the final write, before its
// Scanner can observe those bytes. This is a deterministic legal scheduling
// boundary; no sleeps or Docker/network dependency choose the outcome.
type eofReadGate struct {
	io.ReadCloser
	once    sync.Once
	gated   chan struct{}
	release chan struct{}
}

func (r *eofReadGate) Read(data []byte) (int, error) {
	n, err := r.ReadCloser.Read(data)
	if bytes.Contains(data[:n], []byte("record-199")) {
		r.once.Do(func() { close(r.gated); <-r.release })
	}
	return n, err
}

func TestLogsStreamEOFDrainsBeforeClose(t *testing.T) {
	reader, writer := io.Pipe()
	gate := &eofReadGate{ReadCloser: reader, gated: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(gate.release) }) }
	t.Cleanup(unblock)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	response := make(chan common.Message, 256)
	producerDone, handlerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(handlerDone)
		defer cancel()
		defer reader.Close()
		defer writer.Close()
		_ = streamContainerLogs(ctx, "own", gate, writer, response, func() error {
			for i := 0; i < 200; i++ {
				if _, err := (stdoutWriter{writer}).Write([]byte(fmt.Sprintf("record-%03d 界😀 literal:\ufffd\n", i))); err != nil {
					return err
				}
			}
			close(producerDone)
			return nil
		})
		response <- common.Message{Key: "own", Type: common.Close}
	}()
	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("last Pipe write was not acknowledged")
	}
	select {
	case <-gate.gated:
	case <-time.After(time.Second):
		t.Fatal("deterministic scanner scheduling gate was not reached")
	}
	select {
	case <-handlerDone:
		t.Fatal("native Close overtook the final scanner Body after Docker EOF")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	var bodies []string
	for {
		select {
		case message := <-response:
			if message.Type == common.Close {
				if len(bodies) != 200 || bodies[199] != "01 record-199 界😀 literal:\ufffd\n" {
					t.Fatalf("EOF discarded or changed data: bodies=%d", len(bodies))
				}
				return
			}
			bodies = append(bodies, message.Body)
		case <-time.After(time.Second):
			t.Fatal("drained stream failed to close")
		}
	}
}

func TestLogsStreamCancellationUnblocksUnreadResponse(t *testing.T) {
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response := make(chan common.Message) // No backend consumer after disconnect.
	firstWritten, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = streamContainerLogs(ctx, "own", reader, writer, response, func() error {
			_, err := (stdoutWriter{writer}).Write([]byte("first\n"))
			close(firstWritten)
			if err != nil {
				return err
			}
			_, err = (stdoutWriter{writer}).Write([]byte("second\n"))
			return err
		})
	}()
	select {
	case <-firstWritten:
	case <-time.After(time.Second):
		t.Fatal("first write not consumed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled response send or producer remained blocked")
	}
}

func TestLogsStreamScannerLimitUnblocksProducer(t *testing.T) {
	reader, writer := io.Pipe()
	response := make(chan common.Message, 1)
	done := make(chan error, 1)
	go func() {
		done <- streamContainerLogs(context.Background(), "own", reader, writer, response, func() error {
			_, err := (stdoutWriter{writer}).Write([]byte(strings.Repeat("x", 4*1024*1024+1)))
			return err
		})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("scanner failure did not close producer pipe")
		}
	case <-time.After(time.Second):
		t.Fatal("scanner token limit left Docker writer blocked")
	}
}
