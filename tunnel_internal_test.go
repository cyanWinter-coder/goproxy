package goproxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingReadCloser blocks in Read until Close is called, then returns
// errStreamStopped. It models the client-to-proxy direction of an HTTP/2
// CONNECT stream.
type blockingReadCloser struct {
	closed chan struct{}
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{closed: make(chan struct{})}
}

func (r *blockingReadCloser) Read([]byte) (int, error) {
	<-r.closed
	return 0, errStreamStoppedInternal
}

func (r *blockingReadCloser) Close() error {
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

var errStreamStoppedInternal = errors.New("stream stopped")

// scriptedConn is a net.Conn whose reads fail immediately with readErr.
type scriptedConn struct {
	readErr error
	closed  chan struct{}
}

func newScriptedConn(readErr error) *scriptedConn {
	return &scriptedConn{readErr: readErr, closed: make(chan struct{})}
}

func (c *scriptedConn) Read([]byte) (int, error) { return 0, c.readErr }
func (c *scriptedConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *scriptedConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *scriptedConn) LocalAddr() net.Addr              { return tunnelTestAddr("local") }
func (c *scriptedConn) RemoteAddr() net.Addr             { return tunnelTestAddr("remote") }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type tunnelTestAddr string

func (a tunnelTestAddr) Network() string { return "test" }
func (a tunnelTestAddr) String() string  { return string(a) }

// A copy error must reach ctx.Error and ConnectionErrHandler, but the handler
// must not be able to write a second HTTP response into an HTTP/2 stream that
// already started carrying tunnel data.
func TestRelayTunnelCopyErrorDoesNotWriteToStartedH2Stream(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodConnect, "https://example.com", nil)
	require.NoError(t, err)
	req.RemoteAddr = "198.51.100.7:1234"

	recorder := httptest.NewRecorder()
	stream := &h2StreamConn{
		r:      newBlockingReadCloser(),
		w:      recorder,
		ctrl:   http.NewResponseController(recorder),
		local:  tunnelTestAddr("h2-proxy"),
		remote: tunnelTestAddr(req.RemoteAddr),
	}

	var (
		handlerCalls int
		handlerErr   error
		handlerW     io.Writer
	)
	proxy := NewProxyHttpServer()
	proxy.ConnectionErrHandler = func(w io.Writer, _ *ProxyCtx, err error) {
		handlerCalls++
		handlerErr = err
		handlerW = w
	}

	ctx := &ProxyCtx{Req: req, Proxy: proxy}
	upstream := newScriptedConn(errors.New("upstream exploded"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.relayTunnel(ctx, stream, stream.r, upstream, nil)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relayTunnel did not return after the copy error")
	}

	assert.Equal(t, 1, handlerCalls, "the copy error must be reported exactly once")
	require.Error(t, handlerErr)
	assert.Contains(t, handlerErr.Error(), "upstream exploded")
	assert.Equal(t, io.Discard, handlerW,
		"an already started HTTP/2 stream must not receive a second response")
	require.Error(t, ctx.Error, "copy errors must be observable through ctx.Error")
	assert.Zero(t, recorder.Body.Len(), "no error response may be written into the tunnel stream")
}

// A clean EOF on the upstream side must not be reported as an error; the
// response direction simply ends so the handler can emit END_STREAM.
func TestRelayTunnelCleanUpstreamEOFIsNotAnError(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodConnect, "https://example.com", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	stream := &h2StreamConn{
		r:      newBlockingReadCloser(),
		w:      recorder,
		ctrl:   http.NewResponseController(recorder),
		local:  tunnelTestAddr("h2-proxy"),
		remote: tunnelTestAddr("198.51.100.7:1234"),
	}

	proxy := NewProxyHttpServer()
	calls := 0
	proxy.ConnectionErrHandler = func(io.Writer, *ProxyCtx, error) { calls++ }

	ctx := &ProxyCtx{Req: req, Proxy: proxy}
	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.relayTunnel(ctx, stream, stream.r, newScriptedConn(io.EOF), nil)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relayTunnel did not return after a clean upstream EOF")
	}

	assert.Zero(t, calls)
	assert.NoError(t, ctx.Error)
}
