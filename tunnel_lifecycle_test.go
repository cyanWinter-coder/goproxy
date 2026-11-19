package goproxy_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
}

// startH2ProxyServer serves proxy over TLS with ALPN h2, the configuration in
// which CONNECT is handled without hijacking.
func startH2ProxyServer(t *testing.T, proxy *goproxy.ProxyHttpServer) *httptest.Server {
	t.Helper()
	proxySrv := httptest.NewUnstartedServer(proxy)
	proxySrv.EnableHTTP2 = true
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)
	return proxySrv
}

// listenTunnelTarget starts a TCP listener standing in for the CONNECT target.
func listenTunnelTarget(t *testing.T) net.Listener {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TestHTTP2MitmClientCancelCancelsUpstreamRequest verifies that the base
// context of an HTTP/2 MITM session follows the CONNECT stream: when the client
// abandons it, in-flight upstream requests are cancelled rather than left
// running.
func TestHTTP2MitmClientCancelCancelsUpstreamRequest(t *testing.T) {
	clearProxyEnv(t)

	requestStarted := make(chan struct{})
	requestCancelled := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
		close(requestCancelled)
	}))
	t.Cleanup(backend.Close)

	proxy := goproxy.NewProxyHttpServer()
	proxy.AllowHTTP2 = true
	// Do not inherit the process-wide proxy environment: ProxyFromEnvironment
	// caches it on first use, which would route this backend through whatever
	// proxy the test runner happens to have configured.
	proxy.Tr = &http.Transport{}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://"+backendURL.Host, pr)
	require.NoError(t, err)
	connectResp, err := h2client.RoundTrip(connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)

	// Speak cleartext HTTP/1.1 inside the MITM tunnel: the backend never
	// answers, so the request stays in flight.
	_, err = fmt.Fprintf(pw, "GET /hang HTTP/1.1\r\nHost: %s\r\n\r\n", backendURL.Host)
	require.NoError(t, err)

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was never started")
	}

	// Abandon the CONNECT stream; the in-flight upstream request must be
	// cancelled through the MITM session's base context.
	require.NoError(t, connectResp.Body.Close())

	select {
	case <-requestCancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was not cancelled when the client abandoned the tunnel")
	}
}

// TestHTTP2ConnectClientCancelDuringTLSHandshake verifies that a client that
// disconnects in the middle of the MITM TLS handshake does not leave the
// handshake (or an upstream connection) hanging.
func TestHTTP2ConnectClientCancelDuringTLSHandshake(t *testing.T) {
	clearProxyEnv(t)

	proxy := goproxy.NewProxyHttpServer()
	proxy.AllowHTTP2 = true
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://example.com:443", pr)
	require.NoError(t, err)

	connectResp, err := h2client.RoundTrip(connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)

	// Send an incomplete TLS ClientHello and immediately abandon the stream:
	// the proxy's TLS handshake must fail promptly rather than wait forever.
	_, err = pw.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01})
	require.NoError(t, err)
	require.NoError(t, pw.Close())

	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(connectResp.Body)
		readDone <- err
	}()
	select {
	case <-readDone:
	case <-time.After(10 * time.Second):
		t.Fatal("MITM connection was not torn down after the client half-closed mid-handshake")
	}
}

// TestHTTP2ConnectUpstreamDialFailureReturnsBadGateway verifies the failure
// path still responds once, before the stream started carrying tunnel data.
func TestHTTP2ConnectUpstreamDialFailureReturnsBadGateway(t *testing.T) {
	clearProxyEnv(t)

	proxy := goproxy.NewProxyHttpServer()
	proxy.ConnectDial = func(_, _ string) (net.Conn, error) {
		return nil, errors.New("dial refused")
	}

	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://unreachable.example:443", http.NoBody)
	require.NoError(t, err)

	connectResp, err := h2client.RoundTrip(connectReq)
	require.NoError(t, err)
	defer func() { _ = connectResp.Body.Close() }()
	assert.Equal(t, http.StatusBadGateway, connectResp.StatusCode)

	body, err := io.ReadAll(connectResp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "dial refused")
}

// TestHTTP2ConnectClientCancelAbortsDial verifies that cancelling the CONNECT
// stream while the upstream dial is still in flight abandons the dial: the
// handler must not keep waiting, and a connection that completes afterwards
// must be closed instead of leaked.
func TestHTTP2ConnectClientCancelAbortsDial(t *testing.T) {
	clearProxyEnv(t)

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	proxySide, peerSide := net.Pipe()
	t.Cleanup(func() { _ = peerSide.Close() })

	proxy := goproxy.NewProxyHttpServer()
	// ConnectDial does not take a context: cancellation has to be handled by
	// the CONNECT path itself.
	proxy.ConnectDial = func(_, _ string) (net.Conn, error) {
		close(dialStarted)
		<-releaseDial
		return proxySide, nil
	}

	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()

	connectReq, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://unreachable.example:443", pr)
	require.NoError(t, err)

	roundTripErr := make(chan error, 1)
	go func() {
		resp, err := h2client.RoundTrip(connectReq)
		if resp != nil {
			_ = resp.Body.Close()
		}
		roundTripErr <- err
	}()

	select {
	case <-dialStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream dial was never started")
	}

	cancel()

	select {
	case err := <-roundTripErr:
		require.Error(t, err, "cancelled CONNECT must not yield a response")
	case <-time.After(5 * time.Second):
		t.Fatal("client cancellation did not abort the in-flight CONNECT")
	}

	// Let the dial complete: the connection is now stale and must be closed.
	close(releaseDial)

	require.NoError(t, peerSide.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = peerSide.Read(make([]byte, 1))
	require.Error(t, err, "connection completed after cancellation was leaked")
}

// TestHTTP2ConnectClientCancelStopsCopies verifies that a client cancelling a
// live CONNECT stream (RST_STREAM via resp.Body.Close) tears down the upstream
// connection instead of leaving both copy directions blocked.
func TestHTTP2ConnectClientCancelStopsCopies(t *testing.T) {
	clearProxyEnv(t)

	upstreamClosed := make(chan struct{})
	upstreamListener := listenTunnelTarget(t)

	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(io.Discard, conn)
		close(upstreamClosed)
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()

	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://"+upstreamListener.Addr().String(), pr)
	require.NoError(t, err)

	connectResp, err := h2client.RoundTrip(connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)

	// Prove the tunnel is live before cancelling.
	_, err = pw.Write([]byte("ping"))
	require.NoError(t, err)

	// Cancelling an established CONNECT stream is resp.Body.Close: the
	// http2 transport resets the stream, which cancels the server handler.
	require.NoError(t, connectResp.Body.Close())

	select {
	case <-upstreamClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the CONNECT stream left the upstream connection open")
	}
}

// TestHTTP2ConnectHalfCloseKeepsResponseDirection verifies that a client EOF is
// propagated to the upstream as a half-close: the upstream may then finish its
// response, which must reach the client before the stream ends.
func TestHTTP2ConnectHalfCloseKeepsResponseDirection(t *testing.T) {
	clearProxyEnv(t)

	const reply = "reply-after-client-eof"

	upstreamSawEOF := make(chan struct{})
	upstreamListener := listenTunnelTarget(t)

	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Read until the proxy forwards the client's half-close.
		_, _ = io.Copy(io.Discard, conn)
		close(upstreamSawEOF)
		_, _ = io.WriteString(conn, reply)
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	pr, pw := io.Pipe()
	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://"+upstreamListener.Addr().String(), pr)
	require.NoError(t, err)

	connectResp, err := h2client.RoundTrip(connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)
	defer func() { _ = connectResp.Body.Close() }()

	_, err = pw.Write([]byte("request-before-eof"))
	require.NoError(t, err)
	// Half-close the client request side (HTTP/2 END_STREAM).
	require.NoError(t, pw.Close())

	select {
	case <-upstreamSawEOF:
	case <-time.After(5 * time.Second):
		t.Fatal("client EOF was not propagated to the upstream as a half-close")
	}

	body, err := io.ReadAll(connectResp.Body)
	require.NoError(t, err)
	assert.Equal(t, reply, string(body),
		"upstream response after the client half-close must still reach the client")
}

// TestHTTP2ConnectUpstreamCloseEndsClientStream verifies that when the upstream
// closes, the client's tunnel stream ends instead of waiting for the client to
// half-close first.
func TestHTTP2ConnectUpstreamCloseEndsClientStream(t *testing.T) {
	clearProxyEnv(t)

	const reply = "upstream-done"

	upstreamListener := listenTunnelTarget(t)

	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, reply)
		_ = conn.Close()
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://"+upstreamListener.Addr().String(), pr)
	require.NoError(t, err)

	connectResp, err := h2client.RoundTrip(connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)
	defer func() { _ = connectResp.Body.Close() }()

	type readResult struct {
		body []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		body, err := io.ReadAll(connectResp.Body)
		readDone <- readResult{body: body, err: err}
	}()

	select {
	case res := <-readDone:
		require.NoError(t, res.err)
		assert.Equal(t, reply, string(res.body))
	case <-time.After(5 * time.Second):
		t.Fatal("upstream close did not end the client stream")
	}
}

// TestHTTP2ConnectSimultaneousClose verifies that both sides closing at once
// does not leave the handler (and therefore the HTTP/2 stream) waiting.
func TestHTTP2ConnectSimultaneousClose(t *testing.T) {
	clearProxyEnv(t)

	upstreamClosed := make(chan struct{})
	upstreamListener := listenTunnelTarget(t)

	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		close(upstreamClosed)
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	pr, pw := io.Pipe()
	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://"+upstreamListener.Addr().String(), pr)
	require.NoError(t, err)

	connectResp, err := h2client.RoundTrip(connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)
	defer func() { _ = connectResp.Body.Close() }()

	_, err = pw.Write([]byte("payload"))
	require.NoError(t, err)

	// Close both directions concurrently.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = pw.Close()
	}()
	go func() {
		defer wg.Done()
		select {
		case <-upstreamClosed:
		case <-time.After(5 * time.Second):
			t.Error("upstream connection was not closed")
		}
	}()
	wg.Wait()

	// The client stream must terminate rather than hang on a half-closed
	// tunnel where one direction is already gone.
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(connectResp.Body)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("client stream is still waiting after both sides closed")
	}
}

// TestHTTP2ConnectCopyErrorObservable verifies that a tunnel copy failure is
// reported through ConnectionErrHandler without injecting a second HTTP
// response into the already-started HTTP/2 stream.
func TestHTTP2ConnectCopyErrorObservable(t *testing.T) {
	clearProxyEnv(t)

	proxy := goproxy.NewProxyHttpServer()
	proxy.ConnectDial = func(_, _ string) (net.Conn, error) {
		return &failingReadConn{closed: make(chan struct{})}, nil
	}
	var (
		mu            sync.Mutex
		handlerErrors []error
		handlerWriter io.Writer
	)
	proxy.ConnectionErrHandler = func(w io.Writer, _ *goproxy.ProxyCtx, err error) {
		mu.Lock()
		defer mu.Unlock()
		handlerErrors = append(handlerErrors, err)
		handlerWriter = w
	}

	proxySrv := startH2ProxyServer(t, proxy)
	h2client := dialH2Proxy(t, proxySrv.URL)

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://unreachable.example:443", pr)
	require.NoError(t, err)

	connectResp, err := h2client.RoundTrip(connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode, "the tunnel headers were already sent")
	defer func() { _ = connectResp.Body.Close() }()

	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(connectResp.Body)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel stream did not end after the copy error")
	}

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(handlerErrors) > 0
	}, 5*time.Second, 10*time.Millisecond, "tunnel copy error was not reported to ConnectionErrHandler")

	mu.Lock()
	defer mu.Unlock()
	require.ErrorIs(t, handlerErrors[0], errFailingUpstream)
	assert.Equal(t, io.Discard, handlerWriter,
		"an HTTP/2 tunnel must not receive a second HTTP response after data started")
}

// failingReadConn yields a copy error as soon as the proxy reads from the
// upstream side, modelling a connection that dies mid-transfer.
type failingReadConn struct {
	closed chan struct{}
}

var errFailingUpstream = errors.New("upstream read failed")

func (c *failingReadConn) Read([]byte) (int, error) { return 0, errFailingUpstream }
func (c *failingReadConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *failingReadConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *failingReadConn) LocalAddr() net.Addr              { return h2testAddr("upstream") }
func (c *failingReadConn) RemoteAddr() net.Addr             { return h2testAddr("upstream") }
func (c *failingReadConn) SetDeadline(time.Time) error      { return nil }
func (c *failingReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *failingReadConn) SetWriteDeadline(time.Time) error { return nil }

// openH1Tunnel dials the proxy over plain TCP and opens a CONNECT tunnel to
// target, returning the established connection and its buffered reader.
func openH1Tunnel(t *testing.T, proxySrv *httptest.Server, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxyURL.Host)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, "https://"+target, nil)
	require.NoError(t, err)
	require.NoError(t, connectReq.Write(conn))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return conn, br
}

// TestHTTP1ConnectHalfCloseKeepsResponseDirection verifies the existing
// HTTP/1.1 tunnel path still propagates a client half-close: the upstream can
// then answer after the client's write side ended.
func TestHTTP1ConnectHalfCloseKeepsResponseDirection(t *testing.T) {
	clearProxyEnv(t)

	const reply = "h1-reply-after-half-close"

	upstreamSawEOF := make(chan struct{})
	upstreamListener := listenTunnelTarget(t)
	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(io.Discard, conn)
		close(upstreamSawEOF)
		_, _ = io.WriteString(conn, reply)
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	t.Cleanup(proxySrv.Close)

	conn, br := openH1Tunnel(t, proxySrv, upstreamListener.Addr().String())

	_, err := conn.Write([]byte("h1-request"))
	require.NoError(t, err)
	tcpConn, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	require.NoError(t, tcpConn.CloseWrite())

	select {
	case <-upstreamSawEOF:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/1.1 client half-close was not propagated to the upstream")
	}

	body, err := io.ReadAll(br)
	require.NoError(t, err)
	assert.Equal(t, reply, string(body))
}

// TestHTTP1ConnectUpstreamCloseEndsTunnel verifies that an upstream close ends
// the HTTP/1.1 tunnel promptly instead of waiting for the client.
func TestHTTP1ConnectUpstreamCloseEndsTunnel(t *testing.T) {
	clearProxyEnv(t)

	const reply = "h1-upstream-done"

	upstreamListener := listenTunnelTarget(t)
	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, reply)
		_ = conn.Close()
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	t.Cleanup(proxySrv.Close)

	_, br := openH1Tunnel(t, proxySrv, upstreamListener.Addr().String())

	type readResult struct {
		body []byte
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		body, err := io.ReadAll(br)
		done <- readResult{body: body, err: err}
	}()

	select {
	case res := <-done:
		require.NoError(t, res.err)
		assert.Equal(t, reply, string(res.body))
	case <-time.After(5 * time.Second):
		t.Fatal("upstream close did not end the HTTP/1.1 tunnel")
	}
}
