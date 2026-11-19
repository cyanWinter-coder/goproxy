package goproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/elazarl/goproxy/internal/http1parser"
	"github.com/elazarl/goproxy/internal/signer"
	"golang.org/x/net/http2"
)

var responseHeadTerminator = []byte("\r\n\r\n")

// onceCloseBody shares cleanup between Response.Write and the deferred close.
type onceCloseBody struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (b *onceCloseBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close() })
	return b.err
}

type continueOnRead struct {
	io.ReadCloser
	client   io.Writer
	mu       sync.Mutex
	canWrite bool
	sent     bool
}

func (r *continueOnRead) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.canWrite && !r.sent {
		r.sent = true
		if _, err := io.WriteString(r.client, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			r.mu.Unlock()
			return 0, err
		}
	}
	r.mu.Unlock()
	return r.ReadCloser.Read(p)
}

func (r *continueOnRead) stop() {
	r.mu.Lock()
	r.canWrite = false
	r.mu.Unlock()
}

func (r *continueOnRead) sentContinue() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sent
}

// Close does not drain a body the client was never asked to send. The response
// path advertises "Connection: close" for that case instead, so the connection
// is torn down rather than blocking on bytes that will never arrive.
func (r *continueOnRead) Close() error {
	if !r.sentContinue() {
		return nil
	}
	return r.ReadCloser.Close()
}

type responseHeadWriter struct {
	writer    io.Writer
	head      bytes.Buffer
	wroteHead bool
}

func (w *responseHeadWriter) Write(p []byte) (int, error) {
	if w.wroteHead {
		return w.writer.Write(p)
	}

	buffered := w.head.Len()
	_, _ = w.head.Write(p)
	headEnd := bytes.Index(w.head.Bytes(), responseHeadTerminator)
	if headEnd < 0 {
		return len(p), nil
	}
	headEnd += len(responseHeadTerminator)

	data := w.head.Bytes()
	n, err := w.writer.Write(data[:headEnd])
	if err != nil || n != headEnd {
		current := max(0, min(len(p), n-buffered))
		if err == nil {
			err = io.ErrShortWrite
		}
		return current, err
	}

	w.wroteHead = true
	body := data[headEnd:]
	w.head.Reset()
	if len(body) == 0 {
		return len(p), nil
	}

	n, err = w.writer.Write(body)
	return headEnd - buffered + n, err
}

// ConnectActionLiteral defines the action the proxy should take
// when it receives an HTTP CONNECT request from a client.
type ConnectActionLiteral int

const (
	// ConnectAccept instructs the proxy to accept the CONNECT request
	// and establish a transparent TCP tunnel to the destination host.
	// The proxy will forward raw bytes in both directions without inspecting them.
	ConnectAccept ConnectActionLiteral = iota

	// ConnectReject instructs the proxy to reject the CONNECT request
	// and immediately close the connection with the client.
	ConnectReject

	// ConnectMitm instructs the proxy to perform a Man-in-the-Middle (MITM)
	// attack on the CONNECT tunnel. The proxy generates a dynamic TLS certificate
	// for the target host, signed by its CA (see GoproxyCa), and establishes
	// separate TLS connections with both the client and the destination server.
	// All request and response handlers remain active on this intercepted connection.
	ConnectMitm

	// ConnectHijack instructs the proxy to hand the raw net.Conn to the function
	// defined in ConnectAction.Hijack, giving full low-level control of the
	// connection to the caller. The hijack function is responsible for sending
	// an HTTP response (e.g. "HTTP/1.1 200 OK") back to the client.
	ConnectHijack

	// ConnectHTTPMitm is deprecated: use ConnectMitm instead.
	ConnectHTTPMitm

	// ConnectProxyAuthHijack instructs the proxy to hijack the CONNECT connection
	// after a proxy authentication failure, allowing the handler to send
	// a custom authentication challenge or error response to the client.
	ConnectProxyAuthHijack
)

var (
	// OkConnect is a ready-to-use ConnectAction that accepts the CONNECT request
	// and creates a transparent TCP tunnel to the destination host, using the built-in CA.
	OkConnect = &ConnectAction{Action: ConnectAccept, TLSConfig: TLSConfigFromCA(&GoproxyCa)}

	// MitmConnect is a ready-to-use ConnectAction that performs MITM interception,
	// signing dynamic TLS certificates with the built-in CA (GoproxyCa).
	// Use proxy.CertStore to cache generated certificates and save CPU in production.
	MitmConnect = &ConnectAction{Action: ConnectMitm, TLSConfig: TLSConfigFromCA(&GoproxyCa)}

	// HTTPMitmConnect is deprecated: use MitmConnect instead.
	HTTPMitmConnect = &ConnectAction{Action: ConnectHTTPMitm, TLSConfig: TLSConfigFromCA(&GoproxyCa)}

	// RejectConnect is a ready-to-use ConnectAction that rejects the CONNECT request
	// and closes the connection with the client.
	RejectConnect = &ConnectAction{Action: ConnectReject, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
)

var _errorRespMaxLength int64 = 500

const _tlsRecordTypeHandshake = byte(22)

type readBufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *readBufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// ConnectAction enables the caller to override the standard connect flow.
// When Action is ConnectHijack, it is up to the implementer to send the
// HTTP 200, or any other valid http response back to the client from within the
// Hijack func.
type ConnectAction struct {
	Action    ConnectActionLiteral
	Hijack    func(req *http.Request, client net.Conn, ctx *ProxyCtx)
	TLSConfig func(host string, ctx *ProxyCtx) (*tls.Config, error)
}

func stripPort(s string) string {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return host
}

func (proxy *ProxyHttpServer) dial(ctx *ProxyCtx, network, addr string) (c net.Conn, err error) {
	if ctx.Dialer != nil {
		return ctx.Dialer(ctx.Req.Context(), network, addr)
	}

	if proxy.Tr != nil && proxy.Tr.DialContext != nil {
		return proxy.Tr.DialContext(ctx.Req.Context(), network, addr)
	}

	// if the user didn't specify any dialer, we just use the default one,
	// provided by net package
	var d net.Dialer
	return d.DialContext(ctx.Req.Context(), network, addr)
}

func (proxy *ProxyHttpServer) connectDial(ctx *ProxyCtx, network, addr string) (c net.Conn, err error) {
	if proxy.ConnectDialWithReq == nil && proxy.ConnectDial == nil {
		return proxy.dial(ctx, network, addr)
	}

	if proxy.ConnectDialWithReq != nil {
		return proxy.ConnectDialWithReq(ctx.Req, network, addr)
	}

	return proxy.ConnectDial(network, addr)
}

// closeWriter is the single-direction half-close capability. Both TCP
// connections and the HTTP/2 stream wrapper implement it; wrappers that cannot
// half-close simply do not, and the relay falls back to a full close.
type closeWriter interface {
	CloseWrite() error
}

// halfClosable marks a connection that supports shutting down either half
// independently. TLS connections expose CloseWrite (a close_notify alert) but
// only deliver EOF when fully closed, so both methods are required for the
// relay to treat a half-close as visible to the peer.
type halfClosable interface {
	CloseWrite() error
	CloseRead() error
}

var _ halfClosable = (*net.TCPConn)(nil)

// canHalfClose reports whether a tunnel endpoint's peer will observe EOF when
// only the write side is shut down.
func canHalfClose(c net.Conn) bool {
	_, ok := c.(halfClosable)
	return ok
}

// connectResponseLine builds a CONNECT tunnel status line that echoes the
// requesting client's HTTP version. These replies were previously hardcoded as
// HTTP/1.0, so an HTTP/1.1 CONNECT received an HTTP/1.0 status line on an
// otherwise HTTP/1.1 connection (issue #802). Falls back to HTTP/1.1 when the
// request version is unset.
func connectResponseLine(r *http.Request, code int, text string) string {
	major, minor := r.ProtoMajor, r.ProtoMinor
	if major == 0 {
		major, minor = 1, 1
	}
	return fmt.Sprintf("HTTP/%d.%d %d %s\r\n\r\n", major, minor, code, text)
}

// requestCancelled reports whether the client that issued the CONNECT request
// has gone away (HTTP/2 stream reset, request context cancellation).
func requestCancelled(ctx *ProxyCtx) bool {
	return ctx.Req != nil && ctx.Req.Context().Err() != nil
}

// dialConnectTunnel dials the CONNECT target. Unlike dial, it can be abandoned
// when the client cancels while a custom dialer is still running: dialers
// configured through ConnectDial/ConnectDialWithReq do not take a context, so
// the dial runs in the background and a connection that completes after the
// cancellation is closed instead of leaked.
func (proxy *ProxyHttpServer) dialConnectTunnel(ctx *ProxyCtx, network, addr string) (net.Conn, error) {
	reqCtx := context.Background()
	if ctx.Req != nil {
		reqCtx = ctx.Req.Context()
	}
	if err := reqCtx.Err(); err != nil {
		return nil, err
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	results := make(chan dialResult, 1)
	go func() {
		c, err := proxy.connectDial(ctx, network, addr)
		results <- dialResult{conn: c, err: err}
	}()

	select {
	case res := <-results:
		return res.conn, res.err
	case <-reqCtx.Done():
		go func() {
			if res := <-results; res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, reqCtx.Err()
	}
}

// halfCloseWrite signals EOF to the peer of c without closing the read side.
// Endpoints that cannot half-close (an opaque net.Conn wrapper) are left
// untouched so the opposite direction can keep relaying.
func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func halfCloseRead(c net.Conn) {
	if cr, ok := c.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}
}

// abortTunnelConn tears a tunnel endpoint down immediately, unblocking any
// copy parked in Read or Write. HTTP/2 streams implement Abort to also reset
// the stream; plain TCP connections are fully closed.
func abortTunnelConn(c net.Conn) {
	if a, ok := c.(interface{ Abort() }); ok {
		a.Abort()
		return
	}
	_ = c.Close()
}

// tunnelCopyError reports an error from one of the tunnel copy directions.
// The error is always observable through ctx.Error and the proxy log.
// ConnectionErrHandler is invoked too (it may write a diagnostic to a
// hijacked HTTP/1.1 connection), but an HTTP/2 CONNECT stream has already
// started carrying tunnel data and must not receive a second HTTP response,
// so its writer is replaced with io.Discard.
func (proxy *ProxyHttpServer) tunnelCopyError(ctx *ProxyCtx, client net.Conn, err error) {
	ctx.Error = err
	ctx.Warnf("Error copying in CONNECT tunnel: %s", err)
	if proxy.ConnectionErrHandler == nil {
		return
	}
	var w io.Writer = client
	if _, isH2 := client.(*h2StreamConn); isH2 {
		w = io.Discard
	}
	proxy.ConnectionErrHandler(w, ctx, err)
}

// tunnelCopyClosedError reports whether err is the expected fallout of
// tearing a tunnel down (closed sockets, cancelled contexts, reset HTTP/2
// streams, the past write deadline used to unblock a flow-control-stalled
// HTTP/2 write) rather than a genuine copy failure worth surfacing.
func tunnelCopyClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var streamErr http2.StreamError
	return errors.As(err, &streamErr)
}

// relayTunnel copies bytes in both directions until both directions are done,
// or until one fails or cancel fires. clientSrc reads from client and may
// replay bytes the HTTP parser already buffered (see bufferedClientReader).
//
// Half-close semantics:
//   - A direction that reaches EOF half-closes the peer and the opposite
//     direction keeps running, so a peer that shuts down its write side still
//     receives the rest of the response.
//   - An error, or a cancellation, aborts both sides so neither a copy
//     goroutine nor the caller is left waiting on a dead tunnel.
//
// HTTP/2 cannot half-close a response body early: the END_STREAM flag is only
// sent when ServeHTTP returns. The H2 caller therefore blocks in relayTunnel,
// and relayTunnel finishes as soon as the upstream-to-client direction is done
// so the response can be ended.
func (proxy *ProxyHttpServer) relayTunnel(
	ctx *ProxyCtx,
	client net.Conn,
	clientSrc io.Reader,
	upstream net.Conn,
	cancel <-chan struct{},
) {
	h2, isH2 := client.(*h2StreamConn)

	var (
		abortOnce sync.Once
		aborted   = make(chan struct{})
		finished  = make(chan struct{})
		stopping  atomic.Bool
	)
	finish := func() {
		select {
		case <-finished:
		default:
			close(finished)
		}
	}
	isAborted := func() bool {
		select {
		case <-aborted:
			return true
		default:
			return false
		}
	}
	abort := func(err error) {
		abortOnce.Do(func() {
			// Report before tearing down so a handler that can still write
			// (HTTP/1.1) sees a usable connection.
			if err != nil {
				proxy.tunnelCopyError(ctx, client, err)
			}
			// Waking the copies unblocks Read/Write; isAborted then suppresses
			// their follow-up errors so only the root cause is reported.
			abortTunnelConn(client)
			abortTunnelConn(upstream)
			close(aborted)
		})
	}

	// watcherDone makes finish wait for the cancellation watcher: it may be
	// running abort, which touches the HTTP/2 ResponseWriter, and that must
	// not outlive the ServeHTTP return.
	var watcherDone chan struct{}
	if cancel != nil {
		watcherDone = make(chan struct{})
		go func() {
			defer close(watcherDone)
			select {
			case <-cancel:
				select {
				case <-finished:
				default:
					// The client is gone (e.g. an HTTP/2 RST_STREAM); there is
					// nobody left to report to, only the copies to stop.
					abort(nil)
				}
			case <-finished:
			}
		}()
	}

	// Half-closing only helps if the peer can observe it: a TCP connection
	// does, a TLS one only reports EOF once fully closed, and an opaque
	// net.Conn wrapper may not implement it at all. A direction whose peer
	// cannot see EOF must tear the tunnel down instead of waiting for it.
	clientCanHalfClose := canHalfClose(client)
	upstreamCanHalfClose := canHalfClose(upstream)

	copyDir := func(dst net.Conn, src net.Conn, srcReader io.Reader, canHalfClose bool) error {
		_, err := io.Copy(dst, srcReader)
		if err != nil {
			if !stopping.Load() && !isAborted() && !tunnelCopyClosedError(err) {
				abort(fmt.Errorf("copy %s -> %s: %w", src.RemoteAddr(), dst.RemoteAddr(), err))
			}
			return err
		}
		if !canHalfClose {
			// The opposite peer can never observe our EOF, so waiting for it
			// could block forever. Tear the whole tunnel down instead.
			abort(nil)
			return nil
		}
		// Normal EOF: tell the peer no more data is coming, but keep the
		// opposite direction alive so it can finish its own transfer.
		halfCloseWrite(dst)
		halfCloseRead(src)
		return nil
	}

	upToClient := make(chan error, 1)
	clientToUp := make(chan error, 1)

	go func() {
		// An HTTP/2 response cannot be half-closed; returning from the
		// handler emits END_STREAM, so writes are disabled here instead and
		// the handler return below finishes the response.
		upToClient <- copyDir(client, upstream, upstream, isH2 || clientCanHalfClose)
	}()
	go func() {
		clientToUp <- copyDir(upstream, client, clientSrc, upstreamCanHalfClose)
	}()

	// Wait for the response direction first: it determines when a handler
	// must return. The request direction is interrupted below.
	<-upToClient
	if isH2 {
		// The response side is done. There is no way to keep serving the
		// request direction after ServeHTTP returns, so stop it now: closing
		// the request body and the upstream connection unblocks both a pending
		// Read of the H2 stream and a pending Write to the upstream server.
		// This does not reset the stream, so a normally finished response
		// still ends with a clean END_STREAM. The resulting read error is
		// expected and must not be reported as a tunnel failure.
		stopping.Store(true)
		_ = h2.Close()
		_ = upstream.Close()
	}
	<-clientToUp

	finish()
	if watcherDone != nil {
		// Do not let the watcher touch the HTTP/2 stream after ServeHTTP
		// returns; it exits promptly once finished is closed.
		<-watcherDone
	}
	// Fully release both endpoints: half-closes only shut down one direction
	// and would keep the descriptors, and any blocked reader, alive.
	_ = client.Close()
	_ = upstream.Close()
}

func (proxy *ProxyHttpServer) handleHttps(w http.ResponseWriter, r *http.Request) {
	ctx := &ProxyCtx{Req: r, Session: atomic.AddInt64(&proxy.sess, 1), Proxy: proxy, certStore: proxy.CertStore}

	// Run CONNECT handlers first, before any connection hijacking
	ctx.Logf("Running %d CONNECT handlers", len(proxy.httpsHandlers))
	todo, host := OkConnect, r.URL.Host
	for i, h := range proxy.httpsHandlers {
		newtodo, newhost := h.HandleConnect(host, ctx)
		// If found a result, break the loop immediately
		if newtodo != nil {
			todo, host = newtodo, newhost
			ctx.Logf("on %dth handler: %v %s", i, todo, host)
			break
		}
	}

	hij, canHijack := w.(http.Hijacker)

	// Handle actions that do NOT require a bidirectional tunnel
	switch todo.Action {
	case ConnectReject:
		if ctx.Resp != nil {
			if canHijack {
				proxyClient, _, e := hij.Hijack()
				if e != nil {
					ctx.Warnf("Cannot hijack connection: %v", e)
					return
				}
				defer proxyClient.Close()
				if err := ctx.Resp.Write(proxyClient); err != nil {
					ctx.Warnf("Cannot write response that reject http CONNECT: %v", err)
				}
			} else {
				// HTTP/2: write the rejection as a proper HTTP response.
				copyHeaders(w.Header(), ctx.Resp.Header, proxy.KeepDestinationHeaders)
				w.WriteHeader(ctx.Resp.StatusCode)
				if ctx.Resp.Body != nil {
					_, _ = io.Copy(w, ctx.Resp.Body)
					_ = ctx.Resp.Body.Close()
				}
			}
		} else if canHijack {
			proxyClient, _, _ := hij.Hijack()
			_ = proxyClient.Close()
		} else {
			http.Error(w, "Connection rejected", http.StatusForbidden)
		}
		return

	case ConnectProxyAuthHijack:
		if !canHijack {
			// Extended-CONNECT over HTTP/2 does not support 407 hijack flow.
			ctx.Warnf("ConnectProxyAuthHijack is not supported when the proxy is served over HTTP/2")
			http.Error(w, "Proxy auth hijack not supported in HTTP/2 mode", http.StatusInternalServerError)
			return
		}
		proxyClient, _, e := hij.Hijack()
		if e != nil {
			ctx.Warnf("Cannot hijack connection: %v", e)
			return
		}
		_, _ = proxyClient.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n"))
		todo.Hijack(r, proxyClient, ctx)
		return
	}

	// All remaining actions need a bidirectional tunnel (proxyClient)
	//
	// In HTTP/1.1 mode we hijack the connection.
	// In HTTP/2 mode (r.ProtoMajor == 2), we take the H2 path as explained in RFC 8441 extended-CONNECT.
	var proxyClient net.Conn
	var hijackedReader *bufio.Reader
	isH2Tunnel := false

	if canHijack {
		var rw *bufio.ReadWriter
		var e error
		proxyClient, rw, e = hij.Hijack()
		if e != nil {
			ctx.Warnf("Cannot hijack connection: %v", e)
			return
		}
		// rw.Reader still holds any bytes the HTTP server buffered while parsing the
		// CONNECT request (e.g. a TLS ClientHello sent in the same write).
		hijackedReader = rw.Reader
	} else if r.ProtoMajor == 2 {
		// The incoming CONNECT arrived over HTTP/2 (no hijacking available).
		// Use h2StreamConn so reads/writes go directly against the H2 stream.
		isH2Tunnel = true
		// Wrap the H2 stream directly as a net.Conn — no intermediate pipe,
		// no goroutines, no unnecessary copies.
		proxyClient = newH2StreamConn(w, r)
	} else {
		// Hijacking is not supported and the request is not HTTP/2.
		// This can happen if goproxy is wrapped by middleware that strips the
		// Hijacker interface. There is no safe way to tunnel here.
		ctx.Warnf("CONNECT: server does not support hijacking and request is not HTTP/2 (proto=%s)", r.Proto)
		http.Error(w, "Proxy: cannot establish tunnel (no hijacking support)", http.StatusInternalServerError)
		return
	}

	switch todo.Action {
	case ConnectAccept:
		if !hasPort(host) {
			host += ":80"
		}
		targetSiteCon, err := proxy.dialConnectTunnel(ctx, "tcp", host)
		if err != nil {
			ctx.Warnf("Error dialing to %s: %s", host, err.Error())
			if requestCancelled(ctx) {
				// The client cancelled while we were dialing: abort the tunnel
				// instead of writing a response nobody is left to read.
				abortTunnelConn(proxyClient)
				return
			}
			httpError(proxyClient, ctx, err)
			return
		}
		ctx.Logf("Accepting CONNECT to %s", host)
		// In HTTP/1.1 mode the client is waiting for the 200 confirmation;
		// In HTTP/2 mode we send it now, after we know the dial succeeded.
		if isH2Tunnel {
			if requestCancelled(ctx) {
				// Client left during the dial: don't start a stream it will
				// never read, and release the upstream connection.
				_ = targetSiteCon.Close()
				abortTunnelConn(proxyClient)
				return
			}
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}

			// The H2 handler must block until the tunnel closes: the HTTP/2
			// server keeps the stream alive only while ServeHTTP is running.
			// Cancelling the request (stream reset) aborts both copies below.
			proxy.relayTunnel(ctx, proxyClient, proxyClient, targetSiteCon, r.Context().Done())
		} else {
			if _, err := proxyClient.Write([]byte(connectResponseLine(r, http.StatusOK, "Connection established"))); err != nil {
				ctx.Warnf("Error confirming CONNECT to client: %s", err)
				_ = targetSiteCon.Close()
				_ = proxyClient.Close()
				return
			}

			// The client may have sent its first bytes (e.g. a TLS ClientHello) in the
			// same write as the CONNECT request, so those bytes are still in the request
			// parser's buffer. Replay them before the raw connection instead of leaving
			// them stranded.
			clientSrc := bufferedClientReader(hijackedReader, proxyClient)

			// The tunnel outlives this handler: the connection is hijacked, so
			// ServeHTTP can (and should) return to unblock the HTTP/1.x server.
			go proxy.relayTunnel(ctx, proxyClient, clientSrc, targetSiteCon, nil)
		}

	case ConnectHijack:
		todo.Hijack(r, proxyClient, ctx)

	case ConnectHTTPMitm, ConnectMitm:
		if isH2Tunnel {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		} else {
			_, _ = proxyClient.Write([]byte(connectResponseLine(r, http.StatusOK, "OK")))
		}
		ctx.Logf("Received CONNECT request, mitm proxying it")
		// For HTTP/1.x (after Hijack), the MITM loop runs in a goroutine so the HTTP/1.x
		// server is not blocked by the (potentially very long) tunnel and can shut down cleanly.
		// For HTTP/2 (isH2Tunnel), the handler must block, the HTTP/2 server keeps the H2
		// stream alive only while ServeHTTP is running; returning early closes the stream.
		mitmWork := func() {
			// For an HTTP/2 CONNECT the session must be cancelled when the
			// client abandons the stream, so its inner requests inherit that
			// context. For hijacked HTTP/1.1 the request context dies with
			// ServeHTTP, so background is the only valid choice.
			baseCtx := proxy.mitmBaseContext(isH2Tunnel, r)

			// Check if this is an HTTP or an HTTPS MITM request. The CONNECT
			// request was parsed through the hijacked reader, so any bytes the
			// client sent in the same write (e.g. a TLS ClientHello) are buffered
			// there and must be replayed before the raw connection.
			readBuffer := bufio.NewReader(bufferedClientReader(hijackedReader, proxyClient))
			peek, _ := readBuffer.Peek(1)
			isTLS := len(peek) > 0 && peek[0] == _tlsRecordTypeHandshake

			var client net.Conn = &readBufferedConn{Conn: proxyClient, r: readBuffer}
			defer func() {
				_ = client.Close()
			}()

			if isTLS {
				tlsConfig := defaultTLSConfig
				if todo.TLSConfig != nil {
					var err error
					tlsConfig, err = todo.TLSConfig(host, ctx)
					if err != nil {
						httpError(proxyClient, ctx, err)
						return
					}
				}
				tlsConfig = tlsConfig.Clone()

				if proxy.AllowHTTP2 {
					if !slices.Contains(tlsConfig.NextProtos, "h2") {
						tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
					}
				}

				if !slices.Contains(tlsConfig.NextProtos, "http/1.1") {
					tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
				}

				// Create a TLS connection over the TCP connection
				rawClientTls := tls.Server(client, tlsConfig)
				client = rawClientTls
				if err := rawClientTls.HandshakeContext(baseCtx); err != nil {
					ctx.Warnf("Cannot handshake client %v %v", r.Host, err)
					return
				}
				if proxy.AllowHTTP2 && rawClientTls.ConnectionState().NegotiatedProtocol == "h2" {
					ctx.Logf("ALPN negotiated h2, starting http2.ServeConn")
					proxy.serveH2Mitm(baseCtx, client, host, ctx)
					return
				}
			} else if proxy.AllowHTTP2 {
				// Handle cleartext HTTP/2 (h2c) by looking for the client preface.
				preface, err := readBuffer.Peek(len(http2.ClientPreface))
				if err == nil && string(preface) == http2.ClientPreface {
					proxy.serveH2Mitm(baseCtx, client, host, ctx)
					return
				}
			}

			scheme := "http"
			if isTLS {
				scheme = "https"
			}

			clientReader := http1parser.NewRequestReader(proxy.PreventCanonicalization, client)
			for !clientReader.IsEOF() {
				req, err := clientReader.ReadRequest()
				ctx := &ProxyCtx{
					Req:          req,
					Session:      atomic.AddInt64(&proxy.sess, 1),
					Proxy:        proxy,
					UserData:     ctx.UserData,
					RoundTripper: ctx.RoundTripper,
				}
				if err != nil && !errors.Is(err, io.EOF) {
					ctx.Warnf("Cannot read request from mitm'd client %v %v", r.Host, err)
				}
				if err != nil {
					return
				}
				// The parsed request has no context of its own. Bind it to the
				// tunnel's base context so an HTTP/2 client that abandons the
				// stream cancels this upstream request (and its body reads)
				// instead of letting it run to completion unobserved.
				if baseCtx != req.Context() {
					req = req.WithContext(baseCtx)
					ctx.Req = req
				}
				// The hijacked MITM connection has no net/http server to send
				// 100 Continue when a handler reads the request body.
				hasBody := req.Body != nil && req.Body != http.NoBody
				expectsContinue := headerContains(req.Header, "Expect", "100-continue")
				var continueBody *continueOnRead
				if req.ProtoAtLeast(1, 1) && hasBody && expectsContinue {
					continueBody = &continueOnRead{ReadCloser: req.Body, client: client, canWrite: true}
					req.Body = continueBody
				}

				// since we're converting the request, need to carry over the
				// original connecting IP as well
				req.RemoteAddr = r.RemoteAddr
				ctx.Logf("req %v", r.Host)

				if !req.URL.IsAbs() {
					// Origin-form request target (/path)
					// We prioritize req.Host (from the internal request), over r.Host (from the CONNECT request).
					hostToUse := req.Host
					if hostToUse == "" {
						hostToUse = r.Host // Fallback, if the internal Host header is missing
					}

					urlToParse := scheme + "://" + hostToUse + req.URL.String()
					parsedUrl, err := url.Parse(urlToParse)
					if err != nil {
						ctx.Warnf("Cannot parse URL %s: %v", urlToParse, err)
						return
					}
					req.URL = parsedUrl
				} else {
					// Absolute-form request target
					req.URL.Scheme = scheme
				}

				if continueLoop := func(req *http.Request) bool {
					// Since we handled the request parsing by our own, we manually
					// need to set a cancellable context when we finished the request
					// processing (same behaviour of the stdlib)
					requestContext, finishRequest := context.WithCancel(req.Context())
					req = req.WithContext(requestContext)
					defer finishRequest()

					// explicitly discard request body to avoid data races in certain RoundTripper implementations
					// see https://github.com/golang/go/issues/61596#issuecomment-1652345131
					defer req.Body.Close()

					// Bug fix which goproxy fails to provide request
					// information URL in the context when does HTTPS MITM
					ctx.Req = req

					req, resp := proxy.filterRequest(req, ctx)
					if resp == nil {
						if err != nil {
							if req.URL != nil {
								ctx.Warnf("Illegal URL %s", scheme+"://"+r.Host+req.URL.Path)
							} else {
								ctx.Warnf("Illegal URL %s", scheme+"://"+r.Host)
							}
							return false
						}
						if !proxy.KeepHeader {
							RemoveProxyHeaders(ctx, req)
						}
						resp, err = ctx.RoundTrip(req)
						if err != nil {
							ctx.Warnf("Cannot read response from mitm'd server %v", err)
							return false
						}
						ctx.Logf("resp %v", resp.Status)
					}
					origBody := resp.Body
					resp = proxy.filterResponse(resp, ctx)
					bodyModified := resp.Body != origBody
					if responseBodyAllowed(ctx.Req, resp) && resp.Body != http.NoBody && (bodyModified ||
						(resp.ContentLength <= 0 && resp.Header.Get("Content-Length") == "")) {
						// Return chunked encoded response when we don't know the length of the resp, if the body
						// has been modified by the response handler or if there is no content length in the response.
						// We include 0 in resp.ContentLength <= 0 because 0 is the field zero value and some user
						// might incorrectly leave it instead of setting it to -1 when the length is unknown (but we
						// also check that the Content-Length header is empty, so there is no issue with empty bodies).
						resp.ContentLength = -1
						resp.Header.Del("Content-Length")
						resp.TransferEncoding = []string{"chunked"}
					}

					// The MITM'd client speaks HTTP/1.1, but the upstream
					// response may have been received over HTTP/2. Normalize
					// the protocol version so resp.Write() produces a valid
					// HTTP/1.1 status line.
					resp.Proto = "HTTP/1.1"
					resp.ProtoMajor = 1
					resp.ProtoMinor = 1
					if continueBody != nil {
						continueBody.stop()
					}

					if isWebSocketHandshake(resp.Header) {
						defer resp.Body.Close()
						ctx.Logf("Response looks like websocket upgrade.")

						// According to resp.Body documentation:
						// As of Go 1.12, the Body will also implement io.Writer
						// on a successful "101 Switching Protocols" response,
						// as used by WebSockets and HTTP/2's "h2c" mode.
						wsConn, ok := resp.Body.(io.ReadWriter)
						if !ok {
							ctx.Warnf("Unable to use Websocket connection")
							return false
						}
						// Set Body to nil so resp.Write only writes the headers
						// and returns immediately without blocking on the body
						// (or else we wouldn't be able to proxy WebSocket data).
						resp.Body = nil
						// Buffer the head so it ships as one TLS record, not one tiny record per header (trips strict clients).
						bw := bufio.NewWriter(client)
						if err := resp.Write(bw); err != nil {
							ctx.Warnf("Cannot write response header from mitm'd client: %v", err)
							return false
						}
						if err := bw.Flush(); err != nil {
							ctx.Warnf("Cannot flush response header from mitm'd client: %v", err)
							return false
						}
						// The client may have sent its first WebSocket frame in the
						// same write as the upgrade request, so those bytes are still
						// in the request parser's buffer. Replay them before the raw
						// connection instead of leaving them stranded.
						proxy.proxyWebsocket(ctx, wsConn, bufferedClientReader(clientReader.Reader(), client), client)
						return false
					}

					// A "close" from either side ends the connection (RFC 9112 §9.6).
					// A response filter or a custom RoundTripper may set
					// "Connection: close" on the header without setting resp.Close,
					// so normalize it before writing the response. The same applies
					// when a final response is sent before the client was told to
					// send the request body: the body is unread, so the connection
					// cannot be reused (RFC 9110 §10.1.1).
					if ctx.Req.Close || headerContains(resp.Header, "Connection", "close") ||
						(continueBody != nil && !continueBody.sentContinue()) {
						resp.Close = true
					}

					resp.Body = &onceCloseBody{ReadCloser: resp.Body}
					defer resp.Body.Close()
					writer := &responseHeadWriter{writer: client}
					if err := resp.Write(writer); err != nil {
						ctx.Warnf("Cannot write response from mitm'd client: %v", err)
						return false
					}

					return !resp.Close
				}(req); !continueLoop {
					return
				}
			}
			ctx.Logf("Exiting on EOF")
		}
		if isH2Tunnel {
			mitmWork()
		} else {
			// The hijacked MITM loop outlives ServeHTTP, so it cannot use the
			// request context, which the HTTP/1 server cancels on return.
			go mitmWork()
		}
	}
}

func httpError(w io.Writer, ctx *ProxyCtx, err error) {
	if ctx.Proxy.ConnectionErrHandler != nil {
		ctx.Proxy.ConnectionErrHandler(w, ctx, err)
	} else {
		var rw http.ResponseWriter
		if r, ok := w.(http.ResponseWriter); ok {
			rw = r
		} else if h2, ok := w.(responseWriterProvider); ok {
			rw = h2.ResponseWriter()
		}

		if rw != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
		} else {
			errorMessage := err.Error()
			errStr := fmt.Sprintf(
				"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
				len(errorMessage),
				errorMessage,
			)
			if _, err := io.WriteString(w, errStr); err != nil {
				ctx.Warnf("Error responding to client: %s", err)
			}
		}
	}
	if c, ok := w.(io.Closer); ok {
		if err := c.Close(); err != nil {
			ctx.Warnf("Error closing client connection: %s", err)
		}
	}
}

func copyOrWarn(ctx *ProxyCtx, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	if err != nil && errors.Is(err, net.ErrClosed) {
		// Discard closed connection errors
		err = nil
	} else if err != nil {
		ctx.Warnf("Error copying to client: %s", err)
	}
	return err
}

func dialerFromEnv(proxy *ProxyHttpServer) func(network, addr string) (net.Conn, error) {
	httpsProxy := os.Getenv("HTTPS_PROXY")
	if httpsProxy == "" {
		httpsProxy = os.Getenv("https_proxy")
	}
	if httpsProxy == "" {
		return nil
	}
	return proxy.NewConnectDialToProxy(httpsProxy)
}

// NewConnectDialToProxy returns a dial function that establishes TCP connections
// through an upstream HTTP/HTTPS proxy using the CONNECT method.
// Use it to set proxy.ConnectDial when chaining two proxy servers.
// For authentication or other CONNECT request modifications, use NewConnectDialToProxyWithHandler instead.
func (proxy *ProxyHttpServer) NewConnectDialToProxy(httpsProxy string) func(network, addr string) (net.Conn, error) {
	return proxy.NewConnectDialToProxyWithHandler(httpsProxy, nil)
}

// NewConnectDialToProxyWithHandler returns a dial function that establishes TCP connections
// through an upstream HTTP/HTTPS proxy using the CONNECT method, calling connectReqHandler
// before sending the CONNECT request. Use connectReqHandler to add headers such as
// Proxy-Authorization to authenticate with the upstream proxy.
// If connectReqHandler is nil, the behavior is identical to NewConnectDialToProxy.
func (proxy *ProxyHttpServer) NewConnectDialToProxyWithHandler(
	httpsProxy string,
	connectReqHandler func(req *http.Request),
) func(network, addr string) (net.Conn, error) {
	u, err := url.Parse(httpsProxy)
	if err != nil {
		return nil
	}
	if u.Scheme == "" || u.Scheme == "http" || u.Scheme == "ws" {
		if !strings.ContainsRune(u.Host, ':') {
			u.Host += ":80"
		}
		return func(network, addr string) (net.Conn, error) {
			connectReq := &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			if connectReqHandler != nil {
				connectReqHandler(connectReq)
			}
			c, err := proxy.dial(&ProxyCtx{Req: &http.Request{}}, network, u.Host)
			if err != nil {
				return nil, err
			}
			_ = connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				resp, err := io.ReadAll(io.LimitReader(resp.Body, _errorRespMaxLength))
				if err != nil {
					return nil, err
				}
				_ = c.Close()
				return nil, errors.New("proxy refused connection" + string(resp))
			}
			return c, nil
		}
	}
	if u.Scheme == "https" || u.Scheme == "wss" {
		if !strings.ContainsRune(u.Host, ':') {
			u.Host += ":443"
		}
		return func(network, addr string) (net.Conn, error) {
			ctx := &ProxyCtx{Req: &http.Request{}}
			c, err := proxy.dial(ctx, network, u.Host)
			if err != nil {
				return nil, err
			}

			c, err = proxy.initializeTLSconnection(ctx, c, proxy.Tr.TLSClientConfig, u.Host)
			if err != nil {
				return nil, err
			}

			connectReq := &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			if connectReqHandler != nil {
				connectReqHandler(connectReq)
			}
			_ = connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(io.LimitReader(resp.Body, _errorRespMaxLength))
				if err != nil {
					return nil, err
				}
				_ = c.Close()
				return nil, errors.New("proxy refused connection" + string(body))
			}
			return c, nil
		}
	}
	return nil
}

// TLSConfigFromCA returns a TLSConfig function that generates dynamic TLS certificates
// for each target host, signed by the given CA certificate.
// The generated certificates are used during MITM interception (ConnectMitm).
// If a CertStorage is set on the ProxyCtx, certificates are cached and reused to save CPU.
func TLSConfigFromCA(ca *tls.Certificate) func(host string, ctx *ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *ProxyCtx) (*tls.Config, error) {
		var err error
		var cert *tls.Certificate

		hostname := stripPort(host)
		config := defaultTLSConfig.Clone()
		ctx.Logf("signing for %s", stripPort(host))

		genCert := func() (*tls.Certificate, error) {
			return signer.SignHost(*ca, []string{hostname})
		}
		if ctx.certStore != nil {
			cert, err = ctx.certStore.Fetch(hostname, genCert)
		} else {
			cert, err = genCert()
		}

		if err != nil {
			ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
			return nil, err
		}

		config.Certificates = append(config.Certificates, *cert)
		return config, nil
	}
}

func (proxy *ProxyHttpServer) initializeTLSconnection(
	ctx *ProxyCtx,
	targetConn net.Conn,
	tlsConfig *tls.Config,
	addr string,
) (net.Conn, error) {
	// Infer target ServerName, it's a copy of implementation inside tls.Dial()
	if tlsConfig.ServerName == "" {
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		hostname := addr[:colonPos]
		// Make a copy to avoid polluting argument or default.
		c := tlsConfig.Clone()
		c.ServerName = hostname
		tlsConfig = c
	}

	tlsConn := tls.Client(targetConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx.Req.Context()); err != nil {
		return nil, err
	}
	return tlsConn, nil
}
