package quic

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Resolver resolves a hostname to IPs via the independent resolver.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// GetCertificate mints per-SNI leaves (implemented by certgen.Issuer).
type GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// HTTP3Server terminates HTTP/3 on UDP443 and serves it with the shared handler,
// reusing the dynamic-leaf CA and policy (design doc: quic=true & http3=true).
type HTTP3Server struct {
	srv  *http3.Server
	conn *net.UDPConn
}

// ListenHTTP3 binds addr for UDP and prepares an HTTP/3 server using getCert for
// per-SNI leaves and the given HTTP handler.
func ListenHTTP3(addr string, getCert GetCertificate, handler http.Handler) (*HTTP3Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	srv := &http3.Server{
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: getCert,
			NextProtos:     []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{},
	}
	return &HTTP3Server{srv: srv, conn: conn}, nil
}

// Serve serves HTTP/3 until Close is called. Blocking.
func (h *HTTP3Server) Serve() error { return h.srv.Serve(h.conn) }

// LocalAddr returns the bound UDP address.
func (h *HTTP3Server) LocalAddr() net.Addr { return h.conn.LocalAddr() }

// Close drains the HTTP/3 server and closes the socket.
func (h *HTTP3Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = h.srv.Shutdown(ctx)
	return h.conn.Close()
}

// PassthroughRelay implements quic=true & http3=false: it does not terminate
// QUIC. For each new client flow it parses the Initial SNI, resolves the origin
// via the independent resolver, and relays datagrams both ways (design doc QUIC
// passthrough). Connection migration is not tracked (best-effort; see C-2).
type PassthroughRelay struct {
	conn *net.UDPConn
	res  Resolver
	port string

	mu    sync.Mutex
	flows map[string]*udpFlow
}

type udpFlow struct {
	upstream *net.UDPConn
	last     time.Time
	sniffer  *SNIExtractor // nil once routed
	pending  [][]byte      // datagrams buffered until the SNI is known
}

// ListenPassthrough binds addr for UDP passthrough relaying to origin UDP port.
func ListenPassthrough(addr, originPort string, res Resolver) (*PassthroughRelay, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return &PassthroughRelay{conn: conn, res: res, port: originPort, flows: map[string]*udpFlow{}}, nil
}

// Serve runs the relay loop until Close.
func (p *PassthroughRelay) Serve() error {
	buf := make([]byte, 2048)
	for {
		n, client, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		p.handle(client, data)
	}
}

// Close shuts the relay down.
func (p *PassthroughRelay) Close() error {
	p.mu.Lock()
	for _, f := range p.flows {
		f.upstream.Close()
	}
	p.mu.Unlock()
	return p.conn.Close()
}

func (p *PassthroughRelay) handle(client *net.UDPAddr, data []byte) {
	key := client.String()
	p.mu.Lock()
	flow, ok := p.flows[key]
	p.mu.Unlock()
	if ok {
		flow.last = time.Now()
		if flow.upstream != nil {
			_, _ = flow.upstream.Write(data)
		} else {
			// Still resolving the SNI across datagrams.
			p.continueSniff(client, key, flow, data)
		}
		return
	}

	// New flow: reassemble the ClientHello SNI across the first datagram(s).
	sniffer := &SNIExtractor{}
	sni, done := sniffer.Feed(data)
	if sni == "" {
		if done {
			log.Printf("quic passthrough: gave up routing flow from %s (no SNI)", key)
			return
		}
		// Buffer and wait for more datagrams to complete the ClientHello.
		p.mu.Lock()
		p.flows[key] = &udpFlow{last: time.Now(), sniffer: sniffer, pending: [][]byte{append([]byte(nil), data...)}}
		p.mu.Unlock()
		return
	}
	pending := [][]byte{append([]byte(nil), data...)}
	p.routeFlow(client, key, sni, pending)
}

// continueSniff handles a datagram for a flow that is still resolving its SNI.
func (p *PassthroughRelay) continueSniff(client *net.UDPAddr, key string, flow *udpFlow, data []byte) {
	flow.pending = append(flow.pending, append([]byte(nil), data...))
	sni, done := flow.sniffer.Feed(data)
	if sni == "" {
		if done {
			p.mu.Lock()
			delete(p.flows, key)
			p.mu.Unlock()
			log.Printf("quic passthrough: gave up routing flow from %s (no SNI)", key)
		}
		return
	}
	pending := flow.pending
	p.mu.Lock()
	delete(p.flows, key)
	p.mu.Unlock()
	p.routeFlow(client, key, sni, pending)
}

func (p *PassthroughRelay) routeFlow(client *net.UDPAddr, key, sni string, pending [][]byte) {
	ips, err := p.res.LookupIP(context.Background(), sni)
	if err != nil || len(ips) == 0 {
		log.Printf("quic passthrough: resolve %s failed: %v", sni, err)
		return
	}
	raddr := &net.UDPAddr{IP: ips[0], Port: atoiPort(p.port)}
	up, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Printf("quic passthrough: dial origin %s failed: %v", sni, err)
		return
	}
	p.mu.Lock()
	p.flows[key] = &udpFlow{upstream: up, last: time.Now()}
	p.mu.Unlock()

	// Origin -> client pump.
	go func() {
		rbuf := make([]byte, 2048)
		for {
			up.SetReadDeadline(time.Now().Add(60 * time.Second))
			m, err := up.Read(rbuf)
			if err != nil {
				break
			}
			_, _ = p.conn.WriteToUDP(rbuf[:m], client)
		}
		p.mu.Lock()
		delete(p.flows, key)
		p.mu.Unlock()
		up.Close()
	}()

	// Replay every buffered client datagram (the ClientHello may have spanned
	// several) to the origin, in order.
	for _, d := range pending {
		_, _ = up.Write(d)
	}
	log.Printf("quic passthrough: new flow %s -> %s", key, sni)
}

func atoiPort(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 443
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return 443
	}
	return n
}
