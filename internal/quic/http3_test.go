package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func selfSigned(t *testing.T) *tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "h3.test"},
		DNSNames:     []string{"h3.test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestHTTP3Termination(t *testing.T) {
	cert := selfSigned(t)
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(http.StatusNoContent)
	})

	srv, err := ListenHTTP3("127.0.0.1:0", getCert, handler)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	rt := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}}
	defer rt.Close()
	client := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	url := "https://" + srv.LocalAddr().String() + "/x"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("http3 GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if resp.Header.Get("X-Proto") != "HTTP/3.0" {
		t.Errorf("server saw proto %q, want HTTP/3.0", resp.Header.Get("X-Proto"))
	}
}
