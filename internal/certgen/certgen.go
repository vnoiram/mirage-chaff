package certgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/config"
)

// Issuer loads the intermediate CA and mints per-SNI leaf certificates on the
// fly, signed by the intermediate. Leaves are cached in memory (LRU + TTL) and
// on disk. The disk cache is namespaced by the intermediate CA fingerprint so a
// CA rotation transparently invalidates old leaves (design doc B-2).
//
// Leaves cover ONLY the requested SNI (no extra SANs) to avoid HTTP/2 connection
// coalescing misrouting (design doc A / §A-HTTP2).
type Issuer struct {
	interCert *x509.Certificate
	interKey  crypto.Signer
	interDER  []byte
	fp        string // hex SHA-256 of intermediate DER
	keyType   string
	ttl       time.Duration
	cacheMax  int
	diskDir   string // cacheDir/<fp>

	mu    sync.Mutex
	cache map[string]*entry
}

type entry struct {
	cert    *tls.Certificate
	expires time.Time
	used    time.Time
}

// NewIssuer loads the intermediate CA cert+key described by cfg and prepares the
// leaf cache.
func NewIssuer(cfg config.CertConfig) (*Issuer, error) {
	certPEM, err := os.ReadFile(cfg.IntermediateCert)
	if err != nil {
		return nil, fmt.Errorf("read intermediate cert: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.IntermediateKey)
	if err != nil {
		return nil, fmt.Errorf("read intermediate key: %w", err)
	}

	interCert, err := parseCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate cert: %w", err)
	}
	if !interCert.IsCA {
		return nil, fmt.Errorf("intermediate cert is not a CA (basicConstraints CA:TRUE required)")
	}
	interKey, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate key: %w", err)
	}

	keyType := strings.ToLower(cfg.KeyType)
	if keyType == "" {
		keyType = "ecdsa"
	}
	ttl := time.Duration(cfg.CacheTTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 168 * time.Hour
	}
	cacheMax := cfg.CacheMax
	if cacheMax <= 0 {
		cacheMax = 2048
	}

	sum := sha256.Sum256(interCert.Raw)
	fp := hex.EncodeToString(sum[:])

	iss := &Issuer{
		interCert: interCert,
		interKey:  interKey,
		interDER:  interCert.Raw,
		fp:        fp,
		keyType:   keyType,
		ttl:       ttl,
		cacheMax:  cacheMax,
		cache:     make(map[string]*entry),
	}
	if cfg.CacheDir != "" {
		iss.diskDir = filepath.Join(cfg.CacheDir, fp)
		if err := os.MkdirAll(iss.diskDir, 0o700); err != nil {
			return nil, fmt.Errorf("create cert cache dir: %w", err)
		}
	}
	return iss, nil
}

// Fingerprint returns the hex SHA-256 of the intermediate certificate.
func (i *Issuer) Fingerprint() string { return i.fp }

// NotAfter returns the intermediate CA's expiry (for cert-expiry monitoring).
func (i *Issuer) NotAfter() time.Time { return i.interCert.NotAfter }

// TLSConfig returns a *tls.Config whose GetCertificate mints per-SNI leaves.
// alpn advertises the supported HTTP protocols (e.g. h2, http/1.1).
func (i *Issuer) TLSConfig(alpn []string) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: i.GetCertificate,
		NextProtos:     alpn,
	}
}

// GetCertificate implements tls.Config.GetCertificate: it returns a cached or
// freshly issued leaf for the ClientHello SNI. Connections without SNI are
// rejected here; the server routes them to the SNI-less default path.
func (i *Issuer) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if sni == "" {
		return nil, fmt.Errorf("no SNI in ClientHello")
	}
	if !validHostname(sni) {
		return nil, fmt.Errorf("invalid SNI %q", sni)
	}
	return i.certFor(sni)
}

func (i *Issuer) certFor(sni string) (*tls.Certificate, error) {
	now := time.Now()

	i.mu.Lock()
	if e, ok := i.cache[sni]; ok && now.Before(e.expires) {
		e.used = now
		cert := e.cert
		i.mu.Unlock()
		return cert, nil
	}
	i.mu.Unlock()

	// Try disk cache (survives restart, saves CPU).
	if cert, exp, ok := i.loadDisk(sni); ok && now.Before(exp) {
		i.store(sni, cert, exp)
		return cert, nil
	}

	cert, exp, err := i.issue(sni, now)
	if err != nil {
		return nil, err
	}
	i.store(sni, cert, exp)
	i.saveDisk(sni, cert, exp)
	return cert, nil
}

func (i *Issuer) store(sni string, cert *tls.Certificate, exp time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cache[sni] = &entry{cert: cert, expires: exp, used: time.Now()}
	i.evictLocked()
}

// evictLocked drops the least-recently-used entries when over cacheMax.
func (i *Issuer) evictLocked() {
	for len(i.cache) > i.cacheMax {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, e := range i.cache {
			if first || e.used.Before(oldest) {
				oldest, oldestKey, first = e.used, k, false
			}
		}
		delete(i.cache, oldestKey)
	}
}

// issue mints a new leaf for sni, signed by the intermediate, and returns it
// with its NotAfter. The leaf carries only the requested SNI as SAN.
func (i *Issuer) issue(sni string, now time.Time) (*tls.Certificate, time.Time, error) {
	leafKey, leafPub, err := i.newLeafKey()
	if err != nil {
		return nil, time.Time{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, err
	}

	notAfter := now.Add(i.ttl)
	if notAfter.After(i.interCert.NotAfter) {
		notAfter = i.interCert.NotAfter // never outlive the intermediate
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             now.Add(-1 * time.Hour), // tolerate small clock skew
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.interCert, leafPub, i.interKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("create leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, i.interDER},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}
	return cert, notAfter, nil
}

func (i *Issuer) newLeafKey() (crypto.Signer, crypto.PublicKey, error) {
	if i.keyType == "rsa" {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k, &k.PublicKey, nil
}

// --- disk cache ---

func (i *Issuer) diskPath(sni string) string {
	if i.diskDir == "" {
		return ""
	}
	// sni is validated as a hostname, safe as a filename component.
	return filepath.Join(i.diskDir, sni+".pem")
}

func (i *Issuer) saveDisk(sni string, cert *tls.Certificate, exp time.Time) {
	p := i.diskPath(sni)
	if p == "" {
		return
	}
	var buf strings.Builder
	// Leaf + intermediate chain.
	for _, der := range cert.Certificate {
		pem.Encode(&stringWriter{&buf}, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return
	}
	pem.Encode(&stringWriter{&buf}, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	_ = os.WriteFile(p, []byte(buf.String()), 0o600)
}

func (i *Issuer) loadDisk(sni string) (*tls.Certificate, time.Time, bool) {
	p := i.diskPath(sni)
	if p == "" {
		return nil, time.Time{}, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, time.Time{}, false
	}
	var chain [][]byte
	var key crypto.PrivateKey
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			chain = append(chain, blk.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err == nil {
				key = k
			}
		}
	}
	if len(chain) == 0 || key == nil {
		return nil, time.Time{}, false
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, time.Time{}, false
	}
	cert := &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}
	return cert, leaf.NotAfter, true
}

// --- PEM parsing helpers ---

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("no PEM CERTIFICATE block found")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func parseKey(pemBytes []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("no PEM key block found")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, fmt.Errorf("PKCS8 key is not a signer")
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key format (want PKCS8/EC/PKCS1)")
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, "/\\ \t") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
