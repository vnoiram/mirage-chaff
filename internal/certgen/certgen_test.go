package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/config"
)

// makeCA writes a root + name-constrained intermediate (permitting the given DNS
// subtree) to dir and returns the root cert for verification.
func makeCA(t *testing.T, dir string, permit string) *x509.Certificate {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber:                big.NewInt(2),
		Subject:                     pkix.Name{CommonName: "test intermediate"},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().Add(12 * time.Hour),
		KeyUsage:                    x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{permit},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}

	writePEM(t, filepath.Join(dir, "intermediate.crt"), "CERTIFICATE", interDER)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(interKey)
	writePEM(t, filepath.Join(dir, "intermediate.key"), "PRIVATE KEY", keyDER)
	return root
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func newIssuer(t *testing.T, dir string) *Issuer {
	t.Helper()
	iss, err := NewIssuer(config.CertConfig{
		IntermediateCert: filepath.Join(dir, "intermediate.crt"),
		IntermediateKey:  filepath.Join(dir, "intermediate.key"),
		KeyType:          "ecdsa",
		CacheMax:         16,
		CacheTTLHours:    1,
		CacheDir:         filepath.Join(dir, "cache"),
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func verify(root *x509.Certificate, cert *tls.Certificate, sni string) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	interCert, _ := x509.ParseCertificate(cert.Certificate[1])
	inter.AddCert(interCert)
	_, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName:       sni,
		Roots:         roots,
		Intermediates: inter,
	})
	return err
}

func TestIssueLeafChainsAndMatchesSNI(t *testing.T) {
	dir := t.TempDir()
	root := makeCA(t, dir, "test.example")
	iss := newIssuer(t, dir)

	cert, err := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: "ads.test.example"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert.Leaf.Subject.CommonName != "ads.test.example" {
		t.Errorf("CN = %q", cert.Leaf.Subject.CommonName)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("expected leaf+intermediate chain, got %d certs", len(cert.Certificate))
	}
	if err := verify(root, cert, "ads.test.example"); err != nil {
		t.Errorf("permitted SNI should verify: %v", err)
	}
}

func TestNameConstraintRejectsOutsideDomain(t *testing.T) {
	dir := t.TempDir()
	root := makeCA(t, dir, "test.example")
	iss := newIssuer(t, dir)

	// The issuer will happily mint a leaf (clients enforce constraints), but the
	// chain must FAIL verification for a domain outside the permitted subtree.
	cert, err := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: "evil.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if err := verify(root, cert, "evil.example.com"); err == nil {
		t.Fatal("expected name-constraint violation, got valid chain")
	}
}

func TestCacheAndDiskReuse(t *testing.T) {
	dir := t.TempDir()
	makeCA(t, dir, "test.example")
	iss := newIssuer(t, dir)

	c1, _ := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.test.example"})
	c2, _ := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.test.example"})
	if c1 != c2 {
		t.Error("expected in-memory cache to return the same *tls.Certificate")
	}

	// A fresh issuer over the same dir should reuse the on-disk leaf.
	iss2 := newIssuer(t, dir)
	c3, _ := iss2.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.test.example"})
	if c3.Leaf.SerialNumber.Cmp(c1.Leaf.SerialNumber) != 0 {
		t.Error("expected disk cache reuse (same serial) across issuers")
	}
}

func TestNoSNIRejected(t *testing.T) {
	dir := t.TempDir()
	makeCA(t, dir, "test.example")
	iss := newIssuer(t, dir)
	if _, err := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
		t.Fatal("expected error for empty SNI")
	}
}
