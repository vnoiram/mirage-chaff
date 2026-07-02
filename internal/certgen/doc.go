// Package certgen loads the intermediate CA and issues per-SNI leaf certificates
// on the fly (crypto/tls GetCertificate), with an LRU+TTL in-memory cache and a
// disk-persistent cache under /var/lib/mirage-chaff/certcache.
//
// Security (design doc B-1/B-2): the intermediate CA MUST carry X.509 Name
// Constraints limiting issuance to curated domains, and the cert cache is keyed
// by the intermediate CA fingerprint so stale leaves are purged on CA rotation.
package certgen
