package config

import "testing"

func TestDefaultsAreValid(t *testing.T) {
	if err := Defaults().Check(); err != nil {
		t.Fatalf("default config should be valid, got: %v", err)
	}
}

func TestCheckRejectsBadValues(t *testing.T) {
	tests := map[string]func(*Config){
		"bad mode":           func(c *Config) { c.Mode = "nope" },
		"bad key_type":       func(c *Config) { c.Cert.KeyType = "dsa" },
		"http3 without quic": func(c *Config) { c.Protocols.HTTP3 = true; c.Protocols.QUIC = false },
		"empty https":        func(c *Config) { c.Listen.HTTPS = "" },
		"no resolvers":       func(c *Config) { c.Upstream.Resolvers = nil },
		"no obs listen":      func(c *Config) { c.Observability.Listen = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := Defaults()
			mutate(&c)
			if err := c.Check(); err == nil {
				t.Fatalf("expected Check to reject %q, got nil", name)
			}
		})
	}
}

func TestHTTP3RequiresQUIC(t *testing.T) {
	c := Defaults()
	c.Protocols.QUIC = true
	c.Protocols.HTTP3 = true
	if err := c.Check(); err != nil {
		t.Fatalf("http3 with quic should be valid, got: %v", err)
	}
}
