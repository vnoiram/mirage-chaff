package config

import "testing"

func TestDefaultsAreValid(t *testing.T) {
	if err := Defaults().Check(); err != nil {
		t.Fatalf("default config should be valid, got: %v", err)
	}
}

func TestCheckRejectsBadValues(t *testing.T) {
	tests := map[string]func(*Config){
		"bad mode":            func(c *Config) { c.Mode = "nope" },
		"bad key_type":        func(c *Config) { c.Cert.KeyType = "dsa" },
		"http3 without quic":  func(c *Config) { c.Protocols.HTTP3 = true; c.Protocols.QUIC = false },
		"empty https":         func(c *Config) { c.Listen.HTTPS = "" },
		"no resolvers":        func(c *Config) { c.Upstream.Resolvers = nil },
		"no obs listen":       func(c *Config) { c.Observability.Listen = "" },
		"bad log mode":        func(c *Config) { c.Log.Mode = "raw-ish" },
		"bad unknown profile": func(c *Config) { c.UnknownProfile.Default = "reckless" },
		"empty rule catalog":  func(c *Config) { c.RuleCatalog.Path = "" },
		"resolved ip without target name": func(c *Config) {
			c.AGHManaged.TargetMode = "resolved_ip"
			c.AGHManaged.TargetName = ""
		},
		"cname without target name": func(c *Config) {
			c.AGHManaged.TargetMode = "cname"
			c.AGHManaged.TargetName = ""
		},
		"static ip without addresses": func(c *Config) {
			c.AGHManaged.TargetMode = "static_ip"
			c.AGHManaged.StaticIPv4 = nil
			c.AGHManaged.StaticIPv6 = nil
		},
		"static ipv4 rejects invalid ip": func(c *Config) {
			c.AGHManaged.TargetMode = "static_ip"
			c.AGHManaged.StaticIPv4 = []string{"not-an-ip"}
		},
		"static ipv4 rejects ipv6": func(c *Config) {
			c.AGHManaged.TargetMode = "static_ip"
			c.AGHManaged.StaticIPv4 = []string{"2001:db8::1"}
		},
		"static ipv6 rejects ipv4": func(c *Config) {
			c.AGHManaged.TargetMode = "static_ip"
			c.AGHManaged.StaticIPv6 = []string{"192.0.2.10"}
		},
		"negative large change percent": func(c *Config) {
			c.AGHManaged.Scheduler.LargeChangeThresholdPercent = -1
		},
		"negative large change count": func(c *Config) {
			c.AGHManaged.Scheduler.LargeChangeThresholdCount = -1
		},
		"invalid sync interval": func(c *Config) {
			c.AGHManaged.Scheduler.DefaultSyncInterval = "7days"
		},
		"invalid sync timeout": func(c *Config) {
			c.AGHManaged.Scheduler.SyncTimeout = "thirty-seconds"
		},
		"invalid jitter": func(c *Config) {
			c.AGHManaged.Scheduler.Jitter = "10minutes"
		},
		"invalid stale source ttl": func(c *Config) {
			c.AGHManaged.Scheduler.StaleSourceTTL = "3d0h"
		},
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

func TestCheckAcceptsValidStaticIPTargets(t *testing.T) {
	c := Defaults()
	c.AGHManaged.TargetMode = "static_ip"
	c.AGHManaged.StaticIPv4 = []string{"192.0.2.10"}
	c.AGHManaged.StaticIPv6 = []string{"2001:db8::1"}
	if err := c.Check(); err != nil {
		t.Fatalf("valid static_ip target should be accepted, got: %v", err)
	}
}
