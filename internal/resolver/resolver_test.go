package resolver

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseAnswersIgnoresMismatchedAnswerName(t *testing.T) {
	want := mustDNSName(t, "wanted.example.")
	other := mustDNSName(t, "other.example.")
	wire := mustPackDNS(t, dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{
			Name:  want,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: other, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}},
		}},
	})
	ips, err := parseAnswers(wire, want, dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 0 {
		t.Fatalf("mismatched answer name must be ignored, got %v", ips)
	}
}

func TestParseAnswersAcceptsMatchingAAndAAAA(t *testing.T) {
	want := mustDNSName(t, "wanted.example.")
	aWire := mustPackDNS(t, dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{
			Name:  want,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: want, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}},
		}},
	})
	ips, err := parseAnswers(aWire, want, dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(192, 0, 2, 10)) {
		t.Fatalf("A ips = %v", ips)
	}

	aaaaWire := mustPackDNS(t, dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{
			Name:  want,
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: want, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		}},
	})
	ips, err = parseAnswers(aaaaWire, want, dnsmessage.TypeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("AAAA ips = %v", ips)
	}
}

func mustDNSName(t *testing.T, name string) dnsmessage.Name {
	t.Helper()
	out, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustPackDNS(t *testing.T, msg dnsmessage.Message) []byte {
	t.Helper()
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
