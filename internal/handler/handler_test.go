package handler

import (
	"net"
	"testing"
	"time"

	"dns-proxy/internal/service"

	"github.com/miekg/dns"
)

// ─── helpers ────────────────────────────────────────────────

type mockResponseWriter struct {
	msg *dns.Msg
}

func (m *mockResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}
func (m *mockResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 12345}
}
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *mockResponseWriter) Write([]byte) (int, error)   { return 0, nil }
func (m *mockResponseWriter) Close() error                { return nil }
func (m *mockResponseWriter) TsigStatus() error           { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)         {}
func (m *mockResponseWriter) Hijack()                     {}

func newTestHandler() *DNSRequestHandler {
	cache := service.NewCache(time.Minute)
	resolver := service.NewResolver([]string{"8.8.8.8:53"})
	filter := service.NewFilter(map[string]struct{}{
		"banned_namespace1": {},
		"banned_namespace2": {},
	})
	return NewDNSRequestHandler(cache, resolver, filter)
}

// ─── ServeDNS ───────────────────────────────────────────────

func TestServeDNS_BannedDomain(t *testing.T) {
	h := newTestHandler()

	req := new(dns.Msg)
	req.SetQuestion("banned_namespace1.", dns.TypeA)

	w := &mockResponseWriter{}
	h.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("réponse nil")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want %d (NXDOMAIN)", w.msg.Rcode, dns.RcodeNameError)
	}
	if len(w.msg.Answer) != 0 {
		t.Errorf("Answer devrait être vide pour un domaine banni, got %d records", len(w.msg.Answer))
	}
}

func TestServeDNS_BannedSubdomain(t *testing.T) {
	h := newTestHandler()

	req := new(dns.Msg)
	req.SetQuestion("sub.banned_namespace2.evil.com.", dns.TypeA)

	w := &mockResponseWriter{}
	h.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("réponse nil")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want %d (NXDOMAIN)", w.msg.Rcode, dns.RcodeNameError)
	}
}
