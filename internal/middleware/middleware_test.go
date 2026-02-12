package middleware

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// ─── helpers ────────────────────────────────────────────────

func fakeAddr(ip string, port int) net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

type mockResponseWriter struct {
	msg        *dns.Msg
	remoteAddr net.Addr
}

func (m *mockResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}
func (m *mockResponseWriter) RemoteAddr() net.Addr        { return m.remoteAddr }
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *mockResponseWriter) Write([]byte) (int, error)   { return 0, nil }
func (m *mockResponseWriter) Close() error                { return nil }
func (m *mockResponseWriter) TsigStatus() error           { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)         {}
func (m *mockResponseWriter) Hijack()                     {}

// ─── Allow ──────────────────────────────────────────────────

func TestAllow_UnderLimit(t *testing.T) {
	rl := NewRateLimiter(10, 10)

	for i := 0; i < 10; i++ {
		if !rl.Allow(fakeAddr("192.168.1.1", 12345)) {
			t.Fatalf("requête %d refusée alors que la limite n'est pas atteinte", i+1)
		}
	}
}

func TestAllow_OverLimit(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	// Épuiser le burst
	for i := 0; i < 5; i++ {
		rl.Allow(fakeAddr("10.0.0.1", 12345))
	}

	// La 6ème devrait être refusée
	if rl.Allow(fakeAddr("10.0.0.1", 12345)) {
		t.Error("requête acceptée alors que le burst est épuisé")
	}
}

func TestAllow_PerIPIsolation(t *testing.T) {
	rl := NewRateLimiter(10, 2)

	// Épuiser le burst de l'IP 1
	rl.Allow(fakeAddr("1.1.1.1", 12345))
	rl.Allow(fakeAddr("1.1.1.1", 12345))

	// L'IP 2 doit encore passer
	if !rl.Allow(fakeAddr("2.2.2.2", 12345)) {
		t.Error("IP 2 refusée alors que seule IP 1 est limitée")
	}
}

func TestAllow_DifferentPortsSameIP(t *testing.T) {
	rl := NewRateLimiter(10, 3)

	// Même IP, ports différents → même bucket
	rl.Allow(fakeAddr("5.5.5.5", 1000))
	rl.Allow(fakeAddr("5.5.5.5", 2000))
	rl.Allow(fakeAddr("5.5.5.5", 3000))

	if rl.Allow(fakeAddr("5.5.5.5", 4000)) {
		t.Error("des ports différents sur la même IP devraient partager le même bucket")
	}
}

// ─── Concurrence ────────────────────────────────────────────

func TestAllow_Concurrent(t *testing.T) {
	rl := NewRateLimiter(1000, 100)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				rl.Allow(fakeAddr("10.10.10.10", 12345))
			}
		}()
	}
	wg.Wait()
	// Si pas de data race, le test passe (go test -race)
}

// ─── Wrap ───────────────────────────────────────────────────

func TestWrap_AllowedRequest(t *testing.T) {
	rl := NewRateLimiter(100, 100)
	called := false

	wrapped := rl.Wrap(dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		called = true
	}))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	w := &mockResponseWriter{remoteAddr: fakeAddr("10.0.0.1", 12345)}
	wrapped(w, req)

	if !called {
		t.Error("le handler interne n'a pas été appelé")
	}
}

func TestWrap_RateLimitedRequest(t *testing.T) {
	rl := NewRateLimiter(10, 1)
	called := false

	wrapped := rl.Wrap(dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		called = true
	}))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	w := &mockResponseWriter{remoteAddr: fakeAddr("10.0.0.1", 12345)}

	// 1ère requête: passe
	wrapped(w, req)
	if !called {
		t.Fatal("1ère requête aurait dû passer")
	}

	// 2ème requête: bloquée
	called = false
	wrapped(w, req)
	if called {
		t.Error("le handler interne a été appelé malgré le rate limiting")
	}
	if w.msg == nil {
		t.Fatal("réponse nil pour requête rate-limitée")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want %d (REFUSED)", w.msg.Rcode, dns.RcodeRefused)
	}
}

func TestWrap_MultipleIPs(t *testing.T) {
	rl := NewRateLimiter(10, 1)
	count := 0

	wrapped := rl.Wrap(dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		count++
	}))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	// Chaque IP a son propre bucket → chacune passe 1 fois
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		w := &mockResponseWriter{remoteAddr: fakeAddr(ip, 12345)}
		wrapped(w, req)
	}

	if count != 5 {
		t.Errorf("count = %d, want 5 (chaque IP devrait passer une fois)", count)
	}
}
