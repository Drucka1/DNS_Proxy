package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"dns-proxy/internal/handler"
	"dns-proxy/internal/middleware"
	"dns-proxy/internal/service"

	"github.com/miekg/dns"
)

// startTestServer démarre un serveur DNS sur un port libre et retourne l'adresse.
func startTestServer(t *testing.T, rateLimiter *middleware.RateLimiter) (addr string, shutdown func()) {
	t.Helper()

	cache := service.NewCache(time.Minute)
	resolver := service.NewResolver([]string{"8.8.8.8:53", "1.1.1.1:53"})
	filter := service.NewFilter(map[string]struct{}{
		"banned_namespace1": {},
		"banned_namespace2": {},
	})
	h := handler.NewDNSRequestHandler(cache, resolver, filter)

	// Port aléatoire
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("impossible d'écouter: %v", err)
	}
	addr = pc.LocalAddr().String()
	pc.Close()

	mux := dns.NewServeMux()
	if rateLimiter != nil {
		mux.Handle(".", rateLimiter.Wrap(h))
	} else {
		mux.Handle(".", h)
	}

	server := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }

	go func() {
		if err := server.ListenAndServe(); err != nil {
			// Le shutdown normal provoque une erreur, on l'ignore
		}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: le serveur DNS n'a pas démarré")
	}

	return addr, func() { server.Shutdown() }
}

// query envoie une requête DNS au serveur de test.
func query(addr, domain string, qtype uint16) (*dns.Msg, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	resp, _, err := client.Exchange(msg, addr)
	return resp, err
}

// ─── Tests de résolution DNS ────────────────────────────────

func TestIntegration_ResolveLegitDomain(t *testing.T) {
	addr, shutdown := startTestServer(t, nil)
	defer shutdown()

	resp, err := query(addr, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("erreur requête DNS: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (SUCCESS)", resp.Rcode, dns.RcodeSuccess)
	}
	if len(resp.Answer) == 0 {
		t.Error("aucune réponse pour google.com")
	}
}

func TestIntegration_ResolveAAAA(t *testing.T) {
	addr, shutdown := startTestServer(t, nil)
	defer shutdown()

	resp, err := query(addr, "google.com", dns.TypeAAAA)
	if err != nil {
		t.Fatalf("erreur requête DNS: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (SUCCESS)", resp.Rcode, dns.RcodeSuccess)
	}
}

// ─── Tests de blocage ───────────────────────────────────────

func TestIntegration_BlockBannedDomain(t *testing.T) {
	addr, shutdown := startTestServer(t, nil)
	defer shutdown()

	resp, err := query(addr, "banned_namespace1", dns.TypeA)
	if err != nil {
		t.Fatalf("erreur requête DNS: %v", err)
	}

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want %d (NXDOMAIN) pour domaine banni", resp.Rcode, dns.RcodeNameError)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("Answer non vide pour domaine banni: %d records", len(resp.Answer))
	}
}

func TestIntegration_BlockBannedSubdomain(t *testing.T) {
	addr, shutdown := startTestServer(t, nil)
	defer shutdown()

	resp, err := query(addr, "sub.banned_namespace2.evil.com", dns.TypeA)
	if err != nil {
		t.Fatalf("erreur requête DNS: %v", err)
	}

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want %d (NXDOMAIN) pour sous-domaine banni", resp.Rcode, dns.RcodeNameError)
	}
}

// ─── Tests du cache ─────────────────────────────────────────

func TestIntegration_CacheHit(t *testing.T) {
	addr, shutdown := startTestServer(t, nil)
	defer shutdown()

	// 1ère requête : cache MISS
	resp1, err := query(addr, "example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("erreur 1ère requête: %v", err)
	}
	if resp1.Rcode != dns.RcodeSuccess {
		t.Skipf("example.com non résolu (pas de réseau?), skip")
	}

	// 2ème requête : devrait être servie depuis le cache (plus rapide)
	start := time.Now()
	resp2, err := query(addr, "example.com", dns.TypeA)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("erreur 2ème requête: %v", err)
	}
	if resp2.Rcode != dns.RcodeSuccess {
		t.Errorf("2ème requête Rcode = %d, want SUCCESS", resp2.Rcode)
	}

	// La réponse cachée devrait être quasi-instantanée (< 50ms)
	if elapsed > 50*time.Millisecond {
		t.Logf("cache hit lent: %v (attendu < 50ms)", elapsed)
	}
}

// ─── Tests du rate limiting ─────────────────────────────────

func TestIntegration_RateLimitRefuses(t *testing.T) {
	// burst=3 : la 4ème requête immédiate est refusée
	rl := middleware.NewRateLimiter(5, 3)
	addr, shutdown := startTestServer(t, rl)
	defer shutdown()

	var refused int
	for i := 0; i < 10; i++ {
		resp, err := query(addr, "google.com", dns.TypeA)
		if err != nil {
			t.Fatalf("erreur requête %d: %v", i+1, err)
		}
		if resp.Rcode == dns.RcodeRefused {
			refused++
		}
	}

	if refused == 0 {
		t.Error("aucune requête refusée malgré le rate limiting (burst=3, 10 requêtes)")
	}
	t.Logf("requêtes refusées: %d/10", refused)
}

func TestIntegration_RateLimitPerIP(t *testing.T) {
	// Vérifier que le rate limiting est par IP :
	// Depuis la même IP locale, le burst s'épuise.
	rl := middleware.NewRateLimiter(1, 2)
	addr, shutdown := startTestServer(t, rl)
	defer shutdown()

	// Les 2 premières passent (burst=2)
	for i := 0; i < 2; i++ {
		resp, err := query(addr, "google.com", dns.TypeA)
		if err != nil {
			t.Fatalf("erreur requête %d: %v", i+1, err)
		}
		if resp.Rcode == dns.RcodeRefused {
			t.Errorf("requête %d refusée alors que le burst n'est pas épuisé", i+1)
		}
	}

	// La 3ème devrait être refusée
	resp, err := query(addr, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("erreur 3ème requête: %v", err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("3ème requête Rcode = %d, want %d (REFUSED)", resp.Rcode, dns.RcodeRefused)
	}
}

// ─── Test de charge ─────────────────────────────────────────

func TestIntegration_ConcurrentQueries(t *testing.T) {
	addr, shutdown := startTestServer(t, nil)
	defer shutdown()

	errors := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func(n int) {
			domain := fmt.Sprintf("test%d.example.com", n)
			_, err := query(addr, domain, dns.TypeA)
			errors <- err
		}(i)
	}

	var errCount int
	for i := 0; i < 20; i++ {
		if err := <-errors; err != nil {
			errCount++
			t.Logf("erreur requête concurrente: %v", err)
		}
	}

	if errCount > 5 {
		t.Errorf("trop d'erreurs en concurrence: %d/20", errCount)
	}
}
