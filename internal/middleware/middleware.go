package middleware

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// RateLimiter gère le rate limiting par IP via golang.org/x/time/rate.
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*ClientBucket
	rate    rate.Limit
	burst   int
	cleanup time.Duration
}

// ClientBucket représente un bucket de rate limiting pour un client.
type ClientBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter crée un rate limiter.
//   - r : nombre de requêtes autorisées par seconde (ex: 10)
//   - burst : pic max de requêtes instantanées (ex: 20)
func NewRateLimiter(r float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*ClientBucket),
		rate:    rate.Limit(r),
		burst:   burst,
		cleanup: 5 * time.Minute,
	}
	go rl.cleanupLoop()
	return rl
}

// getClient retourne le limiter associé à une IP, ou en crée un nouveau.
func (rl *RateLimiter) getClient(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	c, exists := rl.clients[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.clients[ip] = &ClientBucket{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}

	c.lastSeen = time.Now()
	return c.limiter
}

// Allow vérifie si l'IP peut envoyer une requête.
func (rl *RateLimiter) Allow(addr net.Addr) bool {
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		ip = addr.String()
	}
	return rl.getClient(ip).Allow()
}

// cleanupLoop supprime les clients inactifs périodiquement.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, c := range rl.clients {
			if now.Sub(c.lastSeen) > rl.cleanup {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Wrap crée un dns.Handler avec rate limiting autour d'un handler existant.
func (rl *RateLimiter) Wrap(next dns.Handler) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if !rl.Allow(w.RemoteAddr()) {
			log.Printf("RATE LIMITED: %s", w.RemoteAddr())
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.Rcode = dns.RcodeRefused
			w.WriteMsg(msg)
			return
		}
		next.ServeDNS(w, r)
	}
}
