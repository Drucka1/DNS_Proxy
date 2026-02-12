package model

import (
	"time"

	"github.com/miekg/dns"
)

// Config contient toute la configuration du proxy DNS.
type Config struct {
	Upstreams  []string
	ListenAddr string
	ListenIP   string
	RateLimit  float64
	RateBurst  int
	BannedFile []string
	CacheSize  int
	GcInterval time.Duration
}

// CacheEntry représente une entrée du cache DNS.
type CacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
}
