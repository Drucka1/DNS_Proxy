package service

import (
	"testing"
	"time"

	"dns-proxy/internal/model"

	"github.com/miekg/dns"
)

func makeDNSResponse(name string, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: []byte{1, 2, 3, 4},
		},
	}
	msg.Rcode = dns.RcodeSuccess
	return msg
}

func TestKey_Format(t *testing.T) {
	c := NewCache(time.Minute)
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	got := c.Key(q)
	want := "example.com.|A|IN"
	if got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}
}

func TestKey_DifferentTypes(t *testing.T) {
	c := NewCache(time.Minute)
	tests := []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"type A", dns.TypeA, "example.com.|A|IN"},
		{"type AAAA", dns.TypeAAAA, "example.com.|AAAA|IN"},
		{"type MX", dns.TypeMX, "example.com.|MX|IN"},
		{"type CNAME", dns.TypeCNAME, "example.com.|CNAME|IN"},
		{"type TXT", dns.TypeTXT, "example.com.|TXT|IN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := dns.Question{Name: "example.com.", Qtype: tt.qtype, Qclass: dns.ClassINET}
			if got := c.Key(q); got != tt.want {
				t.Errorf("Key() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKey_Uniqueness(t *testing.T) {
	c := NewCache(time.Minute)
	q1 := dns.Question{Name: "a.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	q2 := dns.Question{Name: "b.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	q3 := dns.Question{Name: "a.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	k1, k2, k3 := c.Key(q1), c.Key(q2), c.Key(q3)
	if k1 == k2 {
		t.Errorf("cles identiques pour domaines differents: %q", k1)
	}
	if k1 == k3 {
		t.Errorf("cles identiques pour types differents: %q", k1)
	}
}

func TestSetAndGet(t *testing.T) {
	c := NewCache(time.Minute)
	msg := makeDNSResponse("example.com.", 300)
	c.Set("example.com.|A|IN", msg)
	cached, ok := c.Get("example.com.|A|IN")
	if !ok {
		t.Fatal("cache miss alors qu'on vient de set")
	}
	if len(cached.Answer) != 1 {
		t.Fatalf("Answer len = %d, want 1", len(cached.Answer))
	}
	if cached.Answer[0].Header().Name != "example.com." {
		t.Errorf("Answer name = %q, want %q", cached.Answer[0].Header().Name, "example.com.")
	}
}

func TestGet_Miss(t *testing.T) {
	c := NewCache(time.Minute)
	_, ok := c.Get("nonexistent.|A|IN")
	if ok {
		t.Error("cache hit pour une cle inexistante")
	}
}

func TestGet_ReturnsCopy(t *testing.T) {
	c := NewCache(time.Minute)
	msg := makeDNSResponse("copy.com.", 300)
	c.Set("copy.com.|A|IN", msg)
	cached1, _ := c.Get("copy.com.|A|IN")
	cached2, _ := c.Get("copy.com.|A|IN")
	cached1.Answer = nil
	if cached2.Answer == nil || len(cached2.Answer) == 0 {
		t.Error("modifier une copie a affecte l'autre")
	}
}

func TestSet_ZeroTTL_NotCached(t *testing.T) {
	c := NewCache(time.Minute)
	msg := makeDNSResponse("nottl.com.", 0)
	c.Set("nottl.com.|A|IN", msg)
	_, ok := c.Get("nottl.com.|A|IN")
	if ok {
		t.Error("un message avec TTL=0 ne devrait pas etre mis en cache")
	}
}

func TestGet_Expired(t *testing.T) {
	c := NewCache(time.Minute)
	c.store.Store("expired.|A|IN", model.CacheEntry{
		Msg:       makeDNSResponse("expired.", 60),
		ExpiresAt: time.Now().Add(-1 * time.Second),
	})
	_, ok := c.Get("expired.|A|IN")
	if ok {
		t.Error("cache hit pour une entree expiree")
	}
	_, exists := c.store.Load("expired.|A|IN")
	if exists {
		t.Error("l'entree expiree n'a pas ete supprimee du cache")
	}
}

func TestGetMinTTL_SingleAnswer(t *testing.T) {
	msg := makeDNSResponse("test.com.", 300)
	if got := getMinTTL(msg); got != 300 {
		t.Errorf("getMinTTL() = %d, want 300", got)
	}
}

func TestGetMinTTL_MultipleSections(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Ttl: 300}},
		&dns.A{Hdr: dns.RR_Header{Ttl: 600}},
	}
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Ttl: 172800}},
	}
	msg.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Ttl: 86400}},
	}
	if got := getMinTTL(msg); got != 300 {
		t.Errorf("getMinTTL() = %d, want 300", got)
	}
}

func TestGetMinTTL_EmptyMessage(t *testing.T) {
	msg := new(dns.Msg)
	if got := getMinTTL(msg); got != 0 {
		t.Errorf("getMinTTL() = %d, want 0 pour un message vide", got)
	}
}

func TestGetMinTTL_MinInNsSection(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Ttl: 500}},
	}
	msg.Ns = []dns.RR{
		&dns.SOA{Hdr: dns.RR_Header{Ttl: 60}},
	}
	if got := getMinTTL(msg); got != 60 {
		t.Errorf("getMinTTL() = %d, want 60 (min dans Ns)", got)
	}
}
