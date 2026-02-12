package service

import (
	"log"
	"sync"
	"time"

	"dns-proxy/internal/model"

	"github.com/miekg/dns"
)

// Gere le cache DNS avec expiration par TTL.
type Cache struct {
	store      sync.Map
	gcInterval time.Duration
}

// Cree un nouveau cache DNS.
func NewCache(gcInterval time.Duration) *Cache {
	return &Cache{gcInterval: gcInterval}
}

// Lance le nettoyage periodique des entrees expirees.
func (c *Cache) StartGC() {
	go func() {
		ticker := time.NewTicker(c.gcInterval)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			expired := 0
			total := 0

			c.store.Range(func(key, value any) bool {
				total++
				entry := value.(model.CacheEntry)
				if now.After(entry.ExpiresAt) {
					c.store.Delete(key)
					expired++
				}
				return true
			})

			if expired > 0 {
				log.Printf("Cache GC: %d/%d entrees expirees supprimees", expired, total)
			}
		}
	}()
}

// Get recupere une entree du cache. Retourne une copie du message.
func (c *Cache) Get(key string) (*dns.Msg, bool) {
	value, ok := c.store.Load(key)
	if !ok {
		return nil, false
	}

	entry := value.(model.CacheEntry)
	if time.Now().After(entry.ExpiresAt) {
		c.store.Delete(key)
		return nil, false
	}

	return entry.Msg.Copy(), true
}

// Set stocke une reponse DNS dans le cache avec le TTL minimum du message.
func (c *Cache) Set(key string, msg *dns.Msg) {
	ttl := getMinTTL(msg)
	if ttl == 0 {
		return
	}

	c.store.Store(key, model.CacheEntry{
		Msg:       msg.Copy(),
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	})
}

// Key genere la cle de cache pour une question DNS.
func (c *Cache) Key(q dns.Question) string {
	return q.Name + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

// Clear vide le cache.
func (c *Cache) Clear() {
	c.store.Range(func(key, _ any) bool {
		c.store.Delete(key)
		return true
	})
}

func getMinTTL(msg *dns.Msg) uint32 {
	var minTTL uint32
	for _, sections := range [3][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range sections {
			log.Printf("%v", rr)
			// OPT est un pseudo-record EDNS, son TTL n'est pas un vrai TTL
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			ttl := rr.Header().Ttl
			if minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
		}
	}
	return minTTL
}
