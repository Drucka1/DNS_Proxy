package service

import (
	"log"
	"time"

	"github.com/miekg/dns"
)

// Gère la résolution DNS via les serveurs upstream.
type Resolver struct {
	Upstreams []string
	Timeout   time.Duration
}

// Crée un resolver DNS.
func NewResolver(upstreams []string) *Resolver {
	return &Resolver{
		Upstreams: upstreams,
		Timeout:   5 * time.Second,
	}
}

// Envoie la requête à tous les upstreams et retourne la première réponse valide.
func (r *Resolver) Forward(msg *dns.Msg) (*dns.Msg, error) {
	type result struct {
		msg *dns.Msg
		err error
	}

	ch := make(chan result, len(r.Upstreams))

	for _, upstream := range r.Upstreams {
		go func(addr string) {
			client := &dns.Client{
				Net:     "udp",
				Timeout: r.Timeout,
			}
			response, _, err := client.Exchange(msg, addr)
			ch <- result{msg: response, err: err}
		}(upstream)
	}

	var lastErr error
	for range r.Upstreams {
		res := <-ch
		if res.err == nil && res.msg != nil {
			return res.msg, nil
		}
		lastErr = res.err
		log.Printf("Erreur upstream: %v", lastErr)
	}

	return nil, lastErr
}
