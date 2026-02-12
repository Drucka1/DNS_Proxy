package handler

import (
	"log"

	"dns-proxy/internal/service"

	"github.com/miekg/dns"
)

// Traite les requêtes DNS entrantes.
type DNSRequestHandler struct {
	Cache    *service.Cache
	Resolver *service.Resolver
	Filter   *service.Filter
}

// Crée un nouveau Handler DNS.
func NewDNSRequestHandler(cache *service.Cache, resolver *service.Resolver, filter *service.Filter) *DNSRequestHandler {
	return &DNSRequestHandler{
		Cache:    cache,
		Resolver: resolver,
		Filter:   filter,
	}
}

// Traite les requêtes entrantes (implémente dns.Handler).
func (h *DNSRequestHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		log.Printf("Requête reçue: %s %s", dns.TypeToString[question.Qtype], question.Name)

		if h.Filter.IsBanned(question.Name) {
			log.Printf("BLOQUÉ: %s", question.Name)
			msg.Rcode = dns.RcodeNameError
			continue
		}

		key := h.Cache.Key(question)
		if cached, ok := h.Cache.Get(key); ok {
			log.Printf("Cache HIT: %s", key)
			msg.Answer = cached.Answer
			msg.Ns = cached.Ns
			msg.Extra = cached.Extra
			msg.Rcode = cached.Rcode
			continue
		}

		log.Printf("Cache MISS: %s", key)
		response, err := h.Resolver.Forward(r)
		if err != nil {
			log.Printf("Erreur forward: %v", err)
			msg.Rcode = dns.RcodeServerFailure
		} else {
			h.Cache.Set(key, response)
			msg.Answer = response.Answer
			msg.Ns = response.Ns
			msg.Extra = response.Extra
			msg.Rcode = response.Rcode
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Erreur écriture réponse: %v", err)
	}
}
