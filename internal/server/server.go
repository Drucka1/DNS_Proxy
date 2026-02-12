package server

import (
	"log"

	"github.com/miekg/dns"
)

// Server encapsule le serveur DNS UDP.
type Server struct {
	udp *dns.Server
}

// New crée un nouveau serveur DNS.
func New(addr string, handler dns.Handler) *Server {
	return &Server{
		udp: &dns.Server{
			Addr:    addr,
			Net:     "udp",
			Handler: handler,
		},
	}
}

// Start démarre le serveur (bloquant).
func (s *Server) Start() error {
	log.Printf("Démarrage serveur DNS udp sur %s", s.udp.Addr)
	return s.udp.ListenAndServe()
}

// Shutdown arrête le serveur proprement.
func (s *Server) Shutdown() error {
	return s.udp.Shutdown()
}
