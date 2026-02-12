package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"dns-proxy/internal/config"
	"dns-proxy/internal/handler"
	"dns-proxy/internal/middleware"
	"dns-proxy/internal/server"
	"dns-proxy/internal/service"
)

func main() {
	// Charger la configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Erreur configuration: %v", err)
	}

	// Charger les domaines bannis
	banned, err := config.LoadBannedDomains(cfg.BannedFile)
	if err != nil {
		log.Fatalf("Erreur chargement domaines bannis: %v", err)
	}

	// Services
	cache := service.NewCache(cfg.GcInterval)
	if (cfg.GcInterval != 0) { 
		cache.StartGC()
		log.Printf("Demarrage du garbace collector")
	}

	resolver := service.NewResolver(cfg.Upstreams)
	filter := service.NewFilter(banned)

	// Handler
	dnsHandler := handler.NewDNSRequestHandler(cache, resolver, filter)

	// Middleware
	limiter := middleware.NewRateLimiter(cfg.RateLimit, cfg.RateBurst)

	// Serveur
	listenAddr := cfg.ListenIP + cfg.ListenAddr
	srv := server.New(listenAddr, limiter.Wrap(dnsHandler))

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Erreur serveur DNS: %v", err)
		}
	}()

	// Attendre un signal pour shutdown propre
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("\nSignal reçu: %v, arrêt...\n", s)

	srv.Shutdown()
}
