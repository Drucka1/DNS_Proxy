package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"dns-proxy/internal/model"
)

// Load charge la configuration depuis le .env et les variables d'environnement.
func Load() (*model.Config, error) {
	loadEnvFile(".env")

	var errs []string

	upstreams, ok := getEnvList("DNS_UPSTREAMS")
	if !ok {
		errs = append(errs, "DNS_UPSTREAMS")
	}
	upstreams = normalizeUpstreams(upstreams)

	listenAddr, ok := getEnv("DNS_IP")
	if !ok {
		errs = append(errs, "DNS_IP")
	}

	rateLimit, ok := getEnvFloat("RATE_LIMIT")
	if !ok {
		errs = append(errs, "RATE_LIMIT")
	}

	rateBurst, ok := getEnvInt("RATE_BURST")
	if !ok {
		errs = append(errs, "RATE_BURST")
	}

	bannedFile, ok := getEnvList("BANNED_DOMAINS_FILE")
	if !ok {
		errs = append(errs, "BANNED_DOMAINS_FILE")
	}

	gcInterval, ok := getEnvTime("GC_INTERVAL")
	if !ok {
		errs = append(errs, "GC_INTERVAL")
	}

	cacheSize, ok := getEnvInt("CACHE_SIZE")
	if !ok {
		errs = append(errs, "CACHE_SIZE")
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("Problème avec les variables (.env): %s", strings.Join(errs, ", "))
	}

	cfg := &model.Config{
		Upstreams:  upstreams,
		ListenAddr: listenAddr,
		RateLimit:  rateLimit,
		RateBurst:  rateBurst,
		BannedFile: bannedFile,
		CacheSize:  cacheSize,
		GcInterval: gcInterval,
	}

	log.Printf("Config: upstreams=%v listen=%s rate=%.0f/s burst=%d banned=%s",
		cfg.Upstreams, cfg.ListenAddr, cfg.RateLimit, cfg.RateBurst, cfg.BannedFile)

	return cfg, nil
}

// normalizeUpstreams ajoute le port 53 aux adresses qui n'en ont pas.
func normalizeUpstreams(upstreams []string) []string {
	result := make([]string, len(upstreams))
	for i, upstream := range upstreams {
		if !strings.Contains(upstream, ":") {
			result[i] = upstream + ":53"
		} else {
			result[i] = upstream
		}
	}
	return result
}

// LoadBannedDomains charge les domaines bannis depuis un fichier texte.
func LoadBannedDomains(paths []string) (map[string]struct{}, error) {
	banned := make(map[string]struct{})
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("impossible d'ouvrir %s: %w", path, err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			banned[line] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, fmt.Errorf("erreur lecture %s: %w", path, err)
		}
		file.Close()
		log.Printf("Chargé %d domaines bannis depuis %s", len(banned), path)
	}
	return banned, nil
}

// loadEnvFile lit un fichier .env et injecte les variables dans l'environnement.
func loadEnvFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Pas de fichier %s, utilisation des valeurs par défaut", path)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Ne pas écraser une variable déjà définie
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}

///

func getEnv(key string) (string, bool) { return os.LookupEnv(key) }

// parseEnvValue is a generic helper for parsing environment variables.
func parseEnvValue[T any](key string, parse func(string) (T, error)) (T, bool) {
	v, ok := os.LookupEnv(key)
	var zero T
	if !ok {
		return zero, false
	}
	val, err := parse(v)
	if err != nil {
		log.Printf("Valeur invalide pour %s=%q", key, v)
		return zero, false
	}
	return val, true
}

func getEnvList(key string) ([]string, bool) {
	return parseEnvValue(key, func(s string) ([]string, error) {
		var result []string
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				result = append(result, part)
			}
		}
		if len(result) == 0 {
			return nil, fmt.Errorf("Empty list")
		}
		return result, nil
	})
}

func getEnvFloat(key string) (float64, bool) {
	return parseEnvValue(key, func(s string) (float64, error) { return strconv.ParseFloat(s, 64) })
}

func getEnvInt(key string) (int, bool) {
	return parseEnvValue(key, func(s string) (int, error) { return strconv.Atoi(s) })
}

func getEnvTime(key string) (time.Duration, bool) {
	return parseEnvValue(key, func(s string) (time.Duration, error) {
		if s == "null" {
			return 0, nil
		}
		if len(s) < 2 {
			return 0, fmt.Errorf("invalid duration format: %q", s)
		}
		unit := s[len(s)-1]
		valueStr := s[:len(s)-1]
		value, err := strconv.Atoi(valueStr)
		if err != nil {
			return 0, err
		}
		switch unit {
		case 's':
			return time.Duration(value) * time.Second, nil
		case 'm':
			return time.Duration(value) * time.Minute, nil
		case 'h':
			return time.Duration(value) * time.Hour, nil
		default:
			return 0, fmt.Errorf("unknown duration unit: %q", unit)
		}
	})
}
