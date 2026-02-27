package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Server
	Port    int
	BaseURL string

	// Auth
	AdminCode string

	// Cookie
	CookieDomain string
	CookieSecret string
	SessionTTL   time.Duration

	// Database
	DBPath string

	// Branding
	AppName string
	LogoURL string

	// Rate Limiting
	RateLimit       int
	LockoutAfter    int
	LockoutDuration time.Duration

	// Security
	TrustedProxies []*net.IPNet
}

func Load() (*Config, error) {
	secret := getEnv("COOKIE_SECRET", "")
	if secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generating cookie secret: %w", err)
		}
		secret = hex.EncodeToString(b)
	}

	sessionTTL, err := time.ParseDuration(getEnv("SESSION_TTL", "168h"))
	if err != nil {
		return nil, fmt.Errorf("parsing SESSION_TTL: %w", err)
	}

	lockoutDuration, err := time.ParseDuration(getEnv("LOCKOUT_DURATION", "15m"))
	if err != nil {
		return nil, fmt.Errorf("parsing LOCKOUT_DURATION: %w", err)
	}

	proxies, err := parseCIDRs(getEnv("TRUSTED_PROXIES", "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
	if err != nil {
		return nil, fmt.Errorf("parsing TRUSTED_PROXIES: %w", err)
	}

	return &Config{
		Port:            getEnvInt("PORT", 3000),
		BaseURL:         strings.TrimRight(getEnv("BASE_URL", "http://localhost:3000"), "/"),
		AdminCode:       getEnv("ADMIN_CODE", ""),
		CookieDomain:    getEnv("COOKIE_DOMAIN", ""),
		CookieSecret:    secret,
		SessionTTL:      sessionTTL,
		DBPath:          getEnv("DB_PATH", "./data/gate.db"),
		AppName:         getEnv("APP_NAME", "Gate"),
		LogoURL:         getEnv("LOGO_URL", ""),
		RateLimit:       getEnvInt("RATE_LIMIT", 5),
		LockoutAfter:    getEnvInt("LOCKOUT_AFTER", 10),
		LockoutDuration: lockoutDuration,
		TrustedProxies:  proxies,
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func parseCIDRs(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			entry += "/32"
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
		}
		nets = append(nets, cidr)
	}
	return nets, nil
}
