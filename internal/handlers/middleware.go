package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/totorospirit/gate/internal/config"
	"github.com/totorospirit/gate/internal/models"
	"github.com/totorospirit/gate/internal/services"
)

type contextKey string

const (
	sessionKey contextKey = "session"
	csrfKey    contextKey = "csrf_token"
)

func GetSession(r *http.Request) *models.Session {
	if sess, ok := r.Context().Value(sessionKey).(*models.Session); ok {
		return sess
	}
	return nil
}

func GetCSRFToken(r *http.Request) string {
	if token, ok := r.Context().Value(csrfKey).(string); ok {
		return token
	}
	return ""
}

// SessionMiddleware loads session from cookie if present
func SessionMiddleware(sessions *services.SessionService, cookieSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("gate_session")
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			sessionID, ok := validateSignedCookie(cookie.Value, cookieSecret)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			sess, err := sessions.Get(sessionID)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), sessionKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin ensures the request has an admin session
func RequireAdmin(baseURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := GetSession(r)
			if sess == nil {
				http.Redirect(w, r, baseURL+"/login?redirect="+r.URL.RequestURI(), http.StatusFound)
				return
			}
			if sess.Role != "admin" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied</title><link rel="stylesheet" href="/static/style.css"></head><body class="login-body"><div class="login-container"><div class="login-card" style="text-align:center"><div class="login-icon" style="background:rgba(239,68,68,0.1);border-color:rgba(239,68,68,0.2)"><svg viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg></div><h1 style="font-size:1.25rem;font-weight:600;margin:1rem 0 .5rem">Access Denied</h1><p style="color:var(--text-muted);margin-bottom:1.5rem">Admin privileges required. You're signed in as <strong>` + sess.CodeName + `</strong>.</p><div style="display:flex;gap:.75rem;justify-content:center"><a href="/logout" style="padding:.5rem 1.5rem;background:var(--border);color:var(--text);border-radius:8px;text-decoration:none;font-size:.875rem">Sign out & switch</a><a href="/" style="padding:.5rem 1.5rem;background:var(--border);color:var(--text);border-radius:8px;text-decoration:none;font-size:.875rem">Go back</a></div></div></div></body></html>`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRFMiddleware generates and validates CSRF tokens
func CSRFMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				token := generateCSRFToken(secret)
				ctx := context.WithValue(r.Context(), csrfKey, token)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Validate CSRF for state-changing methods
			token := r.FormValue("csrf_token")
			if token == "" {
				token = r.Header.Get("X-CSRF-Token")
			}
			if !validateCSRFToken(token, secret) {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}

			// Generate new token for the response
			newToken := generateCSRFToken(secret)
			ctx := context.WithValue(r.Context(), csrfKey, newToken)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RateLimiter tracks per-IP request rates
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*ipRecord
	limit    int
	lockout  int
	lockDur  time.Duration
}

type ipRecord struct {
	count     int
	total     int // total failures for lockout
	windowEnd time.Time
	lockedUntil time.Time
}

func NewRateLimiter(limit, lockout int, lockDur time.Duration) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string]*ipRecord),
		limit:    limit,
		lockout:  lockout,
		lockDur:  lockDur,
	}
	// Cleanup old entries periodically
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[ip]
	if !ok {
		rl.attempts[ip] = &ipRecord{
			count:     1,
			total:     0,
			windowEnd: time.Now().Add(time.Minute),
		}
		return true
	}

	if !rec.lockedUntil.IsZero() && time.Now().Before(rec.lockedUntil) {
		return false
	}

	if time.Now().After(rec.windowEnd) {
		rec.count = 1
		rec.windowEnd = time.Now().Add(time.Minute)
		return true
	}

	rec.count++
	return rec.count <= rl.limit
}

func (rl *RateLimiter) RecordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[ip]
	if !ok {
		rl.attempts[ip] = &ipRecord{
			count:     1,
			total:     1,
			windowEnd: time.Now().Add(time.Minute),
		}
		return
	}

	rec.total++
	if rec.total >= rl.lockout {
		rec.lockedUntil = time.Now().Add(rl.lockDur)
		rec.total = 0
	}
}

func (rl *RateLimiter) IsLocked(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[ip]
	if !ok {
		return false
	}
	return !rec.lockedUntil.IsZero() && time.Now().Before(rec.lockedUntil)
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, rec := range rl.attempts {
		if now.After(rec.windowEnd) && (rec.lockedUntil.IsZero() || now.After(rec.lockedUntil)) {
			delete(rl.attempts, ip)
		}
	}
}

// ClientIP extracts the real client IP, respecting trusted proxies
func ClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	// Check X-Forwarded-For if request comes from trusted proxy
	remoteIP := extractIP(r.RemoteAddr)
	if isTrusted(remoteIP, trustedProxies) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// Walk backwards to find first untrusted IP
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if !isTrusted(ip, trustedProxies) {
					return ip
				}
			}
			return strings.TrimSpace(parts[0])
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	return remoteIP
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func isTrusted(ip string, proxies []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range proxies {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// Cookie helpers

func SetSessionCookie(w http.ResponseWriter, sessionID string, cfg *config.Config) {
	signed := signCookie(sessionID, cfg.CookieSecret)
	http.SetCookie(w, &http.Cookie{
		Name:     "gate_session",
		Value:    signed,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		MaxAge:   int(cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(cfg.BaseURL, "https"),
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     "gate_session",
		Value:    "",
		Path:     "/",
		Domain:   cfg.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(cfg.BaseURL, "https"),
		SameSite: http.SameSiteLaxMode,
	})
}

func signCookie(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	sig := hex.EncodeToString(mac.Sum(nil))
	return value + "." + sig
}

func validateSignedCookie(signed, secret string) (string, bool) {
	idx := strings.LastIndex(signed, ".")
	if idx == -1 {
		return "", false
	}
	value := signed[:idx]
	expected := signCookie(value, secret)
	if !hmac.Equal([]byte(signed), []byte(expected)) {
		return "", false
	}
	return value, true
}

func generateCSRFToken(secret string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	nonce := base64.RawURLEncoding.EncodeToString(b)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(nonce))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", nonce, sig)
}

func validateCSRFToken(token, secret string) bool {
	if token == "" {
		return false
	}
	idx := strings.LastIndex(token, ".")
	if idx == -1 {
		return false
	}
	nonce := token[:idx]
	expectedSig := func() string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(nonce))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}()
	actualSig := token[idx+1:]
	return hmac.Equal([]byte(expectedSig), []byte(actualSig))
}
