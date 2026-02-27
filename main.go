package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/totorospirit/gate/internal/config"
	"github.com/totorospirit/gate/internal/database"
	"github.com/totorospirit/gate/internal/handlers"
	"github.com/totorospirit/gate/internal/services"
)

//go:embed templates/*.html templates/admin/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

var version = "1.0.0"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := database.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Services
	codeSvc := services.NewCodeService(db)
	sessionSvc := services.NewSessionService(db, cfg.SessionTTL)
	auditSvc := services.NewAuditService(db)

	// Ensure initial admin code
	if err := codeSvc.EnsureAdminCode(cfg.AdminCode); err != nil {
		log.Fatalf("Failed to create initial admin code: %v", err)
	}

	// Parse templates — each page gets its own template set to avoid "content" block collision
	funcMap := template.FuncMap{
		"actionClass": actionClass,
		"truncate":    truncate,
		"deref":       derefInt,
	}
	tmpl := make(map[string]*template.Template)
	// Login page (standalone, no layout)
	tmpl["login.html"] = template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/login.html"))
	// Admin pages — each one gets layout + its own content
	adminPages := []string{"dashboard", "codes", "sessions", "audit", "settings"}
	for _, page := range adminPages {
		name := "admin_" + page + ".html"
		tmpl[name] = template.Must(
			template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/layout.html", "templates/admin/"+page+".html"),
		)
	}

	// Rate limiter
	limiter := handlers.NewRateLimiter(cfg.RateLimit, cfg.LockoutAfter, cfg.LockoutDuration)

	// Handlers
	authH := handlers.NewAuthHandler(cfg, codeSvc, sessionSvc, auditSvc, limiter, tmpl)
	adminH := handlers.NewAdminHandler(cfg, codeSvc, sessionSvc, auditSvc, tmpl)

	// Router
	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Compress(5))
	r.Use(handlers.SessionMiddleware(sessionSvc, cfg.CookieSecret))
	r.Use(handlers.CSRFMiddleware(cfg.CookieSecret))

	// Static files
	staticSub, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Health
	r.Get("/health", authH.Health)

	// Auth routes
	r.Get("/login", authH.LoginPage)
	r.Post("/login", authH.LoginSubmit)
	r.Post("/logout", authH.Logout)
	r.Get("/logout", authH.LogoutGet)

	// Verify endpoints for reverse proxies
	r.Get("/api/verify", authH.VerifyGeneric)
	r.Get("/api/verify/traefik", authH.VerifyTraefik)
	r.Get("/api/verify/caddy", authH.VerifyCaddy)
	r.Get("/api/verify/nginx", authH.VerifyNginx)

	// Admin routes (require admin role)
	r.Route("/admin", func(r chi.Router) {
		r.Use(handlers.RequireAdmin(cfg.BaseURL))
		r.Get("/", adminH.Dashboard)
		r.Get("/codes", adminH.Codes)
		r.Post("/codes/create", adminH.CreateCode)
		r.Post("/codes/revoke", adminH.RevokeCode)
		r.Get("/sessions", adminH.Sessions)
		r.Post("/sessions/revoke", adminH.RevokeSession)
		r.Get("/audit", adminH.AuditLog)
		r.Get("/settings", adminH.Settings)
	})

	// API stats (admin only)
	r.Route("/api", func(r chi.Router) {
		r.Use(handlers.RequireAdmin(cfg.BaseURL))
		r.Get("/stats", adminH.Stats)
	})

	// Root
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		sess := handlers.GetSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if sess.Role == "admin" {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authenticated</title><link rel="stylesheet" href="/static/style.css"></head><body class="login-body"><div class="login-container"><div class="login-card" style="text-align:center"><div class="login-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div><h1 style="font-size:1.25rem;font-weight:600;margin:1rem 0 .5rem">Authenticated</h1><p style="color:var(--text-muted);margin-bottom:1.5rem">Signed in as <strong>` + sess.CodeName + `</strong></p><a href="/logout" style="display:inline-block;padding:.5rem 1.5rem;background:var(--border);color:var(--text);border-radius:8px;text-decoration:none;font-size:.875rem">Sign out</a></div></div></body></html>`))
	})

	// Session cleanup ticker
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			sessionSvc.Cleanup()
		}
	}()

	// Start server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Gate %s starting on :%d", version, cfg.Port)
	log.Printf("Base URL: %s", cfg.BaseURL)

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-done
	log.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)

	log.Println("Bye.")
}

// Template helper functions

func actionClass(action string) string {
	return action
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
