package handlers

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/totorospirit/gate/internal/config"
	"github.com/totorospirit/gate/internal/i18n"
	"github.com/totorospirit/gate/internal/services"
)

type AuthHandler struct {
	cfg      *config.Config
	codes    *services.CodeService
	sessions *services.SessionService
	audit    *services.AuditService
	limiter  *RateLimiter
	tmpl     map[string]*template.Template
}

func NewAuthHandler(
	cfg *config.Config,
	codes *services.CodeService,
	sessions *services.SessionService,
	audit *services.AuditService,
	limiter *RateLimiter,
	tmpl map[string]*template.Template,
) *AuthHandler {
	return &AuthHandler{
		cfg:      cfg,
		codes:    codes,
		sessions: sessions,
		audit:    audit,
		limiter:  limiter,
		tmpl:     tmpl,
	}
}

func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	// If already authenticated, redirect
	if sess := GetSession(r); sess != nil {
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			if sess.Role == "admin" {
				redirect = "/admin"
			} else {
				redirect = "/"
			}
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	msgs := i18n.Get(r.Header.Get("Accept-Language"))
	h.renderLogin(w, r, msgs, "", "")
}

func (h *AuthHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	ip := ClientIP(r, h.cfg.TrustedProxies)
	ua := r.UserAgent()
	msgs := i18n.Get(r.Header.Get("Accept-Language"))
	redirect := r.FormValue("redirect")
	code := r.FormValue("code")

	// Check lockout
	if h.limiter.IsLocked(ip) {
		h.audit.Log("login_locked", "", ip, ua, "IP locked out")
		h.renderLogin(w, r, msgs, msgs.LoginLocked, redirect)
		return
	}

	// Check rate limit
	if !h.limiter.Allow(ip) {
		h.audit.Log("login_rate_limited", "", ip, ua, "Rate limited")
		h.renderLogin(w, r, msgs, msgs.LoginRateLimited, redirect)
		return
	}

	// Validate code
	accessCode, err := h.codes.Validate(code)
	if err != nil {
		h.limiter.RecordFailure(ip)
		errMsg := msgs.LoginError
		switch err.Error() {
		case "expired":
			errMsg = msgs.LoginExpired
		case "max_uses":
			errMsg = msgs.LoginMaxUses
		}
		h.audit.Log("login_failed", "", ip, ua, err.Error())
		h.renderLogin(w, r, msgs, errMsg, redirect)
		return
	}

	// Create session
	sess, err := h.sessions.Create(accessCode.Name, accessCode.Role, ip, ua)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.audit.Log("login_success", accessCode.Name, ip, ua, "role="+accessCode.Role)
	SetSessionCookie(w, sess.ID, h.cfg)

	if redirect == "" || !isValidRedirect(redirect) {
		if accessCode.Role == "admin" {
			redirect = "/admin"
		} else {
			redirect = "/"
		}
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r)
	if sess != nil {
		ip := ClientIP(r, h.cfg.TrustedProxies)
		h.sessions.Delete(sess.ID)
		h.audit.Log("logout", sess.CodeName, ip, r.UserAgent(), "")
	}
	ClearSessionCookie(w, h.cfg)
	http.Redirect(w, r, h.cfg.BaseURL+"/login", http.StatusFound)
}

func (h *AuthHandler) LogoutGet(w http.ResponseWriter, r *http.Request) {
	h.Logout(w, r)
}

// Verify endpoints for reverse proxies

func (h *AuthHandler) VerifyGeneric(w http.ResponseWriter, r *http.Request) {
	if sess := GetSession(r); sess != nil {
		w.Header().Set("X-Gate-User", sess.CodeName)
		w.Header().Set("X-Gate-Role", sess.Role)
		w.WriteHeader(http.StatusOK)
		return
	}
	redirectToLogin(w, r, h.cfg, r.Header.Get("X-Forwarded-Uri"))
}

func (h *AuthHandler) VerifyTraefik(w http.ResponseWriter, r *http.Request) {
	if sess := GetSession(r); sess != nil {
		w.Header().Set("X-Gate-User", sess.CodeName)
		w.Header().Set("X-Gate-Role", sess.Role)
		w.WriteHeader(http.StatusOK)
		return
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	if proto == "" {
		proto = "https"
	}
	originalURL := proto + "://" + host + uri
	http.Redirect(w, r, h.cfg.BaseURL+"/login?redirect="+originalURL, http.StatusFound)
}

func (h *AuthHandler) VerifyCaddy(w http.ResponseWriter, r *http.Request) {
	if sess := GetSession(r); sess != nil {
		w.Header().Set("X-Gate-User", sess.CodeName)
		w.Header().Set("X-Gate-Role", sess.Role)
		w.WriteHeader(http.StatusOK)
		return
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	if proto == "" {
		proto = "https"
	}
	originalURL := proto + "://" + host + uri
	http.Redirect(w, r, h.cfg.BaseURL+"/login?redirect="+originalURL, http.StatusFound)
}

func (h *AuthHandler) VerifyNginx(w http.ResponseWriter, r *http.Request) {
	if sess := GetSession(r); sess != nil {
		w.Header().Set("X-Gate-User", sess.CodeName)
		w.Header().Set("X-Gate-Role", sess.Role)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func (h *AuthHandler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (h *AuthHandler) renderLogin(w http.ResponseWriter, r *http.Request, msgs *i18n.Messages, errMsg, redirect string) {
	if redirect == "" {
		redirect = r.URL.Query().Get("redirect")
	}

	data := map[string]interface{}{
		"Messages":  msgs,
		"Error":     errMsg,
		"Redirect":  redirect,
		"AppName":   h.cfg.AppName,
		"LogoURL":   h.cfg.LogoURL,
		"CSRFToken": GetCSRFToken(r),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if errMsg != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	h.tmpl["login.html"].ExecuteTemplate(w, "login.html", data)
}

func redirectToLogin(w http.ResponseWriter, r *http.Request, cfg *config.Config, uri string) {
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	http.Redirect(w, r, cfg.BaseURL+"/login?redirect="+uri, http.StatusFound)
}

func isValidRedirect(u string) bool {
	return strings.HasPrefix(u, "/") || strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}
