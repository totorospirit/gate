package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/totorospirit/gate/internal/config"
	"github.com/totorospirit/gate/internal/services"
)

var startTime = time.Now()

type AdminHandler struct {
	cfg      *config.Config
	codes    *services.CodeService
	sessions *services.SessionService
	audit    *services.AuditService
	tmpl     map[string]*template.Template
}

func NewAdminHandler(
	cfg *config.Config,
	codes *services.CodeService,
	sessions *services.SessionService,
	audit *services.AuditService,
	tmpl map[string]*template.Template,
) *AdminHandler {
	return &AdminHandler{
		cfg:      cfg,
		codes:    codes,
		sessions: sessions,
		audit:    audit,
		tmpl:     tmpl,
	}
}

func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r)
	sessionCount, _ := h.sessions.ActiveCount()
	codeCount, _ := h.codes.Count()
	recentAudit, _ := h.audit.Recent(10)

	data := map[string]interface{}{
		"Session":      sess,
		"AppName":      h.cfg.AppName,
		"SessionCount": sessionCount,
		"CodeCount":    codeCount,
		"RecentAudit":  recentAudit,
		"Uptime":       time.Since(startTime).Round(time.Second).String(),
		"CSRFToken":    GetCSRFToken(r),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.tmpl["admin_dashboard.html"].ExecuteTemplate(w, "admin_dashboard.html", data)
}

func (h *AdminHandler) Codes(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r)
	codes, _ := h.codes.List()

	data := map[string]interface{}{
		"Session":   sess,
		"AppName":   h.cfg.AppName,
		"Codes":     codes,
		"CSRFToken": GetCSRFToken(r),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.tmpl["admin_codes.html"].ExecuteTemplate(w, "admin_codes.html", data)
}

func (h *AdminHandler) CreateCode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	code := r.FormValue("code")
	role := r.FormValue("role")
	if role != "admin" && role != "user" {
		role = "user"
	}

	var expiresAt *time.Time
	if exp := r.FormValue("expires_at"); exp != "" {
		t, err := time.Parse("2006-01-02T15:04", exp)
		if err == nil {
			expiresAt = &t
		}
	}

	var maxUses *int
	if mu := r.FormValue("max_uses"); mu != "" {
		if v, err := strconv.Atoi(mu); err == nil && v > 0 {
			maxUses = &v
		}
	}

	sess := GetSession(r)
	ip := ClientIP(r, h.cfg.TrustedProxies)

	if err := h.codes.Create(name, code, role, expiresAt, maxUses); err != nil {
		h.audit.Log("code_create_failed", name, ip, r.UserAgent(), err.Error())
		// Re-render with error via htmx
		if isHTMX(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<div class="alert alert-error">Failed to create code: ` + template.HTMLEscapeString(err.Error()) + `</div>`))
			return
		}
		http.Redirect(w, r, "/admin/codes", http.StatusFound)
		return
	}

	h.audit.Log("code_created", name, ip, r.UserAgent(), "role="+role+" by="+sess.CodeName)

	if isHTMX(r) {
		w.Header().Set("HX-Redirect", "/admin/codes")
		return
	}
	http.Redirect(w, r, "/admin/codes", http.StatusFound)
}

func (h *AdminHandler) RevokeCode(w http.ResponseWriter, r *http.Request) {
	idStr := r.FormValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	code, err := h.codes.GetByID(id)
	if err != nil {
		http.Error(w, "Code not found", http.StatusNotFound)
		return
	}

	sess := GetSession(r)
	ip := ClientIP(r, h.cfg.TrustedProxies)

	if err := h.codes.Revoke(id); err != nil {
		http.Error(w, "Failed to revoke", http.StatusInternalServerError)
		return
	}

	h.audit.Log("code_revoked", code.Name, ip, r.UserAgent(), "by="+sess.CodeName)

	if isHTMX(r) {
		w.Header().Set("HX-Redirect", "/admin/codes")
		return
	}
	http.Redirect(w, r, "/admin/codes", http.StatusFound)
}

func (h *AdminHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r)
	allSessions, _ := h.sessions.List()

	data := map[string]interface{}{
		"Session":     sess,
		"AppName":     h.cfg.AppName,
		"AllSessions": allSessions,
		"CSRFToken":   GetCSRFToken(r),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.tmpl["admin_sessions.html"].ExecuteTemplate(w, "admin_sessions.html", data)
}

func (h *AdminHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.FormValue("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	sess := GetSession(r)
	ip := ClientIP(r, h.cfg.TrustedProxies)

	if err := h.sessions.Delete(sessionID); err != nil {
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	h.audit.Log("session_revoked", "", ip, r.UserAgent(), "session="+sessionID[:8]+"... by="+sess.CodeName)

	if isHTMX(r) {
		w.Header().Set("HX-Redirect", "/admin/sessions")
		return
	}
	http.Redirect(w, r, "/admin/sessions", http.StatusFound)
}

func (h *AdminHandler) AuditLog(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r)
	entries, _ := h.audit.Recent(100)

	data := map[string]interface{}{
		"Session":   sess,
		"AppName":   h.cfg.AppName,
		"Entries":   entries,
		"CSRFToken": GetCSRFToken(r),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.tmpl["admin_audit.html"].ExecuteTemplate(w, "admin_audit.html", data)
}

func (h *AdminHandler) Settings(w http.ResponseWriter, r *http.Request) {
	sess := GetSession(r)

	data := map[string]interface{}{
		"Session":      sess,
		"AppName":      h.cfg.AppName,
		"LogoURL":      h.cfg.LogoURL,
		"CookieDomain": h.cfg.CookieDomain,
		"SessionTTL":   h.cfg.SessionTTL.String(),
		"BaseURL":      h.cfg.BaseURL,
		"CSRFToken":    GetCSRFToken(r),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.tmpl["admin_settings.html"].ExecuteTemplate(w, "admin_settings.html", data)
}

func (h *AdminHandler) Stats(w http.ResponseWriter, r *http.Request) {
	sessionCount, _ := h.sessions.ActiveCount()
	codeCount, _ := h.codes.Count()
	auditCount, _ := h.audit.Count()

	data := map[string]interface{}{
		"version":        "1.0.0",
		"uptime":         time.Since(startTime).Round(time.Second).String(),
		"active_sessions": sessionCount,
		"active_codes":   codeCount,
		"audit_entries":  auditCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}
