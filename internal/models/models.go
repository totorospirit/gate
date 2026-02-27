package models

import "time"

type AccessCode struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Hash      string     `json:"-"`
	Role      string     `json:"role"` // "admin" or "user"
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	MaxUses   *int       `json:"max_uses,omitempty"`
	UseCount  int        `json:"use_count"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
}

type Session struct {
	ID        string    `json:"id"`
	CodeName  string    `json:"code_name"`
	Role      string    `json:"role"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AuditEntry struct {
	ID        int64     `json:"id"`
	Action    string    `json:"action"` // "login_success", "login_failed", "logout", "code_created", "code_revoked", "session_revoked"
	CodeName  string    `json:"code_name,omitempty"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Details   string    `json:"details,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Settings struct {
	AppName      string `json:"app_name"`
	LogoURL      string `json:"logo_url"`
	CookieDomain string `json:"cookie_domain"`
	SessionTTL   string `json:"session_ttl"`
}
