package services

import (
	"database/sql"

	"github.com/totorospirit/gate/internal/models"
)

type AuditService struct {
	db *sql.DB
}

func NewAuditService(db *sql.DB) *AuditService {
	return &AuditService{db: db}
}

func (s *AuditService) Log(action, codeName, ip, userAgent, details string) {
	_, _ = s.db.Exec(
		`INSERT INTO audit_log (action, code_name, ip, user_agent, details) VALUES (?, ?, ?, ?, ?)`,
		action, codeName, ip, userAgent, details,
	)
}

func (s *AuditService) Recent(limit int) ([]models.AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, action, code_name, ip, user_agent, details, created_at
		 FROM audit_log ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.AuditEntry
	for rows.Next() {
		var e models.AuditEntry
		if err := rows.Scan(&e.ID, &e.Action, &e.CodeName, &e.IP, &e.UserAgent, &e.Details, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (s *AuditService) Count() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&count)
	return count, err
}
