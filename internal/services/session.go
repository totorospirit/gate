package services

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/totorospirit/gate/internal/models"
)

type SessionService struct {
	db  *sql.DB
	ttl time.Duration
}

func NewSessionService(db *sql.DB, ttl time.Duration) *SessionService {
	return &SessionService{db: db, ttl: ttl}
}

func (s *SessionService) Create(codeName, role, ip, userAgent string) (*models.Session, error) {
	id, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(s.ttl)

	_, err = s.db.Exec(
		`INSERT INTO sessions (id, code_name, role, ip, user_agent, created_at, last_seen, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, codeName, role, ip, userAgent, now, now, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return &models.Session{
		ID:        id,
		CodeName:  codeName,
		Role:      role,
		IP:        ip,
		UserAgent: userAgent,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *SessionService) Get(id string) (*models.Session, error) {
	var sess models.Session
	err := s.db.QueryRow(
		`SELECT id, code_name, role, ip, user_agent, created_at, last_seen, expires_at
		 FROM sessions WHERE id = ? AND expires_at > ?`, id, time.Now(),
	).Scan(&sess.ID, &sess.CodeName, &sess.Role, &sess.IP, &sess.UserAgent,
		&sess.CreatedAt, &sess.LastSeen, &sess.ExpiresAt)
	if err != nil {
		return nil, err
	}

	// Update last_seen
	_, _ = s.db.Exec(`UPDATE sessions SET last_seen = ? WHERE id = ?`, time.Now(), id)

	return &sess, nil
}

func (s *SessionService) Delete(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *SessionService) List() ([]models.Session, error) {
	rows, err := s.db.Query(
		`SELECT id, code_name, role, ip, user_agent, created_at, last_seen, expires_at
		 FROM sessions WHERE expires_at > ? ORDER BY last_seen DESC`, time.Now(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		var sess models.Session
		if err := rows.Scan(
			&sess.ID, &sess.CodeName, &sess.Role, &sess.IP, &sess.UserAgent,
			&sess.CreatedAt, &sess.LastSeen, &sess.ExpiresAt,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

func (s *SessionService) ActiveCount() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE expires_at > ?`, time.Now()).Scan(&count)
	return count, err
}

func (s *SessionService) Cleanup() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, time.Now())
	return err
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}
