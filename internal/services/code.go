package services

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/totorospirit/gate/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type CodeService struct {
	db *sql.DB
}

func NewCodeService(db *sql.DB) *CodeService {
	return &CodeService{db: db}
}

func (s *CodeService) Create(name, plainCode, role string, expiresAt *time.Time, maxUses *int) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainCode), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing code: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO access_codes (name, hash, role, expires_at, max_uses) VALUES (?, ?, ?, ?, ?)`,
		name, string(hash), role, expiresAt, maxUses,
	)
	if err != nil {
		return fmt.Errorf("inserting code: %w", err)
	}
	return nil
}

func (s *CodeService) Validate(plainCode string) (*models.AccessCode, error) {
	rows, err := s.db.Query(
		`SELECT id, name, hash, role, expires_at, max_uses, use_count, active, created_at
		 FROM access_codes WHERE active = 1`,
	)
	if err != nil {
		return nil, fmt.Errorf("querying codes: %w", err)
	}
	defer rows.Close()

	var codes []models.AccessCode
	for rows.Next() {
		var code models.AccessCode
		if err := rows.Scan(
			&code.ID, &code.Name, &code.Hash, &code.Role,
			&code.ExpiresAt, &code.MaxUses, &code.UseCount,
			&code.Active, &code.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning code: %w", err)
		}
		codes = append(codes, code)
	}
	rows.Close()

	for _, code := range codes {
		if err := bcrypt.CompareHashAndPassword([]byte(code.Hash), []byte(plainCode)); err != nil {
			continue
		}

		if code.ExpiresAt != nil && code.ExpiresAt.Before(time.Now()) {
			return nil, fmt.Errorf("expired")
		}
		if code.MaxUses != nil && code.UseCount >= *code.MaxUses {
			return nil, fmt.Errorf("max_uses")
		}

		// Increment use count
		_, _ = s.db.Exec(`UPDATE access_codes SET use_count = use_count + 1 WHERE id = ?`, code.ID)
		return &code, nil
	}
	return nil, fmt.Errorf("invalid")
}

func (s *CodeService) List() ([]models.AccessCode, error) {
	rows, err := s.db.Query(
		`SELECT id, name, hash, role, expires_at, max_uses, use_count, active, created_at
		 FROM access_codes ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var codes []models.AccessCode
	for rows.Next() {
		var c models.AccessCode
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Hash, &c.Role,
			&c.ExpiresAt, &c.MaxUses, &c.UseCount,
			&c.Active, &c.CreatedAt,
		); err != nil {
			return nil, err
		}
		codes = append(codes, c)
	}
	return codes, nil
}

func (s *CodeService) Revoke(id int64) error {
	_, err := s.db.Exec(`UPDATE access_codes SET active = 0 WHERE id = ?`, id)
	return err
}

func (s *CodeService) GetByID(id int64) (*models.AccessCode, error) {
	var c models.AccessCode
	err := s.db.QueryRow(
		`SELECT id, name, hash, role, expires_at, max_uses, use_count, active, created_at
		 FROM access_codes WHERE id = ?`, id,
	).Scan(&c.ID, &c.Name, &c.Hash, &c.Role, &c.ExpiresAt, &c.MaxUses, &c.UseCount, &c.Active, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *CodeService) Count() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM access_codes WHERE active = 1`).Scan(&count)
	return count, err
}

func (s *CodeService) EnsureAdminCode(adminCode string) error {
	if adminCode == "" {
		return nil
	}

	count, err := s.Count()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil // Codes already exist, skip initial setup
	}

	return s.Create("Admin", adminCode, "admin", nil, nil)
}
