package repository

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"iam-service/internal/model"
)

// AuditRepo persists authentication events. Failures are logged but never
// propagated to callers: an audit outage must not break authentication.
type AuditRepo struct {
	pg     *Postgres
	logger *zap.Logger
}

// NewAuditRepo builds the audit repository.
func NewAuditRepo(pg *Postgres, logger *zap.Logger) *AuditRepo {
	return &AuditRepo{pg: pg, logger: logger}
}

// Insert writes one event.
func (r *AuditRepo) Insert(ctx context.Context, event *model.AuthEvent) error {
	if event == nil || event.EventType == "" {
		return nil
	}
	var ip any
	if event.IP.IsValid() {
		ip = event.IP.String()
	}
	_, err := r.pg.pool.Exec(ctx, `
		INSERT INTO auth_events (event_type, user_id, client_id, session_id, ip, user_agent,
		                         success, error_code, request_id)
		VALUES ($1, nullif($2, '')::uuid, nullif($3, ''), nullif($4, ''), $5, nullif($6, ''),
		        $7, nullif($8, ''), nullif($9, ''))`,
		event.EventType, event.UserID, event.ClientID, event.SessionID, ip, truncate(event.UserAgent, 512),
		event.Success, event.ErrorCode, event.RequestID,
	)
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("audit insert failed",
				zap.String("event_type", event.EventType),
				zap.String("error", err.Error()))
		}
		return fmt.Errorf("repository: insert audit event: %w", err)
	}
	return nil
}

// Recent returns the newest events of a user, newest first. It backs tests and
// the future admin API.
func (r *AuditRepo) Recent(ctx context.Context, userID string, limit int) ([]model.AuditRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := r.pg.pool.Query(ctx, `
		SELECT id, event_type, user_id::text, client_id, session_id, host(ip), user_agent,
		       success, error_code, request_id, created_at
		FROM auth_events
		WHERE user_id = nullif($1, '')::uuid
		ORDER BY created_at DESC
		LIMIT $2`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("repository: query audit events: %w", err)
	}
	defer rows.Close()

	var out []model.AuditRecord
	for rows.Next() {
		var rec model.AuditRecord
		if err := rows.Scan(&rec.ID, &rec.EventType, &rec.UserID, &rec.ClientID, &rec.SessionID,
			&rec.IP, &rec.UserAgent, &rec.Success, &rec.ErrorCode, &rec.RequestID, &rec.CreatedAt); err != nil {
			return nil, fmt.Errorf("repository: scan audit event: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
