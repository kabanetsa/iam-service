package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"iam-service/internal/model"
)

// SessionRepo keeps all short-lived authorization state in Redis: sessions,
// authorization codes, pending interactions, refresh-token families and the
// user status cache.
type SessionRepo struct {
	r *Redis
}

// NewSessionRepo builds the state store.
func NewSessionRepo(r *Redis) *SessionRepo { return &SessionRepo{r: r} }

// HashToken returns the hex SHA-256 of a token value. Tokens themselves are
// never stored, only their hashes.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *SessionRepo) sessionKey(sid string) string    { return key("session", sid) }
func (s *SessionRepo) userKey(userID string) string    { return key("user_sessions", userID) }
func (s *SessionRepo) codeKey(code string) string      { return key("code", HashToken(code)) }
func (s *SessionRepo) interactKey(id string) string    { return key("interaction", id) }
func (s *SessionRepo) refreshKey(fam string) string    { return key("rf", "current", fam) }
func (s *SessionRepo) refreshTokenKey(h string) string { return key("rf", "token", h) }
func (s *SessionRepo) refreshUsedKey(h string) string  { return key("rf", "used", h) }
func (s *SessionRepo) replayKey(h string) string       { return key("rf", "replay", h) }
func (s *SessionRepo) statusKey(uid string) string     { return key("userstatus", uid) }

// --- sessions ---------------------------------------------------------------

// SaveSession stores a session and indexes it under the owning user, so that
// "logout everywhere" and session listing stay cheap.
func (s *SessionRepo) SaveSession(ctx context.Context, session *model.Session, ttl time.Duration) error {
	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("repository: marshal session: %w", err)
	}
	pipe := s.r.client.TxPipeline()
	pipe.Set(ctx, s.sessionKey(session.ID), payload, ttl)
	pipe.ZAdd(ctx, s.userKey(session.UserID), redis.Z{Score: float64(session.ExpiresAt.Unix()), Member: session.ID})
	pipe.Expire(ctx, s.userKey(session.UserID), ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("repository: save session: %w", err)
	}
	return nil
}

// GetSession returns the session or ErrNotFound.
func (s *SessionRepo) GetSession(ctx context.Context, sid string) (*model.Session, error) {
	payload, err := s.r.client.Get(ctx, s.sessionKey(sid)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: get session: %w", err)
	}
	var session model.Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, fmt.Errorf("repository: unmarshal session: %w", err)
	}
	return &session, nil
}

// DeleteSession removes a session atomically together with its user index entry.
// A missing session is not an error: logout is idempotent.
func (s *SessionRepo) DeleteSession(ctx context.Context, sid string) error {
	// The script needs the user index key, which depends on the owner; resolve it
	// from the payload in a first pass, then delete with the correct keys.
	session, err := s.GetSession(ctx, sid)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	_, err = sessionDeleteScript.Run(ctx, s.r.client, []string{s.sessionKey(sid), s.userKey(session.UserID)}, sid).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("repository: delete session: %w", err)
	}
	return nil
}

// ListSessions returns live sessions of a user, newest expiry first. Expired
// index entries are pruned as a side effect.
func (s *SessionRepo) ListSessions(ctx context.Context, userID string) ([]*model.Session, error) {
	now := float64(time.Now().Unix())
	if err := s.r.client.ZRemRangeByScore(ctx, s.userKey(userID), "-inf", fmt.Sprintf("%f", now)).Err(); err != nil {
		return nil, fmt.Errorf("repository: prune session index: %w", err)
	}
	ids, err := s.r.client.ZRevRange(ctx, s.userKey(userID), 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("repository: list session index: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, s.sessionKey(id))
	}
	values, err := s.r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("repository: load sessions: %w", err)
	}

	sessions := make([]*model.Session, 0, len(values))
	for _, value := range values {
		raw, ok := value.(string)
		if !ok {
			continue
		}
		var session model.Session
		if err := json.Unmarshal([]byte(raw), &session); err != nil {
			continue
		}
		sessions = append(sessions, &session)
	}
	return sessions, nil
}

// DeleteSessions removes the given sessions and returns how many were removed.
func (s *SessionRepo) DeleteSessions(ctx context.Context, userID string, sids ...string) (int, error) {
	if len(sids) == 0 {
		return 0, nil
	}
	keys := make([]string, 0, len(sids))
	for _, sid := range sids {
		keys = append(keys, s.sessionKey(sid))
	}
	pipe := s.r.client.TxPipeline()
	deleted := 0
	for i, sid := range sids {
		pipe.Del(ctx, keys[i])
		member := redis.Z{Member: sid}
		pipe.ZRem(ctx, s.userKey(userID), member.Member)
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return 0, fmt.Errorf("repository: delete sessions: %w", err)
	}
	deleted = len(sids)
	return deleted, nil
}

// DeleteAllSessions of a user: used by "logout everywhere". It also drops the
// refresh families of the removed sessions.
func (s *SessionRepo) DeleteAllSessions(ctx context.Context, userID string) (int, error) {
	sessions, err := s.ListSessions(ctx, userID)
	if err != nil {
		return 0, err
	}
	if len(sessions) == 0 {
		return 0, nil
	}
	pipe := s.r.client.TxPipeline()
	for _, session := range sessions {
		pipe.Del(ctx, s.sessionKey(session.ID))
		if session.FamilyID != "" {
			pipe.Del(ctx, s.refreshKey(session.FamilyID))
		}
	}
	pipe.Del(ctx, s.userKey(userID))
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return 0, fmt.Errorf("repository: delete all sessions: %w", err)
	}
	return len(sessions), nil
}

// --- authorization codes ----------------------------------------------------

// SaveCode stores an authorization code under its hash.
func (s *SessionRepo) SaveCode(ctx context.Context, code string, payload *model.AuthorizationCode, ttl time.Duration) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("repository: marshal code: %w", err)
	}
	if err := s.r.client.Set(ctx, s.codeKey(code), data, ttl).Err(); err != nil {
		return fmt.Errorf("repository: save code: %w", err)
	}
	return nil
}

// ConsumeCode atomically reads and deletes a code (single use, RFC 6749 §4.1.2).
func (s *SessionRepo) ConsumeCode(ctx context.Context, code string) (*model.AuthorizationCode, error) {
	payload, err := s.r.client.GetDel(ctx, s.codeKey(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: consume code: %w", err)
	}
	var stored model.AuthorizationCode
	if err := json.Unmarshal(payload, &stored); err != nil {
		return nil, fmt.Errorf("repository: unmarshal code: %w", err)
	}
	return &stored, nil
}

// --- login/consent interactions --------------------------------------------

// SaveInteraction stores a pending /authorize request.
func (s *SessionRepo) SaveInteraction(ctx context.Context, id string, payload *model.Interaction, ttl time.Duration) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("repository: marshal interaction: %w", err)
	}
	if err := s.r.client.Set(ctx, s.interactKey(id), data, ttl).Err(); err != nil {
		return fmt.Errorf("repository: save interaction: %w", err)
	}
	return nil
}

// GetInteraction returns a pending interaction or ErrNotFound.
func (s *SessionRepo) GetInteraction(ctx context.Context, id string) (*model.Interaction, error) {
	payload, err := s.r.client.Get(ctx, s.interactKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: get interaction: %w", err)
	}
	var interaction model.Interaction
	if err := json.Unmarshal(payload, &interaction); err != nil {
		return nil, fmt.Errorf("repository: unmarshal interaction: %w", err)
	}
	return &interaction, nil
}

// DeleteInteraction drops a completed interaction.
func (s *SessionRepo) DeleteInteraction(ctx context.Context, id string) error {
	if err := s.r.client.Del(ctx, s.interactKey(id)).Err(); err != nil {
		return fmt.Errorf("repository: delete interaction: %w", err)
	}
	return nil
}

// --- refresh token families -------------------------------------------------

// RefreshState is the currently valid refresh token of a family, together with
// the session it belongs to.
type RefreshState struct {
	Hash      string `json:"hash"`
	SessionID string `json:"sid"`
}

// SetRefreshState records the valid refresh token hash of a family.
func (s *SessionRepo) SetRefreshState(ctx context.Context, familyID string, state RefreshState, ttl time.Duration) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("repository: marshal refresh state: %w", err)
	}
	if err := s.r.client.Set(ctx, s.refreshKey(familyID), payload, ttl).Err(); err != nil {
		return fmt.Errorf("repository: set refresh state: %w", err)
	}
	return nil
}

// GetRefreshState returns the current state of a family, or ErrNotFound when the
// family is unknown or revoked.
func (s *SessionRepo) GetRefreshState(ctx context.Context, familyID string) (*RefreshState, error) {
	payload, err := s.r.client.Get(ctx, s.refreshKey(familyID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: get refresh state: %w", err)
	}
	var state RefreshState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, fmt.Errorf("repository: unmarshal refresh state: %w", err)
	}
	return &state, nil
}

// SetRefreshTokenIndex maps a presented token hash to its family, which is how a
// refresh request finds its family without the token carrying any metadata.
func (s *SessionRepo) SetRefreshTokenIndex(ctx context.Context, hash, familyID string, ttl time.Duration) error {
	if err := s.r.client.Set(ctx, s.refreshTokenKey(hash), familyID, ttl).Err(); err != nil {
		return fmt.Errorf("repository: set refresh index: %w", err)
	}
	return nil
}

// GetRefreshTokenIndex returns the family owning the presented token hash.
func (s *SessionRepo) GetRefreshTokenIndex(ctx context.Context, hash string) (string, error) {
	family, err := s.r.client.Get(ctx, s.refreshTokenKey(hash)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("repository: get refresh index: %w", err)
	}
	return family, nil
}

// MarkRefreshUsed remembers that a hash was valid in the past, which is how a
// replayed token is recognised.
func (s *SessionRepo) MarkRefreshUsed(ctx context.Context, hash, familyID string, ttl time.Duration) error {
	if err := s.r.client.Set(ctx, s.refreshUsedKey(hash), familyID, ttl).Err(); err != nil {
		return fmt.Errorf("repository: mark refresh used: %w", err)
	}
	return nil
}

// GetRefreshUsed returns the family a previously used hash belonged to.
func (s *SessionRepo) GetRefreshUsed(ctx context.Context, hash string) (string, error) {
	family, err := s.r.client.Get(ctx, s.refreshUsedKey(hash)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("repository: get refresh used: %w", err)
	}
	return family, nil
}

// SaveRefreshReplay caches the token pair produced by a rotation, so a client
// that retries the same request within the grace window gets the same answer
// instead of tripping reuse detection.
func (s *SessionRepo) SaveRefreshReplay(ctx context.Context, hash string, pair *model.TokenPair, ttl time.Duration) error {
	data, err := json.Marshal(pair)
	if err != nil {
		return fmt.Errorf("repository: marshal replay: %w", err)
	}
	if err := s.r.client.Set(ctx, s.replayKey(hash), data, ttl).Err(); err != nil {
		return fmt.Errorf("repository: save replay: %w", err)
	}
	return nil
}

// GetRefreshReplay returns a cached rotation result.
func (s *SessionRepo) GetRefreshReplay(ctx context.Context, hash string) (*model.TokenPair, error) {
	payload, err := s.r.client.Get(ctx, s.replayKey(hash)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: get replay: %w", err)
	}
	var pair model.TokenPair
	if err := json.Unmarshal(payload, &pair); err != nil {
		return nil, fmt.Errorf("repository: unmarshal replay: %w", err)
	}
	return &pair, nil
}

// DeleteRefreshFamily invalidates a family, so any of its tokens stops working.
func (s *SessionRepo) DeleteRefreshFamily(ctx context.Context, familyID string) error {
	if err := s.r.client.Del(ctx, s.refreshKey(familyID)).Err(); err != nil {
		return fmt.Errorf("repository: delete refresh family: %w", err)
	}
	return nil
}

// --- user status cache ------------------------------------------------------

// CacheUserStatus stores a user status with a short TTL, so /verify does not hit
// Postgres on every proxied request.
func (s *SessionRepo) CacheUserStatus(ctx context.Context, userID, status string, ttl time.Duration) error {
	if err := s.r.client.Set(ctx, s.statusKey(userID), status, ttl).Err(); err != nil {
		return fmt.Errorf("repository: cache user status: %w", err)
	}
	return nil
}

// CachedUserStatus returns the cached status and whether it was present.
func (s *SessionRepo) CachedUserStatus(ctx context.Context, userID string) (string, bool, error) {
	status, err := s.r.client.Get(ctx, s.statusKey(userID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("repository: get cached user status: %w", err)
	}
	return status, true, nil
}

// DeleteUserStatus drops the cached status of a user.
func (s *SessionRepo) DeleteUserStatus(ctx context.Context, userID string) error {
	if err := s.r.client.Del(ctx, s.statusKey(userID)).Err(); err != nil {
		return fmt.Errorf("repository: delete cached user status: %w", err)
	}
	return nil
}
