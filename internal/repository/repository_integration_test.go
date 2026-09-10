//go:build integration

// Integration tests exercise the repositories against a real Postgres and Redis.
// They are opt-in:
//
//	make test-integration
//	# or
//	TEST_DATABASE_URL=... TEST_REDIS_ADDR=... go test -tags=integration ./internal/repository/...
//
// The tests never touch pre-existing rows: every record they create carries a
// unique marker and is removed again.
package repository

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"iam-service/internal/config"
	"iam-service/internal/model"
)

func testPostgres(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pg, err := NewPostgres(context.Background(), config.DatabaseConfig{
		DSN:             dsn,
		MaxConns:        4,
		MinConns:        1,
		MaxConnLifetime: time.Minute,
		MaxConnIdleTime: time.Minute,
		ConnectTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to postgres: %v", err)
	}
	t.Cleanup(pg.Close)
	return pg
}

func testRedis(t *testing.T) *Redis {
	t.Helper()
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR is not set")
	}
	rdb, err := NewRedis(context.Background(), config.RedisConfig{
		Addr:         addr,
		PoolSize:     4,
		MinIdleConns: 1,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func marker(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test-%d-%s", time.Now().UnixNano(), t.Name()[:min(8, len(t.Name()))])
}

func TestUserRepoLifecycle(t *testing.T) {
	pg := testPostgres(t)
	repo := NewUserRepo(pg)
	ctx := context.Background()

	id := marker(t)
	email := id + "@example.test"

	user, err := repo.Create(ctx, email, "Test User", "$2a$12$notarealhashnotarealhashnotarealhashnotarealhash")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _, _ = pg.Pool().Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID) })

	if user.Status != model.UserStatusActive {
		t.Errorf("status = %q, want active", user.Status)
	}

	// citext makes the lookup case-insensitive.
	byEmail, err := repo.ByEmail(ctx, strings.ToUpper(email))
	if err != nil {
		t.Fatalf("by email (uppercase): %v", err)
	}
	if byEmail.ID != user.ID {
		t.Errorf("lookup returned a different user")
	}

	if _, err := repo.ByEmail(ctx, id+"-missing@example.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user error = %v, want ErrNotFound", err)
	}

	// A duplicate email must be reported as a conflict, not as a generic error.
	if _, err := repo.Create(ctx, email, "Duplicate", "hash"); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate create error = %v, want ErrConflict", err)
	}

	if err := repo.AssignRole(ctx, user.ID, model.RoleAdmin); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := repo.AssignRole(ctx, user.ID, model.RoleAdmin); err != nil {
		t.Fatalf("assigning the same role twice must be idempotent: %v", err)
	}
	roles, err := repo.Roles(ctx, user.ID)
	if err != nil {
		t.Fatalf("roles: %v", err)
	}
	if len(roles) != 1 || roles[0] != model.RoleAdmin {
		t.Errorf("roles = %v, want [admin]", roles)
	}
}

func TestUserRepoFailureCountingAndLockout(t *testing.T) {
	pg := testPostgres(t)
	repo := NewUserRepo(pg)
	ctx := context.Background()

	email := marker(t) + "@example.test"
	user, err := repo.Create(ctx, email, "Lock Test", "$2a$12$notarealhashnotarealhashnotarealhashnotarealhash")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _, _ = pg.Pool().Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID) })

	const threshold = 3
	lockFor := 15 * time.Minute

	for attempt := 1; attempt <= threshold; attempt++ {
		locked, until, err := repo.RecordFailedLogin(ctx, user.ID, threshold, lockFor)
		if err != nil {
			t.Fatalf("record failed login %d: %v", attempt, err)
		}
		if attempt < threshold && locked {
			t.Fatalf("the account locked after %d attempts, expected %d", attempt, threshold)
		}
		if attempt == threshold {
			if !locked {
				t.Fatalf("the account did not lock after %d attempts", threshold)
			}
			if time.Until(until) < lockFor-time.Minute {
				t.Errorf("lockout ends in %s, expected about %s", time.Until(until), lockFor)
			}
		}
	}

	current, err := repo.ByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if current.Status != model.UserStatusLocked {
		t.Errorf("status = %q, want locked", current.Status)
	}
	if !current.IsLocked(time.Now()) {
		t.Error("IsLocked should report an active lockout")
	}
	if current.LockedFor(time.Now()) <= 0 {
		t.Error("LockedFor should return a positive remaining duration")
	}

	if err := repo.ResetFailedLogins(ctx, user.ID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	afterReset, err := repo.ByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload after reset: %v", err)
	}
	if afterReset.Status != model.UserStatusActive || afterReset.LockedUntil != nil || afterReset.FailedLogins != 0 {
		t.Errorf("reset left status=%q locked=%v failed=%d", afterReset.Status, afterReset.LockedUntil, afterReset.FailedLogins)
	}
}

func TestSessionRepoLifecycle(t *testing.T) {
	rdb := testRedis(t)
	repo := NewSessionRepo(rdb)
	ctx := context.Background()

	userID := "00000000-0000-0000-0000-0000000000" + fmt.Sprintf("%02d", time.Now().Unix()%100)
	t.Cleanup(func() { _, _ = repo.DeleteAllSessions(ctx, userID) })

	now := time.Now()
	first := &model.Session{
		ID: "sid-first-" + marker(t), UserID: userID, ClientID: "erplite-spa", FamilyID: "fam-1",
		Scope: "openid", AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	second := &model.Session{
		ID: "sid-second-" + marker(t), UserID: userID, ClientID: "erplite-spa", FamilyID: "fam-2",
		Scope: "openid", AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(2 * time.Hour),
	}
	for _, session := range []*model.Session{first, second} {
		if err := repo.SaveSession(ctx, session, time.Hour); err != nil {
			t.Fatalf("save session: %v", err)
		}
	}

	loaded, err := repo.GetSession(ctx, first.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if loaded.UserID != userID || loaded.FamilyID != "fam-1" {
		t.Errorf("loaded session = %+v", loaded)
	}

	if _, err := repo.GetSession(ctx, "sid-does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing session error = %v, want ErrNotFound", err)
	}

	sessions, err := repo.ListSessions(ctx, userID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("listed %d sessions, want 2", len(sessions))
	}
	// Newest expiry first.
	if sessions[0].ID != second.ID {
		t.Errorf("sessions are not ordered by expiry: %s first", sessions[0].ID)
	}

	// Deleting a session must also clean the user index.
	if err := repo.DeleteSession(ctx, first.ID); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if err := repo.DeleteSession(ctx, first.ID); err != nil {
		t.Fatalf("deleting twice must be idempotent: %v", err)
	}
	sessions, err = repo.ListSessions(ctx, userID)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != second.ID {
		t.Fatalf("the index still references a deleted session: %+v", sessions)
	}

	revoked, err := repo.DeleteAllSessions(ctx, userID)
	if err != nil {
		t.Fatalf("delete all: %v", err)
	}
	if revoked != 1 {
		t.Errorf("revoked %d sessions, want 1", revoked)
	}
	sessions, err = repo.ListSessions(ctx, userID)
	if err != nil {
		t.Fatalf("list after delete all: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("%d sessions survived logout-all", len(sessions))
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	repo := NewSessionRepo(testRedis(t))
	ctx := context.Background()

	code := "code-" + marker(t)
	payload := &model.AuthorizationCode{
		ClientID: "erplite-spa", UserID: "user-1", RedirectURI: "http://localhost:3000/callback",
		Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256",
		AuthTime: time.Now(), IssuedAt: time.Now(),
	}
	if err := repo.SaveCode(ctx, code, payload, time.Minute); err != nil {
		t.Fatalf("save code: %v", err)
	}

	// The value is never stored in clear text.
	keys, err := repo.r.client.Keys(ctx, key("code", "*")).Result()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	for _, k := range keys {
		if k == key("code", code) {
			t.Fatalf("the code is stored verbatim under %s", k)
		}
	}

	consumed, err := repo.ConsumeCode(ctx, code)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.ClientID != payload.ClientID || consumed.CodeChallenge != payload.CodeChallenge {
		t.Errorf("consumed payload = %+v", consumed)
	}

	if _, err := repo.ConsumeCode(ctx, code); !errors.Is(err, ErrNotFound) {
		t.Errorf("second consumption error = %v, want ErrNotFound", err)
	}
}

func TestRefreshFamilyState(t *testing.T) {
	repo := NewSessionRepo(testRedis(t))
	ctx := context.Background()

	family := "family-" + marker(t)
	sessionID := "sid-" + marker(t)
	firstHash := HashToken("refresh-one")
	secondHash := HashToken("refresh-two")

	if err := repo.SetRefreshState(ctx, family, RefreshState{Hash: firstHash, SessionID: sessionID}, time.Hour); err != nil {
		t.Fatalf("set state: %v", err)
	}
	if err := repo.SetRefreshTokenIndex(ctx, firstHash, family, time.Hour); err != nil {
		t.Fatalf("set index: %v", err)
	}

	state, err := repo.GetRefreshState(ctx, family)
	if err != nil {
		t.Fatalf("get state: %v", err)
	}
	if state.Hash != firstHash || state.SessionID != sessionID {
		t.Errorf("state = %+v", state)
	}

	found, err := repo.GetRefreshTokenIndex(ctx, firstHash)
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	if found != family {
		t.Errorf("index = %q, want %q", found, family)
	}

	// Rotate: the old hash becomes "used", the family points at the new one.
	if err := repo.MarkRefreshUsed(ctx, firstHash, family, time.Hour); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	if err := repo.SetRefreshState(ctx, family, RefreshState{Hash: secondHash, SessionID: sessionID}, time.Hour); err != nil {
		t.Fatalf("rotate state: %v", err)
	}
	usedFamily, err := repo.GetRefreshUsed(ctx, firstHash)
	if err != nil {
		t.Fatalf("get used: %v", err)
	}
	if usedFamily != family {
		t.Errorf("used family = %q", usedFamily)
	}

	pair := &model.TokenPair{AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 600}
	if err := repo.SaveRefreshReplay(ctx, firstHash, pair, time.Minute); err != nil {
		t.Fatalf("save replay: %v", err)
	}
	replayed, err := repo.GetRefreshReplay(ctx, firstHash)
	if err != nil {
		t.Fatalf("get replay: %v", err)
	}
	if replayed.AccessToken != pair.AccessToken {
		t.Errorf("replay = %+v", replayed)
	}

	if _, err := repo.GetRefreshReplay(ctx, HashToken("never-seen")); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing replay error = %v, want ErrNotFound", err)
	}

	if err := repo.DeleteRefreshFamily(ctx, family); err != nil {
		t.Fatalf("delete family: %v", err)
	}
	if _, err := repo.GetRefreshState(ctx, family); !errors.Is(err, ErrNotFound) {
		t.Errorf("a deleted family is still readable: %v", err)
	}
}

func TestInteractionLifecycle(t *testing.T) {
	repo := NewSessionRepo(testRedis(t))
	ctx := context.Background()

	id := "interaction-" + marker(t)
	interaction := &model.Interaction{
		ID: id, ClientID: "erplite-spa", RedirectURI: "http://localhost:3000/callback",
		Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256",
		CSRFToken: "csrf", CreatedAt: time.Now(),
	}
	if err := repo.SaveInteraction(ctx, id, interaction, time.Minute); err != nil {
		t.Fatalf("save interaction: %v", err)
	}

	loaded, err := repo.GetInteraction(ctx, id)
	if err != nil {
		t.Fatalf("get interaction: %v", err)
	}
	if loaded.CSRFToken != "csrf" || loaded.ClientID != "erplite-spa" {
		t.Errorf("interaction = %+v", loaded)
	}
	if loaded.AuthenticatedUserID != "" {
		t.Errorf("a fresh interaction must not carry a user")
	}

	// The login step records the authenticated user on the same interaction.
	loaded.AuthenticatedUserID = "user-42"
	if err := repo.SaveInteraction(ctx, id, loaded, time.Minute); err != nil {
		t.Fatalf("update interaction: %v", err)
	}
	updated, err := repo.GetInteraction(ctx, id)
	if err != nil {
		t.Fatalf("get updated interaction: %v", err)
	}
	if updated.AuthenticatedUserID != "user-42" {
		t.Errorf("user id = %q", updated.AuthenticatedUserID)
	}

	if err := repo.DeleteInteraction(ctx, id); err != nil {
		t.Fatalf("delete interaction: %v", err)
	}
	if _, err := repo.GetInteraction(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("a deleted interaction is still readable: %v", err)
	}
}

func TestRateLimitWindow(t *testing.T) {
	repo := NewRateLimitRepo(testRedis(t))
	ctx := context.Background()

	bucket := "test-bucket-" + marker(t)
	const limit = 3
	window := time.Minute
	t.Cleanup(func() { _ = repo.Reset(ctx, bucket) })

	for attempt := 1; attempt <= limit; attempt++ {
		result, err := repo.Allow(ctx, bucket, limit, window)
		if err != nil {
			t.Fatalf("allow %d: %v", attempt, err)
		}
		if !result.Allowed {
			t.Fatalf("attempt %d of %d was rejected", attempt, limit)
		}
		if result.Count != int64(attempt) {
			t.Errorf("count = %d, want %d", result.Count, attempt)
		}
	}

	blocked, err := repo.Allow(ctx, bucket, limit, window)
	if err != nil {
		t.Fatalf("allow over the limit: %v", err)
	}
	if blocked.Allowed {
		t.Fatal("the limiter allowed a request over the limit")
	}
	if blocked.RetryAfter <= 0 || blocked.RetryAfter > window {
		t.Errorf("RetryAfter = %s, want a value within %s", blocked.RetryAfter, window)
	}

	if err := repo.Reset(ctx, bucket); err != nil {
		t.Fatalf("reset: %v", err)
	}
	afterReset, err := repo.Allow(ctx, bucket, limit, window)
	if err != nil {
		t.Fatalf("allow after reset: %v", err)
	}
	if !afterReset.Allowed || afterReset.Count != 1 {
		t.Errorf("after reset count = %d allowed = %v", afterReset.Count, afterReset.Allowed)
	}
}

func TestRateLimitHandlesParallelBursts(t *testing.T) {
	repo := NewRateLimitRepo(testRedis(t))
	ctx := context.Background()

	bucket := "test-burst-" + marker(t)
	const limit = 5
	t.Cleanup(func() { _ = repo.Reset(ctx, bucket) })

	const workers = 20
	results := make(chan bool, workers)
	for i := 0; i < workers; i++ {
		go func() {
			result, err := repo.Allow(ctx, bucket, limit, time.Minute)
			results <- err == nil && result.Allowed
		}()
	}

	allowed := 0
	for i := 0; i < workers; i++ {
		if <-results {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("%d of %d parallel requests were allowed, want exactly %d", allowed, workers, limit)
	}
}

func TestLockOwnership(t *testing.T) {
	repo := NewRateLimitRepo(testRedis(t))
	ctx := context.Background()

	name := "test-lock-" + marker(t)
	token, ok, err := repo.AcquireLock(ctx, name, time.Minute)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}

	if _, second, err := repo.AcquireLock(ctx, name, time.Minute); err != nil || second {
		t.Fatalf("a second holder acquired the lock: ok=%v err=%v", second, err)
	}

	// A wrong token must not release somebody else's lock.
	if err := repo.ReleaseLock(ctx, name, "another-owner"); err != nil {
		t.Fatalf("release with a wrong token: %v", err)
	}
	if _, ok, err := repo.AcquireLock(ctx, name, time.Minute); err != nil || ok {
		t.Fatalf("the lock was released by a foreign token: ok=%v err=%v", ok, err)
	}

	if err := repo.ReleaseLock(ctx, name, token); err != nil {
		t.Fatalf("release with the owner token: %v", err)
	}
	if _, ok, err := repo.AcquireLock(ctx, name, time.Minute); err != nil || !ok {
		t.Fatalf("the lock is still held after a correct release: ok=%v err=%v", ok, err)
	}
	_ = repo.ReleaseLock(ctx, name, token)
}

func TestWaitForLockSerialises(t *testing.T) {
	repo := NewRateLimitRepo(testRedis(t))
	ctx := context.Background()

	name := "test-wait-" + marker(t)
	holder, ok, err := repo.AcquireLock(ctx, name, 300*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}

	start := time.Now()
	token, ok, err := repo.WaitForLock(ctx, name, time.Minute, 2*time.Second)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !ok {
		t.Fatal("WaitForLock gave up while the lock was about to expire")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("WaitForLock returned after %s, before the holder released the lock", elapsed)
	}
	if err := repo.ReleaseLock(ctx, name, token); err != nil {
		t.Fatalf("release: %v", err)
	}
	_ = repo.ReleaseLock(ctx, name, holder)
}

func TestUserStatusCache(t *testing.T) {
	repo := NewSessionRepo(testRedis(t))
	ctx := context.Background()

	userID := "cache-" + marker(t)
	if _, ok, err := repo.CachedUserStatus(ctx, userID); err != nil || ok {
		t.Fatalf("empty cache: ok=%v err=%v", ok, err)
	}

	if err := repo.CacheUserStatus(ctx, userID, model.UserStatusActive, time.Minute); err != nil {
		t.Fatalf("cache: %v", err)
	}
	status, ok, err := repo.CachedUserStatus(ctx, userID)
	if err != nil || !ok || status != model.UserStatusActive {
		t.Fatalf("cached status = %q ok=%v err=%v", status, ok, err)
	}

	if err := repo.DeleteUserStatus(ctx, userID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, err := repo.CachedUserStatus(ctx, userID); err != nil || ok {
		t.Fatalf("the status survived deletion: ok=%v err=%v", ok, err)
	}
}

func TestAuditRepoInsertAndRead(t *testing.T) {
	pg := testPostgres(t)
	repo := NewAuditRepo(pg, nil)
	ctx := context.Background()

	// auth_events.user_id references users, so the audit test creates its own user.
	users := NewUserRepo(pg)
	email := marker(t) + "@example.test"
	user, err := users.Create(ctx, email, "Audit Test", "$2a$12$notarealhashnotarealhashnotarealhashnotarealhash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pg.Pool().Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID) })

	event := model.NewAuthEvent(model.EventTokenIssued, true).
		WithUser(user.ID).
		WithClient("erplite-spa").
		WithSession("sid-1").
		WithIP(netip.MustParseAddr("203.0.113.7")).
		WithAgent("integration-test").
		WithRequest("req-1")
	if err := repo.Insert(ctx, event); err != nil {
		t.Fatalf("insert: %v", err)
	}

	records, err := repo.Recent(ctx, user.ID, 10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("read %d records, want 1", len(records))
	}
	record := records[0]
	if record.EventType != model.EventTokenIssued || !record.Success {
		t.Errorf("record = %+v", record)
	}
	if record.IP == nil || *record.IP != "203.0.113.7" {
		t.Errorf("ip = %v", record.IP)
	}

	// An event for an unknown user must not break the request path.
	orphan := model.NewAuthEvent(model.EventLoginFailure, false).WithError("unknown_account")
	if err := repo.Insert(ctx, orphan); err != nil {
		t.Fatalf("insert without a user: %v", err)
	}
	_, _ = pg.Pool().Exec(ctx, `DELETE FROM auth_events WHERE event_type = $1 AND request_id IS NULL AND created_at > now() - interval '1 minute'`, model.EventLoginFailure)
}
