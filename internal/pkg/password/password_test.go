package password

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	const secret = "correct-horse-battery-staple"

	hash, err := Hash(secret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("hash %q is not bcrypt", hash)
	}
	if !Verify(hash, secret) {
		t.Error("the correct password was rejected")
	}
	if Verify(hash, secret+"x") {
		t.Error("a wrong password was accepted")
	}
	if Verify("not-a-hash", secret) {
		t.Error("a malformed hash was accepted")
	}
	if Verify("", secret) {
		t.Error("an empty hash was accepted")
	}
}

func TestHashIsSalted(t *testing.T) {
	first, err := Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	second, err := Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if first == second {
		t.Error("two hashes of the same password are identical: the salt is missing")
	}
}

func TestNeedsRehash(t *testing.T) {
	hash, err := Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if NeedsRehash(hash) {
		t.Error("a fresh hash at the current cost should not need rehashing")
	}
	if !NeedsRehash("") {
		t.Error("an empty hash must be rehashed")
	}
	if !NeedsRehash("$2a$04$abcdefghijklmnopqrstuv") {
		t.Error("a hash with a lower cost must be rehashed")
	}
	weak := strings.Replace(hash, "$2a$12$", "$2a$10$", 1)
	if !NeedsRehash(weak) {
		t.Error("a cost-10 hash must be rehashed")
	}
}

func TestValidatePolicy(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"short", "short", true},
		{"minimum length", strings.Repeat("a", MinLength), false},
		{"at the bcrypt limit", strings.Repeat("a", MaxLength), false},
		{"above the bcrypt limit", strings.Repeat("a", MaxLength+1), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.password)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHashRejectsOverlongPassword(t *testing.T) {
	if _, err := Hash(strings.Repeat("a", MaxLength+1)); err == nil {
		t.Fatal("bcrypt would silently truncate this password; the hash must fail instead")
	}
}

func TestVerifyDummyDoesNotPanic(t *testing.T) {
	VerifyDummy("anything")
	VerifyDummy(strings.Repeat("a", MaxLength*2))
}
