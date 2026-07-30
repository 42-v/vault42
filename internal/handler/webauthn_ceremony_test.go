package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

const (
	wanfidoRPID   = "vault.test"
	wanfidoOrigin = "https://vault.test"

	wanfidoFlagUP = 0x01
	wanfidoFlagUV = 0x04
	wanfidoFlagAT = 0x40
)

// wanfidoAuthenticator is a software FIDO2 authenticator: an ES256 key plus a
// credential ID. It produces the attestation and assertion payloads a browser
// would post, so the handler runs against the real go-webauthn verifier instead
// of a stub. Without it every branch past FinishRegistration/FinishLogin is
// unreachable from a unit test.
type wanfidoAuthenticator struct {
	priv   *ecdsa.PrivateKey
	credID []byte
}

func newWanfidoAuthenticator(t *testing.T, credID string) *wanfidoAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate authenticator key: %v", err)
	}
	return &wanfidoAuthenticator{priv: priv, credID: []byte(credID)}
}

func wanfidoCBORHead(major byte, n uint64) []byte {
	mt := major << 5
	switch {
	case n < 24:
		return []byte{mt | byte(n)}
	case n < 1<<8:
		return []byte{mt | 24, byte(n)}
	default:
		return []byte{mt | 25, byte(n >> 8), byte(n)}
	}
}

func wanfidoCBORBytes(b []byte) []byte {
	return append(wanfidoCBORHead(2, uint64(len(b))), b...)
}

func wanfidoCBORText(s string) []byte {
	return append(wanfidoCBORHead(3, uint64(len(s))), s...)
}

// coseKey encodes the public key in the COSE_Key form an authenticator reports:
// kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y.
func (a *wanfidoAuthenticator) coseKey() []byte {
	x := a.priv.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.priv.PublicKey.Y.FillBytes(make([]byte, 32))

	out := []byte{0xa5}
	out = append(out, 0x01, 0x02)
	out = append(out, 0x03, 0x26)
	out = append(out, 0x20, 0x01)
	out = append(out, 0x21)
	out = append(out, wanfidoCBORBytes(x)...)
	out = append(out, 0x22)
	out = append(out, wanfidoCBORBytes(y)...)
	return out
}

func (a *wanfidoAuthenticator) authData(rpID string, flags byte, counter uint32, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))

	out := make([]byte, 0, 128)
	out = append(out, h[:]...)
	out = append(out, flags)

	var c [4]byte
	binary.BigEndian.PutUint32(c[:], counter)
	out = append(out, c[:]...)

	if attested {
		out = append(out, make([]byte, 16)...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(a.credID)))
		out = append(out, l[:]...)
		out = append(out, a.credID...)
		out = append(out, a.coseKey()...)
	}
	return out
}

func wanfidoClientData(t *testing.T, ceremony, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type":        ceremony,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return b
}

func wanfidoB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// attestationRequest builds the body of a registration/finish POST for the
// given challenge, using attestation format "none" as a platform authenticator
// configured for no attestation conveyance would.
func (a *wanfidoAuthenticator) attestationRequest(t *testing.T, challenge string, counter uint32) *http.Request {
	t.Helper()
	return a.attestationRequestWithFlags(t, challenge, counter, wanfidoFlagUP|wanfidoFlagUV|wanfidoFlagAT)
}

// attestationRequestWithFlags is attestationRequest with the authenticator data
// flags chosen by the caller, so a backup-eligible (synced) passkey can be
// enrolled as well as a device-bound one.
func (a *wanfidoAuthenticator) attestationRequestWithFlags(t *testing.T, challenge string, counter uint32, flags byte) *http.Request {
	t.Helper()

	clientData := wanfidoClientData(t, "webauthn.create", challenge, wanfidoOrigin)
	authData := a.authData(wanfidoRPID, flags, counter, true)

	att := []byte{0xa3}
	att = append(att, wanfidoCBORText("fmt")...)
	att = append(att, wanfidoCBORText("none")...)
	att = append(att, wanfidoCBORText("attStmt")...)
	att = append(att, 0xa0)
	att = append(att, wanfidoCBORText("authData")...)
	att = append(att, wanfidoCBORBytes(authData)...)

	body, err := json.Marshal(map[string]any{
		"id":    wanfidoB64(a.credID),
		"rawId": wanfidoB64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    wanfidoB64(clientData),
			"attestationObject": wanfidoB64(att),
		},
	})
	if err != nil {
		t.Fatalf("marshal attestation body: %v", err)
	}

	return httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/finish", strings.NewReader(string(body)))
}

// assertionRequest builds the body of a verify/finish POST, signing over
// authData || SHA-256(clientDataJSON) exactly as an authenticator does.
func (a *wanfidoAuthenticator) assertionRequest(t *testing.T, challenge string, counter uint32, flags byte, userHandle []byte) *http.Request {
	t.Helper()

	clientData := wanfidoClientData(t, "webauthn.get", challenge, wanfidoOrigin)
	authData := a.authData(wanfidoRPID, flags, counter, false)

	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	response := map[string]any{
		"clientDataJSON":    wanfidoB64(clientData),
		"authenticatorData": wanfidoB64(authData),
		"signature":         wanfidoB64(sig),
	}
	if len(userHandle) > 0 {
		response["userHandle"] = wanfidoB64(userHandle)
	}

	body, err := json.Marshal(map[string]any{
		"id":       wanfidoB64(a.credID),
		"rawId":    wanfidoB64(a.credID),
		"type":     "public-key",
		"response": response,
	})
	if err != nil {
		t.Fatalf("marshal assertion body: %v", err)
	}

	return httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", strings.NewReader(string(body)))
}

func newWanfidoWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wan, err := webauthn.New(&webauthn.Config{
		RPID:          wanfidoRPID,
		RPDisplayName: "Vault Test",
		RPOrigins:     []string{wanfidoOrigin},
	})
	if err != nil {
		t.Fatalf("create webauthn: %v", err)
	}
	return wan
}

func newWanfidoUserRepo() *mocks.MockUserRepo {
	return &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@vault.test", Roles: []string{"user"}}, nil
		},
	}
}

// wanfidoSessionCache holds the ceremony session the way the real cache does:
// Set stores it, GetAndDelete hands it over once.
type wanfidoSessionCache struct {
	mu    sync.Mutex
	store map[string]string
}

func newWanfidoSessionCache() *wanfidoSessionCache {
	return &wanfidoSessionCache{store: map[string]string{}}
}

func (c *wanfidoSessionCache) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store[key], nil
}

func (c *wanfidoSessionCache) Set(_ context.Context, key, value string, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = value
	return nil
}

func (c *wanfidoSessionCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, key)
	return nil
}

func (c *wanfidoSessionCache) GetAndDelete(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.store[key]
	delete(c.store, key)
	return v, nil
}

func (c *wanfidoSessionCache) SetIfNotExists(_ context.Context, key, value string, _ time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.store[key]; ok {
		return false, nil
	}
	c.store[key] = value
	return true, nil
}

func (c *wanfidoSessionCache) Increment(context.Context, string, time.Duration) (int64, error) {
	return 0, nil
}

func (c *wanfidoSessionCache) Exists(_ context.Context, key string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.store[key]
	return ok, nil
}

func (c *wanfidoSessionCache) Close() error { return nil }

// wanfidoRegistrationSession stores a registration challenge in the cache for
// the given user and returns it, mirroring what RegisterBegin would have left
// behind.
func wanfidoRegistrationSession(t *testing.T, wan *webauthn.WebAuthn, c *wanfidoSessionCache, userID string) string {
	t.Helper()

	wanUser := &model.WebAuthnUser{User: &model.User{ID: userID, Email: "user@vault.test"}}
	_, session, err := wan.BeginRegistration(wanUser)
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if err := c.Set(context.Background(), "webauthn_reg:"+userID, string(raw), time.Minute); err != nil {
		t.Fatalf("seed registration session: %v", err)
	}
	return session.Challenge
}

// wanfidoLoginSession stores an assertion challenge for the credentials the
// user actually owns, mirroring VerifyBegin.
func wanfidoLoginSession(t *testing.T, wan *webauthn.WebAuthn, c *wanfidoSessionCache, userID string, creds []*model.WebAuthnCredential) string {
	t.Helper()

	wanUser := &model.WebAuthnUser{
		User:        &model.User{ID: userID, Email: "user@vault.test"},
		Credentials: modelCredsToWebAuthn(creds),
	}
	_, session, err := wan.BeginLogin(wanUser)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if err := c.Set(context.Background(), "webauthn_auth:"+userID, string(raw), time.Minute); err != nil {
		t.Fatalf("seed login session: %v", err)
	}
	return session.Challenge
}

func newWanfidoAuthService(t *testing.T, tokens *mocks.MockRefreshTokenRepo, c *wanfidoSessionCache) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	return service.NewAuthService(
		newWanfidoUserRepo(), tokens, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, newTestAuditLogger(), nil, c, nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
}

// A completed registration ceremony must persist the credential the
// authenticator actually attested to, bound to the subject of the bearer token.
// The credential ID and public key are the only things that will ever
// authenticate this user again, so taking them from anywhere but the verified
// attestation (the request body carries an attacker-controlled "id" field too)
// would let a caller enrol a key they do not hold.
func TestWebAuthnRegisterFinish_PersistsAttestedCredentialBoundToTokenSubject(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "attested-credential-id")
	sessions := newWanfidoSessionCache()
	challenge := wanfidoRegistrationSession(t, wan, sessions, "user-1")

	var stored *model.WebAuthnCredential
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		CreateFn: func(_ context.Context, cred *model.WebAuthnCredential) error {
			stored = cred
			return nil
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	req := setAuthContext(auth.attestationRequest(t, challenge, 7), "user-1")
	rec := httptest.NewRecorder()

	h.RegisterFinish(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if stored == nil {
		t.Fatal("registration returned 200 without persisting a credential")
	}
	if string(stored.CredentialID) != "attested-credential-id" {
		t.Errorf("stored credential ID = %q, want the attested one", string(stored.CredentialID))
	}
	if string(stored.PublicKey) != string(auth.coseKey()) {
		t.Error("stored public key is not the one from the verified attestation")
	}
	if stored.UserID != "user-1" {
		t.Errorf("credential bound to %q, want the token subject", stored.UserID)
	}
	if stored.SignCount != 7 {
		t.Errorf("stored sign count = %d, want the attested 7", stored.SignCount)
	}
	if stored.ID == "" {
		t.Error("credential stored without a primary key")
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "webauthn_registered" {
		t.Errorf("status field = %q, want webauthn_registered", result["status"])
	}
}

// If the credential cannot be written, the ceremony must fail. Reporting
// success would leave the user believing a security key is enrolled while the
// server has no record of it, and the challenge has already been consumed.
func TestWebAuthnRegisterFinish_CredentialWriteFailureDeniesEnrolment(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "unwritable-credential")
	sessions := newWanfidoSessionCache()
	challenge := wanfidoRegistrationSession(t, wan, sessions, "user-1")

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		CreateFn: func(context.Context, *model.WebAuthnCredential) error {
			return errors.New("db down")
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	req := setAuthContext(auth.attestationRequest(t, challenge, 1), "user-1")
	rec := httptest.NewRecorder()

	h.RegisterFinish(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "webauthn_registered") {
		t.Error("enrolment reported as complete while the credential was never stored")
	}
	if strings.Contains(rec.Body.String(), "db down") {
		t.Error("storage error leaked to the client")
	}
}

// A successful assertion must write the new sign count back before the caller
// is told anything succeeded. The stored count is the only thing that lets the
// next assertion detect a cloned authenticator, so a stale count silently
// disarms clone detection.
func TestWebAuthnVerifyFinish_AdvancesStoredSignCount(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "assertion-credential")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: 4},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	var updatedID string
	var updatedCount int
	updates := 0
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateSignCountFn: func(_ context.Context, id string, count int) error {
			updates++
			updatedID, updatedCount = id, count
			return nil
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	req := setAuthContext(auth.assertionRequest(t, challenge, 9, wanfidoFlagUP|wanfidoFlagUV, nil), "user-1")
	rec := httptest.NewRecorder()

	h.VerifyFinish(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if updates != 1 {
		t.Fatalf("UpdateSignCount called %d times, want exactly 1", updates)
	}
	if updatedID != "cred-row-1" {
		t.Errorf("updated row %q, want cred-row-1", updatedID)
	}
	if updatedCount != 9 {
		t.Errorf("stored sign count = %d, want the asserted 9", updatedCount)
	}

	var result map[string]bool
	decodeResponse(t, rec, &result)
	if !result["verified"] {
		t.Error("a verified assertion did not report verified=true")
	}
}

// If the sign count cannot be persisted, the assertion must be refused. Letting
// it through would leave the stored counter behind the authenticator's, and
// every later replay of this assertion would pass clone detection unnoticed.
func TestWebAuthnVerifyFinish_SignCountWriteFailureDeniesAssertion(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "assertion-credential")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: 4},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateSignCountFn: func(context.Context, string, int) error {
			return errors.New("db down")
		},
	}

	tokens := &mocks.MockRefreshTokenRepo{}
	authSvc := newWanfidoAuthService(t, tokens, sessions)
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, authSvc, false)

	req := setChallengeContext(auth.assertionRequest(t, challenge, 9, wanfidoFlagUP|wanfidoFlagUV, nil), "user-1", "jti-signcount")
	rec := httptest.NewRecorder()

	h.VerifyFinish(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "access_token") || strings.Contains(body, "verified") {
		t.Errorf("assertion granted a session despite an unpersisted sign count: %s", body)
	}
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "refresh") {
			t.Error("a refresh cookie was set despite an unpersisted sign count")
		}
	}
}

// A sign count that does not move forward is what FIDO2 6.1.4.5 treats as
// evidence of a cloned authenticator. The assertion must be refused and every
// refresh-token family for the user revoked: if only this request were refused,
// the attacker's earlier sessions would survive.
func TestWebAuthnVerifyFinish_ClonedAuthenticatorRevokesSessionsAndDenies(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "cloned-credential")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: 12},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	signCountWrites := 0
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateSignCountFn: func(context.Context, string, int) error {
			signCountWrites++
			return nil
		},
	}

	revokedFor := ""
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(_ context.Context, userID string) error {
			revokedFor = userID
			return nil
		},
	}
	authSvc := newWanfidoAuthService(t, tokens, sessions)
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, authSvc, false)

	req := setChallengeContext(auth.assertionRequest(t, challenge, 12, wanfidoFlagUP|wanfidoFlagUV, nil), "user-1", "jti-clone")
	rec := httptest.NewRecorder()

	h.VerifyFinish(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "cloned_authenticator_detected" {
		t.Errorf("error = %q, want cloned_authenticator_detected", result["error"])
	}
	if revokedFor != "user-1" {
		t.Errorf("RevokeAllTokensForUser called for %q, want user-1", revokedFor)
	}
	if signCountWrites != 0 {
		t.Error("a cloned assertion was allowed to move the stored sign count")
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("a cloned authenticator was issued a session")
	}
}

// When the bearer token is a 2FA challenge, a verified assertion completes the
// login and hands back real tokens. The refresh token belongs in a cookie, not
// only in the body, and the challenge response must not be mistaken for the
// bare verified=true reply of the enrolled-device flow.
func TestWebAuthnVerifyFinish_CompletesMFAChallenge(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "mfa-credential")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: 1},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
	}
	authSvc := newWanfidoAuthService(t, &mocks.MockRefreshTokenRepo{}, sessions)
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, authSvc, false)

	req := setChallengeContext(auth.assertionRequest(t, challenge, 5, wanfidoFlagUP|wanfidoFlagUV, nil), "user-1", "jti-mfa")
	rec := httptest.NewRecorder()

	h.VerifyFinish(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	decodeResponse(t, rec, &result)
	if token, _ := result["access_token"].(string); token == "" {
		t.Fatalf("challenge completion issued no access token; body: %s", rec.Body.String())
	}
	if _, ok := result["verified"]; ok {
		t.Error("challenge completion fell through to the verified=true reply")
	}

	found := false
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "refresh") {
			found = true
		}
	}
	if !found {
		t.Error("challenge completion did not set a refresh cookie")
	}
}

// An assertion signed by a key the user does not own must be refused even when
// it is otherwise well formed and answers the live challenge. This is the
// credential-substitution case: without it, anyone holding any authenticator
// could clear another account's second factor.
func TestWebAuthnVerifyFinish_ForeignCredentialIsRefused(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	owned := newWanfidoAuthenticator(t, "owned-credential")
	attacker := newWanfidoAuthenticator(t, "attacker-credential")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: owned.credID, PublicKey: owned.coseKey(), SignCount: 1},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	signCountWrites := 0
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateSignCountFn: func(context.Context, string, int) error {
			signCountWrites++
			return nil
		},
	}
	authSvc := newWanfidoAuthService(t, &mocks.MockRefreshTokenRepo{}, sessions)
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, authSvc, false)

	req := setChallengeContext(attacker.assertionRequest(t, challenge, 9, wanfidoFlagUP|wanfidoFlagUV, nil), "user-1", "jti-foreign")
	rec := httptest.NewRecorder()

	h.VerifyFinish(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body.String())
	}
	if signCountWrites != 0 {
		t.Error("a foreign credential moved the stored sign count")
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("a foreign credential completed the second factor")
	}
}
