package attack

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// This file used to open with a sanitizeBlobLabel of its own, a
// strings.NewReplacer described as "mirrors the sanitization logic from
// internal/handler/blob.go (Download handler, line 180)". Every test in it
// asserted on the copy. Production sanitizes with sanitizeLabelForHeader
// (blob.go:220 and :315), which drops every rune below U+0020 rather than CR and
// LF alone, and deleting it left this whole file green.
//
// The label a caller supplies is stored encrypted and comes back out on the
// X-Blob-Label response header, so the assertion that matters is on the header
// bytes the handler writes. Every test below uploads through the real
// BlobService and reads the header off the real Download handler behind the real
// auth middleware.

const blobLabelUserID = "00000000-0000-0000-0000-0000000000c1"

// blobLabelRoundTrip stores a blob carrying label and returns the X-Blob-Label
// header the download handler answered with.
func blobLabelRoundTrip(t *testing.T, label string) (http.Header, int) {
	t.Helper()

	var stored *model.Blob
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(context.Context, string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, b *model.Blob) error {
			stored = b
			return nil
		},
		GetByIDAndPseudonymFn: func(context.Context, string, string) (*model.Blob, error) {
			return stored, nil
		},
	}

	svc := service.NewBlobService(repo,
		[]byte("01234567890123456789012345678901"),
		[]byte("test-hmac-secret-key-32-bytes!!"),
		service.BlobConfig{MinBlobSize: 1, MaxBlobSize: 1 << 20, MaxBlobsPerUser: 10, QuotaBytes: 1 << 20},
	)

	blob, err := svc.Upload(context.Background(), blobLabelUserID, []byte("ciphertext-stand-in"), label)
	if err != nil {
		t.Fatalf("upload a blob labeled %q: %v", label, err)
	}
	if stored == nil {
		t.Fatal("the upload stored nothing, so the download has nothing to answer with")
	}

	h := handler.NewBlobHandler(svc, nil, 1, 1<<20)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate a signing key: %v", err)
	}
	const kid = "b1b1b1b1-c2c2-d3d3-e4e4-f5f5f5f5f5f5"
	now := time.Now()
	token, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "https://vault.test",
			Audience:  vjwt.ClaimStrings{"https://vault.test"},
			Subject:   blobLabelUserID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        "blob-label-jti",
		},
		Roles:     []string{"user"},
		TokenType: "Bearer",
	}, key, kid)
	if err != nil {
		t.Fatalf("sign an access token: %v", err)
	}

	mux := http.NewServeMux()
	authMW := middleware.Auth(map[string]*rsa.PublicKey{kid: &key.PublicKey},
		"https://vault.test", "https://vault.test")
	mux.Handle("GET /user/blobs/{id}", authMW(http.HandlerFunc(h.Download)))

	req := httptest.NewRequest(http.MethodGet, "/user/blobs/"+blob.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Header(), rec.Code
}

// requireHeaderIsSafe fails if the delivered header value carries anything a
// header value may not: net/http would refuse to write a CR or LF, and every
// other control character is what lets a label smuggle a field separator or
// truncate the value in a downstream parser.
func requireHeaderIsSafe(t *testing.T, value string) {
	t.Helper()
	for i, r := range value {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("the delivered X-Blob-Label carries control character %#U at index %d: %q",
				r, i, value)
		}
	}
}

// TestBlobLabel_CRLFInjection drives response-splitting payloads through the
// upload/download round trip and asserts nothing that could break the header
// block reaches the wire.
func TestBlobLabel_CRLFInjection(t *testing.T) {
	cases := []struct {
		name  string
		label string
		want  string
	}{
		{"bare CRLF", "file\r\nX-Injected: evil", "fileX-Injected: evil"},
		{"bare CR", "file\rX-Injected: evil", "fileX-Injected: evil"},
		{"bare LF", "file\nX-Injected: evil", "fileX-Injected: evil"},
		{"double CRLF (blank line)", "file\r\n\r\n<html>evil</html>", "file<html>evil</html>"},
		{"CRLF at start", "\r\nInjected-Header: value", "Injected-Header: value"},
		{"CRLF at end", "normal-label\r\n", "normal-label"},
		{"multiple CRLF", "a\r\nb\r\nc\r\n", "abc"},
		{"mixed CR and LF", "a\rb\nc\r\nd", "abcd"},
		{"set-cookie injection", "file\r\nSet-Cookie: admin=true\r\n", "fileSet-Cookie: admin=true"},
		{"location redirect", "file\r\nLocation: https://evil.com\r\n\r\n", "fileLocation: https://evil.com"},
		{
			"HTTP response forge", "file\r\n\r\nHTTP/1.1 200 OK\r\n\r\n<h1>pwned</h1>",
			"fileHTTP/1.1 200 OK<h1>pwned</h1>",
		},
		{"tab separator", "file\tX-Injected: evil", "fileX-Injected: evil"},
		{"vertical tab", "file\vX-Injected: evil", "fileX-Injected: evil"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header, code := blobLabelRoundTrip(t, tc.label)
			if code != http.StatusOK {
				t.Fatalf("download answered %d", code)
			}
			got := header.Get("X-Blob-Label")
			requireHeaderIsSafe(t, got)
			if got != tc.want {
				t.Fatalf("X-Blob-Label = %q, want %q", got, tc.want)
			}
			if len(header.Values("X-Blob-Label")) != 1 {
				t.Fatalf("the label produced %d X-Blob-Label headers", len(header.Values("X-Blob-Label")))
			}
			if _, injected := header["X-Injected"]; injected {
				t.Fatalf("the label added an X-Injected header to the response: %v", header)
			}
			if _, injected := header["Set-Cookie"]; injected {
				t.Fatalf("the label added a Set-Cookie header to the response: %v", header)
			}
		})
	}
}

// TestBlobLabel_NullBytes pins what the production sanitizer does with a NUL,
// which is drop it. The mirror this file used to assert on stripped only CR and
// LF, and its comment said a NUL "may pass through ... which is acceptable" —
// a statement about the copy, and untrue of the code that ships.
func TestBlobLabel_NullBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		label string
		want  string
	}{
		{"null byte mid-string", "before\x00after", "beforeafter"},
		{"null byte at start", "\x00label", "label"},
		{"null byte at end", "label\x00", "label"},
		{"null with CRLF", "label\x00\r\ninjected", "labelinjected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header, code := blobLabelRoundTrip(t, tc.label)
			if code != http.StatusOK {
				t.Fatalf("download answered %d", code)
			}
			got := header.Get("X-Blob-Label")
			requireHeaderIsSafe(t, got)
			if got != tc.want {
				t.Fatalf("X-Blob-Label = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBlobLabel_HTMLInJSON verifies markup in a label is not mangled. The label
// is returned as a raw header value and in a JSON body, neither of which renders
// HTML, so escaping it here would corrupt a legitimate filename for no gain. The
// sanitizer's job is control characters and nothing else.
func TestBlobLabel_HTMLInJSON(t *testing.T) {
	for _, payload := range []string{
		`<script>alert('xss')</script>`,
		`<img src=x onerror=alert(1)>`,
		`"><svg onload=alert(1)>`,
		`<iframe src="evil.com">`,
		`<b onmouseover=alert(1)>hover</b>`,
	} {
		t.Run(payload[:min(len(payload), 25)], func(t *testing.T) {
			header, code := blobLabelRoundTrip(t, payload)
			if code != http.StatusOK {
				t.Fatalf("download answered %d", code)
			}
			got := header.Get("X-Blob-Label")
			requireHeaderIsSafe(t, got)
			if got != payload {
				t.Fatalf("a label with no control characters was altered: %q -> %q", payload, got)
			}
		})
	}
}

// TestBlobLabel_CleanLabelsUnchanged verifies an ordinary label survives the
// round trip byte for byte, so the sanitizer cannot be satisfied by dropping
// everything.
func TestBlobLabel_CleanLabelsUnchanged(t *testing.T) {
	for _, label := range []string{
		"my-backup-2024.enc",
		"vault_export_v2.bin",
		"profile-photo.jpg.enc",
		"label with spaces",
		"unicode-label-école",
		strings.Repeat("a", 255),
	} {
		name := label
		if len(name) > 30 {
			name = name[:30] + "..."
		}
		t.Run(name, func(t *testing.T) {
			header, code := blobLabelRoundTrip(t, label)
			if code != http.StatusOK {
				t.Fatalf("download answered %d", code)
			}
			if got := header.Get("X-Blob-Label"); got != label {
				t.Fatalf("clean label was modified: %q -> %q", label, got)
			}
		})
	}
}
