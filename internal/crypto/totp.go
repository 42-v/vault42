package crypto

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 (TOTP) mandates HMAC-SHA1 for interoperability with authenticator apps
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	totpPeriod = 30 // seconds
	totpDigits = 6
	totpSkew   = 1 // ±1 period
)

// GenerateTOTPSecret generates a 20-byte base32-encoded TOTP secret.
func GenerateTOTPSecret() (string, error) {
	b, err := RandomBytes(20)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateTOTPCode generates the current TOTP code for the given secret.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("totp: decode secret: %w", err)
	}
	ts := t.Unix()
	if ts < 0 {
		return "", fmt.Errorf("totp: negative timestamp")
	}
	counter := uint64(ts) / totpPeriod // #nosec G115 -- negative check above
	return generateHOTP(key, counter, totpDigits), nil
}

// ValidateTOTPCode validates a TOTP code with ±1 period skew.
// Returns the time step that matched, or -1 if no match.
func ValidateTOTPCode(secret, code string, t time.Time) (int64, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return -1, fmt.Errorf("totp: decode secret: %w", err)
	}

	counter := t.Unix() / totpPeriod

	for offset := int64(-totpSkew); offset <= int64(totpSkew); offset++ {
		step := counter + offset
		if step < 0 {
			continue
		}
		expected := generateHOTP(key, uint64(step), totpDigits) // #nosec G115 -- step < 0 filtered above
		if SecureCompare(expected, code) {
			return step, nil
		}
	}
	return -1, nil
}

// BuildOTPAuthURL builds an otpauth:// URL for QR code generation.
func BuildOTPAuthURL(secret, issuer, accountName string) string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   fmt.Sprintf("/%s:%s", url.PathEscape(issuer), url.PathEscape(accountName)),
	}
	q := u.Query()
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	u.RawQuery = q.Encode()
	return u.String()
}

// generateHOTP implements RFC 4226 HOTP.
func generateHOTP(key []byte, counter uint64, digits int) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, code%mod)
}
