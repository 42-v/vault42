package httputil

import (
	"fmt"
	"regexp"
)

// dbURLPattern matches the userinfo of a PostgreSQL DSN so it can be redacted
// out of an error before it reaches a log.
//
// Both schemes, because pgx accepts postgresql:// as well as postgres:// and
// DATABASE_URL is operator-supplied, so the longer spelling reached these
// messages unredacted. And [^:]+:[^@]* rather than [^\s]+, because a pattern
// that stops at whitespace does not match a DSN carrying a space anywhere before
// the @, and the entire string then goes to the log with the password in it.
//
// Only the userinfo is replaced. The host and database survive, because an
// operator reading a connection failure needs to know what it was connecting to.
var dbURLPattern = regexp.MustCompile(`(postgres(?:ql)?://)[^:@/]+:[^@]*@`)

// RedactDSN strips connection-URL credentials from an error message.
//
// pgx puts the DSN it dialed into its connect errors, so any tool that logs one
// raw prints the database password. This is the shared home for the redaction
// that cmd/vault and cmd/admin-gateway each carry a private copy of; cmd/recover
// had none at all, which mattered most because it is the tool that always holds
// the production DSN.
//
// The message is rebuilt with fmt.Errorf("%s", ...) rather than wrapped: keeping
// the cause in the chain would let errors.As reach it and print the unredacted
// original.
func RedactDSN(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", dbURLPattern.ReplaceAllString(err.Error(), "${1}***:***@"))
}
