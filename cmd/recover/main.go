// Command recover is the offline account-recovery tool. Given the recovery
// PRIVATE key and a database DSN, it reads the append-only recovery escrow log,
// decrypts each record, and prints the recoverable details as JSON lines so an
// operator can restore deleted users from backup.
//
// The running server never has the private key — it can only WRITE escrow
// records. This tool is meant to run on a trusted offline host where the key is
// available.
//
// Usage:
//
//	recover --key /path/to/recovery_private.pem --dsn "postgres://user:pass@host:5432/vault?sslmode=require"
//
// The DSN may also be supplied via the DATABASE_URL environment variable.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// escrowQuery reads the append-only escrow log newest first. The table is
// INSERT/SELECT only (migrations/007_account_recovery.sql), so this tool never
// needs write access to the database it recovers from.
const escrowQuery = `
		SELECT payload, deleted_at, deleted_by, reason
		FROM auth.account_recovery
		ORDER BY deleted_at DESC
		LIMIT $1`

// escrowedPayload mirrors the JSON written by the erasure service. Kept local so
// the tool stays decoupled from internal service types.
type escrowedPayload struct {
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	Roles       []string  `json:"roles"`
	DisplayName string    `json:"display_name"`
}

// recoveredRecord is the JSON-line output for one recovered account.
type recoveredRecord struct {
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name,omitempty"`
	Roles       []string  `json:"roles,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	DeletedAt   time.Time `json:"deleted_at"`
	DeletedBy   string    `json:"deleted_by,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// rowSource is the read side of the escrow log. pgx.Rows satisfies it; the
// narrower interface is what lets the decrypt loop run against a table of
// crafted escrow blobs instead of a live database.
type rowSource interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// escrowOpener opens the escrow log and returns its rows together with the
// release function that closes both the rows and the connection behind them.
type escrowOpener func(ctx context.Context, dsn string, limit int) (rowSource, func(), error)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, openPostgres))
}

// run is the whole tool. It returns the process exit code: 2 for a flag error
// (the stdlib's own convention), 1 for a fatal error, 0 otherwise. Individual
// records that fail to decrypt are counted and reported, not fatal, so one
// corrupt row cannot abort an entire restore.
func run(args []string, stdout, stderr io.Writer, open escrowOpener) int {
	logger := log.New(stderr, "", log.LstdFlags)

	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "path to the recovery RSA private key (PEM)")
	dsn := fs.String("dsn", os.Getenv("DATABASE_URL"), "PostgreSQL DSN (or set DATABASE_URL)")
	limit := fs.Int("limit", 10000, "maximum number of records to read")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *keyPath == "" {
		logger.Print("recover: --key is required")
		return 1
	}
	if *dsn == "" {
		logger.Print("recover: --dsn (or DATABASE_URL) is required")
		return 1
	}

	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		logger.Printf("recover: read key: %v", err)
		return 1
	}
	priv, err := vaultcrypto.LoadRSAPrivateKeyPEM(keyPEM)
	if err != nil {
		logger.Printf("recover: parse key: %v", err)
		return 1
	}

	ctx := context.Background()
	rows, release, err := open(ctx, *dsn, *limit)
	if err != nil {
		logger.Printf("recover: %v", err)
		return 1
	}
	defer release()

	enc := json.NewEncoder(stdout)
	var count, failures int
	for rows.Next() {
		var payload []byte
		var deletedAt time.Time
		var deletedBy, reason *string
		if err := rows.Scan(&payload, &deletedAt, &deletedBy, &reason); err != nil {
			logger.Printf("recover: scan: %v", err)
			return 1
		}

		plain, err := vaultcrypto.DecryptRecovery(priv, payload)
		if err != nil {
			// Wrong key or corrupt record — report on stderr and continue so one
			// bad row does not abort the whole restore.
			failures++
			fmt.Fprintf(stderr, "recover: decrypt failed for a record (deleted_at=%s): %v\n", deletedAt.Format(time.RFC3339), err)
			continue
		}

		var p escrowedPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			failures++
			fmt.Fprintf(stderr, "recover: malformed payload (deleted_at=%s): %v\n", deletedAt.Format(time.RFC3339), err)
			continue
		}

		out := recoveredRecord{
			Email:       p.Email,
			DisplayName: p.DisplayName,
			Roles:       p.Roles,
			CreatedAt:   p.CreatedAt,
			DeletedAt:   deletedAt,
			DeletedBy:   deref(deletedBy),
			Reason:      deref(reason),
		}
		if err := enc.Encode(out); err != nil {
			logger.Printf("recover: encode: %v", err)
			return 1
		}
		count++
	}
	if err := rows.Err(); err != nil {
		logger.Printf("recover: iterate: %v", err)
		return 1
	}

	fmt.Fprintf(stderr, "recover: %d record(s) decrypted, %d failure(s)\n", count, failures)
	return 0
}

// openPostgres is the production escrowOpener: it dials the DSN with pgx and
// runs escrowQuery. The connect and query failures keep separate prefixes so an
// operator can tell "the offline host cannot reach the database" apart from
// "the escrow table is not there".
func openPostgres(ctx context.Context, dsn string, limit int) (rowSource, func(), error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}

	rows, err := conn.Query(ctx, escrowQuery, limit)
	if err != nil {
		_ = conn.Close(ctx)
		return nil, nil, fmt.Errorf("query: %w", err)
	}

	return rows, func() {
		rows.Close()
		_ = conn.Close(ctx)
	}, nil
}

func deref(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
