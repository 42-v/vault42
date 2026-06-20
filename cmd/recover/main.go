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
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

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

func main() {
	keyPath := flag.String("key", "", "path to the recovery RSA private key (PEM)")
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "PostgreSQL DSN (or set DATABASE_URL)")
	limit := flag.Int("limit", 10000, "maximum number of records to read")
	flag.Parse()

	if *keyPath == "" {
		log.Fatal("recover: --key is required")
	}
	if *dsn == "" {
		log.Fatal("recover: --dsn (or DATABASE_URL) is required")
	}

	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("recover: read key: %v", err)
	}
	priv, err := vaultcrypto.LoadRSAPrivateKeyPEM(keyPEM)
	if err != nil {
		log.Fatalf("recover: parse key: %v", err)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		log.Fatalf("recover: connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	rows, err := conn.Query(ctx, `
		SELECT payload, deleted_at, deleted_by, reason
		FROM auth.account_recovery
		ORDER BY deleted_at DESC
		LIMIT $1`, *limit)
	if err != nil {
		log.Fatalf("recover: query: %v", err)
	}
	defer rows.Close()

	enc := json.NewEncoder(os.Stdout)
	var count, failures int
	for rows.Next() {
		var payload []byte
		var deletedAt time.Time
		var deletedBy, reason *string
		if err := rows.Scan(&payload, &deletedAt, &deletedBy, &reason); err != nil {
			log.Fatalf("recover: scan: %v", err)
		}

		plain, err := vaultcrypto.DecryptRecovery(priv, payload)
		if err != nil {
			// Wrong key or corrupt record — report on stderr and continue so one
			// bad row does not abort the whole restore.
			failures++
			fmt.Fprintf(os.Stderr, "recover: decrypt failed for a record (deleted_at=%s): %v\n", deletedAt.Format(time.RFC3339), err)
			continue
		}

		var p escrowedPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "recover: malformed payload (deleted_at=%s): %v\n", deletedAt.Format(time.RFC3339), err)
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
			log.Fatalf("recover: encode: %v", err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("recover: iterate: %v", err)
	}

	fmt.Fprintf(os.Stderr, "recover: %d record(s) decrypted, %d failure(s)\n", count, failures)
}

func deref(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
