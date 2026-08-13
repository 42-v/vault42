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
//
// # Escrow formats
//
// A payload is sealed to the row it lives in: the record's primary key and its
// subject pseudonym are the RSA-OAEP label and the AES-GCM AAD, and the payload
// names its own subject. That binding is what stops a payload being moved
// between rows and reported under another erasure's deleted_at, deleted_by and
// reason. This tool rebuilds it from the columns it reads, which is why it needs
// no HMAC secret to do so.
//
// Records written before the binding existed are still readable, because they
// are the only recoverable copy of the accounts they describe. Every output line
// carries escrow_format, "bound" or "legacy", so a restore can tell a verified
// attribution from an unverified one without reading stderr, and every legacy
// read is announced there as well. --allow-legacy=false refuses them outright;
// once the retention horizon has aged the last one out, the legacy path here and
// in internal/crypto can be deleted.
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
//
// id and pseudonym are selected because they are the binding a bound payload was
// sealed to, not because they are printed. id is cast to text so the value that
// reaches crypto.RecoveryBinding is PostgreSQL's canonical UUID spelling rather
// than whatever the driver would have produced from the binary representation.
const escrowQuery = `
		SELECT id::text, pseudonym, payload, deleted_at, deleted_by, reason
		FROM auth.account_recovery
		ORDER BY deleted_at DESC
		LIMIT $1`

// boundPayloadVersion is the version stamp internal/service/erasure.go puts
// inside every bound payload. A bound record that does not carry it is not a
// profile this tool understands, and is dropped rather than half-read.
const boundPayloadVersion = 2

// escrowedPayload mirrors the JSON written by the erasure service. Kept local so
// the tool stays decoupled from internal service types.
type escrowedPayload struct {
	Version     int       `json:"v"`
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	Roles       []string  `json:"roles"`
	DisplayName string    `json:"display_name"`
}

// recoveredRecord is the JSON-line output for one recovered account.
//
// EscrowFormat is not decoration and has no omitempty: every line says which
// framing it came from. "bound" means the payload was cryptographically sealed
// to this row, so the profile and the deleted_at/deleted_by/reason beside it are
// the same erasure event. "legacy" means it was not, and the attribution is
// unverified. A restore driven off this output has to be able to tell the two
// apart without reading stderr, which is why it is a field and not only a log
// line.
type recoveredRecord struct {
	UserID       string    `json:"user_id,omitempty"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"display_name,omitempty"`
	Roles        []string  `json:"roles,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	DeletedAt    time.Time `json:"deleted_at"`
	DeletedBy    string    `json:"deleted_by,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	EscrowFormat string    `json:"escrow_format"`
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

// exitIncomplete is returned when the run finished but at least one escrow
// record did not yield a restorable account. It is distinct from the fatal 1 so
// an operator can tell a run that could not start from one that ran and came
// back short.
const exitIncomplete = 3

// run is the whole tool. It returns the process exit code: 2 for a flag error
// (the stdlib's own convention), 1 for a fatal error, 3 when the run completed
// with at least one unrecoverable record, 0 when every record was recovered.
// Individual records that fail are counted and reported, not fatal, so one
// corrupt row cannot abort an entire restore.
func run(args []string, stdout, stderr io.Writer, open escrowOpener) int {
	logger := log.New(stderr, "", log.LstdFlags)

	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "path to the recovery RSA private key (PEM)")
	dsn := fs.String("dsn", os.Getenv("DATABASE_URL"), "PostgreSQL DSN (or set DATABASE_URL)")
	limit := fs.Int("limit", 10000, "maximum number of records to read")
	// Defaults to true because the alternative is refusing to recover accounts
	// erased before the escrow was bound to its row, and an operator running this
	// tool is usually mid-incident and not in a position to debug a format
	// argument. It is a flag rather than a constant so a deployment can prove it
	// has no legacy records left before the legacy path is deleted from the tree.
	allowLegacy := fs.Bool("allow-legacy", true,
		"read pre-binding escrow records, whose payload is not bound to its row (set false once none remain)")
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
	var count, failures, legacy int
	for rows.Next() {
		var recordID, pseudonym string
		var payload []byte
		var deletedAt time.Time
		var deletedBy, reason *string
		if err := rows.Scan(&recordID, &pseudonym, &payload, &deletedAt, &deletedBy, &reason); err != nil {
			logger.Printf("recover: scan: %v", err)
			return 1
		}

		// The framing is classified from the blob's own bytes before any key is
		// touched, and each format then gets exactly one decryption attempt with
		// the primitive that matches it. The alternative, trying bound first and
		// falling back to legacy on failure, was rejected: a failed bound decrypt
		// is indistinguishable from a wrong key or a corrupt row, so every one of
		// those would quietly become a second attempt down the weaker path, and
		// the tool could not honestly report which format it had read.
		format := vaultcrypto.RecoveryBlobFormat(payload)

		if format == vaultcrypto.RecoveryFormatLegacy && !*allowLegacy {
			failures++
			fmt.Fprintf(stderr, "recover: refused a legacy record (id=%s deleted_at=%s): its payload "+
				"predates row binding and --allow-legacy=false\n", recordID, deletedAt.Format(time.RFC3339))
			continue
		}

		var plain []byte
		switch format {
		case vaultcrypto.RecoveryFormatBound:
			// The binding is rebuilt from this row's own columns, so a payload
			// moved here from another row cannot produce the AES key: the OAEP
			// unwrap fails and nothing downstream ever runs.
			plain, err = vaultcrypto.DecryptRecovery(priv, payload, vaultcrypto.RecoveryBinding(recordID, pseudonym))
		case vaultcrypto.RecoveryFormatLegacy:
			plain, err = vaultcrypto.DecryptRecoveryLegacy(priv, payload)
		default:
			err = errors.New("unrecognised escrow blob framing")
		}
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

		// A payload that decrypts and parses can still carry no identity: JSON
		// null and {} both unmarshal cleanly into a zero escrowedPayload. Emitting
		// those produced a well-formed record with an empty email and the genuine
		// audit columns, counted among the successes, and an operator restoring
		// from that output would create accounts that never existed.
		//
		// This is reachable by an adversary rather than only by corruption. The
		// running server holds the recovery PUBLIC key and appends these rows, so
		// anything that can write the escrow log can seal an arbitrary number of
		// empty payloads without ever holding the private key.
		if p.Email == "" {
			failures++
			fmt.Fprintf(stderr, "recover: payload carries no identity (deleted_at=%s); "+
				"decrypted and parsed but has no email, so there is no account to restore\n",
				deletedAt.Format(time.RFC3339))
			continue
		}

		// A bound record has to name itself as well. The binding already proves the
		// blob belongs to this row; these two checks prove the plaintext inside it
		// is the profile shape this tool knows how to restore, sealed by a producer
		// that agreed on the version. Without the user id there is nothing to
		// restore the account under: the scrubbed user row is keyed by exactly that
		// id, and the escrow row names its subject only as an HMAC pseudonym this
		// tool has no secret to invert.
		//
		// It runs after the email check so that an empty or null payload still gets
		// the specific diagnostic rather than this general one. Legacy records are
		// exempt because their format predates both fields; that is precisely what
		// makes them unverifiable and why they are reported as such.
		if format == vaultcrypto.RecoveryFormatBound && (p.Version != boundPayloadVersion || p.UserID == "") {
			failures++
			fmt.Fprintf(stderr, "recover: bound record does not describe its subject (deleted_at=%s): "+
				"payload version %d, user id present: %t\n",
				deletedAt.Format(time.RFC3339), p.Version, p.UserID != "")
			continue
		}

		out := recoveredRecord{
			UserID:       p.UserID,
			Email:        p.Email,
			DisplayName:  p.DisplayName,
			Roles:        p.Roles,
			CreatedAt:    p.CreatedAt,
			DeletedAt:    deletedAt,
			DeletedBy:    deref(deletedBy),
			Reason:       deref(reason),
			EscrowFormat: format.String(),
		}
		if err := enc.Encode(out); err != nil {
			logger.Printf("recover: encode: %v", err)
			return 1
		}
		count++

		// Counted and announced only once the record actually became output. A
		// legacy blob that failed to decrypt was a failure, not a legacy read,
		// and inflating this count would make the retirement decision on the
		// legacy path harder rather than easier.
		//
		// The per-record line names the row rather than the person: the record id
		// is what an operator needs to find the row, and stderr is the channel
		// that ends up in scrollback and tickets.
		if format == vaultcrypto.RecoveryFormatLegacy {
			legacy++
			fmt.Fprintf(stderr, "recover: legacy record read (id=%s deleted_at=%s): written before escrow "+
				"payloads were bound to their row, so its attribution to this row's deleted_at, deleted_by "+
				"and reason is unverified\n", recordID, deletedAt.Format(time.RFC3339))
		}
	}
	if err := rows.Err(); err != nil {
		logger.Printf("recover: iterate: %v", err)
		return 1
	}

	fmt.Fprintf(stderr, "recover: %d record(s) decrypted, %d failure(s)\n", count, failures)
	if legacy > 0 {
		fmt.Fprintf(stderr, "recover: %d of those came from the legacy pre-binding escrow format; "+
			"they are marked escrow_format=legacy in the output and their attribution is unverified. "+
			"Once VAULT_RECOVERY_RETENTION_DAYS has aged the last of them out, run with "+
			"--allow-legacy=false to confirm, then the legacy read path can be removed.\n", legacy)
	}

	// Exit status has to distinguish "recovered nothing because there was
	// nothing" from "recovered nothing because every record failed". Both used
	// to exit 0, so `recover --key wrong.pem > accounts.jsonl || alert` wrote an
	// empty file and reported success, which is the wrong direction to fail for
	// a restore driven from a script. The failure count only ever existed on
	// stderr, which a pipeline does not read.
	//
	// Individual failures stay non-fatal mid-run, so one corrupt row still does
	// not abort a restore; the status is reported once at the end.
	if failures > 0 {
		return exitIncomplete
	}
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
