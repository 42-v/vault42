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
//	DATABASE_URL="postgres://user:pass@host:5432/vault?sslmode=require" \
//		recover --key /path/to/recovery_private.pem --out recovered.jsonl
//
// The DSN belongs in DATABASE_URL rather than in --dsn: every argument of a
// running process is readable by every other process on the host through
// /proc/<pid>/cmdline, and a shell keeps it in history afterwards. --dsn still
// works, and says so on stderr when the value it was given carries a password.
//
// --out writes the recovered records to a file the tool creates itself, mode
// 0600, refusing to overwrite an existing file or to follow a symlink. Without it
// the records go to stdout, and a `> file` redirect creates that file with the
// operator's umask, which on a stock login is world-readable. This output is the
// personal data an erasure removed, so it is worth the extra flag.
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
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"strings"
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
	// Before anything reads the key. A failure here is reported and not fatal: it
	// weakens the run, but refusing to answer a legal request because a hardening
	// step was unavailable is worse.
	if err := hardenProcess(); err != nil {
		fmt.Fprintf(os.Stderr, "recover: could not disable core dumps and debugger attach: %v\n", err)
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, openPostgres))
}

// exitIncomplete is returned when the run finished but at least one escrow
// record did not yield a restorable account. It is distinct from the fatal 1 so
// an operator can tell a run that could not start from one that ran and came
// back short.
const exitIncomplete = 3

// decryptEscrowed runs exactly one decryption attempt with the primitive that
// matches the framing already classified from the blob's own bytes.
//
// Trying bound first and falling back to legacy on failure was rejected: a
// failed bound decrypt is indistinguishable from a wrong key or a corrupt row,
// so every one of those would quietly become a second attempt down the weaker
// path, and the tool could not honestly report which format it had read.
func decryptEscrowed(priv *rsa.PrivateKey, format vaultcrypto.RecoveryFormat, payload []byte, recordID, pseudonym string) ([]byte, error) {
	switch format {
	case vaultcrypto.RecoveryFormatBound:
		// The binding is rebuilt from this row's own columns, so a payload moved
		// here from another row cannot produce the AES key: the OAEP unwrap fails
		// and nothing downstream ever runs.
		return vaultcrypto.DecryptRecovery(priv, payload, vaultcrypto.RecoveryBinding(recordID, pseudonym))
	case vaultcrypto.RecoveryFormatLegacy:
		return vaultcrypto.DecryptRecoveryLegacy(priv, payload)
	case vaultcrypto.RecoveryFormatUnknown:
		return nil, errors.New("unrecognized escrow blob framing")
	default:
		return nil, errors.New("unrecognized escrow blob framing")
	}
}

// run is the whole tool. It returns the process exit code: 2 for a flag error
// (the stdlib's own convention), 1 for a fatal error, 3 when the run completed
// with at least one unrecoverable record, 0 when every record was recovered.
// Individual records that fail are counted and reported, not fatal, so one
// corrupt row cannot abort an entire restore.
func run(args []string, stdout, stderr io.Writer, open escrowOpener) (code int) {
	logger := log.New(stderr, "", log.LstdFlags)

	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "path to the recovery RSA private key (PEM)")
	// The default stays empty and DATABASE_URL is read after parsing instead.
	// Wiring the environment variable in as the flag default put its value in the
	// usage text, because flag.PrintDefaults appends `(default "<value>")` for any
	// non-empty string default: `recover -h` printed the production database
	// password into the terminal of anyone who had followed the documented advice
	// to keep it out of argv.
	dsn := fs.String("dsn", "", "PostgreSQL DSN (or set DATABASE_URL, which keeps the password out of argv)")
	limit := fs.Int("limit", 10000, "maximum number of records to read")
	outPath := fs.String("out", "", "write the recovered records to this file, created 0600 and never overwritten (default stdout)")
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

	// A DSN that came from the flag is already in argv; one that came from the
	// environment is not, and the two get different treatment below.
	dsnFromArgv := *dsn != ""
	if !dsnFromArgv {
		*dsn = os.Getenv("DATABASE_URL")
	}

	if *keyPath == "" {
		logger.Print("recover: --key is required")
		return 1
	}
	if *dsn == "" {
		logger.Print("recover: --dsn (or DATABASE_URL) is required")
		return 1
	}

	if dsnFromArgv {
		warnDSNInArgv(logger, *dsn)
	}

	priv, ok := loadRecoveryKey(logger, *keyPath)
	if !ok {
		return 1
	}

	// Opened before the escrow log, so an unusable path is discovered while the
	// process is still holding nothing.
	out, closeOut, ok := openOutput(logger, *outPath, stdout)
	if !ok {
		return 1
	}
	defer func() { closeOut(&code) }()

	ctx := context.Background()
	rows, release, err := open(ctx, *dsn, *limit)
	if err != nil {
		logger.Printf("recover: %v", err)
		return 1
	}
	defer release()

	enc := json.NewEncoder(out)
	var count, failures, legacy, scanned int
	for rows.Next() {
		var row escrowLogRow
		if err := rows.Scan(&row.id, &row.pseudonym, &row.payload, &row.deletedAt, &row.deletedBy, &row.reason); err != nil {
			logger.Printf("recover: scan: %v", err)
			return 1
		}
		// Rows read, not records recovered: a row that failed still came out of the
		// escrow log and still consumed one of the LIMIT, so it is what decides
		// whether the read was truncated.
		scanned++

		rec, format, ok := recoverRow(priv, row, *allowLegacy, stderr)
		if !ok {
			failures++
			continue
		}
		if err := enc.Encode(rec); err != nil {
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
				"and reason is unverified\n", row.id, row.deletedAt.Format(time.RFC3339))
		}
	}

	if err := rows.Err(); err != nil {
		logger.Printf("recover: iterate: %v", err)
		return 1
	}

	fmt.Fprintf(stderr, "recover: %d record(s) decrypted, %d failure(s)\n", count, failures)

	// A read that filled its LIMIT says nothing about what it did not reach. The
	// summary above is otherwise indistinguishable from a complete pass, and the
	// default limit is 10000, so a deployment past that number would hand a
	// regulator the most recent 10000 erasures and call it the set.
	//
	// It is a warning and not a non-zero status: --limit 1 to look at the newest
	// record is ordinary use, and failing that run would be wrong.
	if *limit > 0 && scanned >= *limit {
		fmt.Fprintf(stderr, "recover: --limit %d was reached, so the escrow log may hold older records this "+
			"run did not read; re-run with a higher --limit before treating this output as the complete set.\n", *limit)
	}

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

// warnDSNInArgv says out loud that a credential passed on the command line is
// already disclosed. The process cannot rewrite its own argv, so this is the only
// move left, and it is worth making while the operator is still at the keyboard.
func warnDSNInArgv(logger *log.Logger, dsn string) {
	if !dsnCarriesPassword(dsn) {
		return
	}
	logger.Print("recover: the database password was passed on the command line, where it is " +
		"readable to every process on this host via /proc/<pid>/cmdline and is kept in shell history. " +
		"Pass the DSN in DATABASE_URL instead, and rotate this credential.")
}

// loadRecoveryKey reads and parses the operator's offline key, reporting on
// stderr and returning ok=false for anything that is not a usable RSA private
// key. Every failure here is fatal to the run and none of them reach the
// database.
func loadRecoveryKey(logger *log.Logger, path string) (*rsa.PrivateKey, bool) {
	keyPEM, perm, err := readKeyFile(path)
	if err != nil {
		logger.Printf("recover: read key: %v", err)
		return nil, false
	}

	// Group and other access on the key file, checked on the handle the bytes were
	// actually read from. This key opens every escrow record ever written,
	// including records already swept out of the database but still present in a
	// backup, so its exposure is the one here that rotating something cannot undo.
	//
	// A warning and not a refusal: this tool runs mid-incident, sometimes from a
	// read-only mount where chmod is not available, and refusing to answer a legal
	// request over a permission bit is the worse failure of the two.
	if perm&0o066 != 0 {
		logger.Printf("recover: %s is mode %#o, so it is readable by accounts other than yours. "+
			"The recovery key opens every escrow record ever written: chmod 600 it and treat it as disclosed.",
			path, perm)
	}

	priv, err := vaultcrypto.LoadRSAPrivateKeyPEM(keyPEM)
	// The parsed key's big.Ints cannot be wiped, but the PEM buffer can, and it is
	// the copy that holds the key in its on-disk encoding. Zeroing it shortens the
	// window in which a core dump or a swapped-out page carries a directly usable
	// private key file.
	zero(keyPEM)
	if err != nil {
		logger.Printf("recover: parse key: %v", err)
		return nil, false
	}
	return priv, true
}

// openOutput picks where the recovered records go and returns the cleanup the
// caller must defer. The cleanup takes the run's exit code because what happens
// to a half-written file depends on how the run ended.
//
// An empty path means stdout, which the caller redirects at its own umask. A
// named path is opened here instead, and the two flags are the whole point of the
// option: O_EXCL refuses to truncate a previous recovery (which may already have
// been quoted in a legal response) and refuses to follow a symlink planted at the
// path, since open(2) with O_CREAT|O_EXCL fails with EEXIST on a symlink whether
// or not its target exists. The mode is explicit because the umask that governs a
// `> file` redirect does not apply here, and this output is exactly the personal
// data an erasure was supposed to remove.
func openOutput(logger *log.Logger, path string, fallback io.Writer) (io.Writer, func(code *int), bool) {
	if path == "" {
		return fallback, func(*int) {}, true
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the operator names their own output file
	if err != nil {
		logger.Printf("recover: open output: %v", err)
		return nil, nil, false
	}

	return f, func(code *int) {
		if cerr := f.Close(); cerr != nil {
			logger.Printf("recover: close output: %v", cerr)
			*code = 1
		}
		// A fatal run stopped at an arbitrary row, and the prefix it wrote is
		// indistinguishable from a complete recovery once the process is gone. An
		// incomplete run (exitIncomplete) is different: it read the whole log and
		// reported every record it could not recover, so its output is kept.
		if *code == 1 {
			if rerr := os.Remove(path); rerr != nil {
				logger.Printf("recover: remove partial output: %v", rerr)
			}
		}
	}, true
}

// escrowLogRow is one scanned row of auth.account_recovery. id and pseudonym are
// not output: they are the binding a bound payload was sealed to, which is why
// they have to travel with the row rather than be invented at decrypt time.
type escrowLogRow struct {
	id        string
	pseudonym string
	payload   []byte
	deletedAt time.Time
	deletedBy *string
	reason    *string
}

// recoverRow turns one escrow row into an output record, reporting on stderr and
// returning ok=false for every row that cannot become one. It never returns a
// partially filled record: a row either yields a profile this tool is prepared to
// stand behind, or it yields nothing.
//
// The returned format is the framing the row was actually read through, which the
// caller needs to count legacy reads separately from bound ones.
func recoverRow(priv *rsa.PrivateKey, row escrowLogRow, allowLegacy bool, stderr io.Writer) (recoveredRecord, vaultcrypto.RecoveryFormat, bool) {
	when := row.deletedAt.Format(time.RFC3339)

	// The framing is classified from the blob's own bytes before any key is
	// touched, and each format then gets exactly one decryption attempt with
	// the primitive that matches it. The alternative, trying bound first and
	// falling back to legacy on failure, was rejected: a failed bound decrypt
	// is indistinguishable from a wrong key or a corrupt row, so every one of
	// those would quietly become a second attempt down the weaker path, and
	// the tool could not honestly report which format it had read.
	format := vaultcrypto.RecoveryBlobFormat(row.payload)

	if format == vaultcrypto.RecoveryFormatLegacy && !allowLegacy {
		fmt.Fprintf(stderr, "recover: refused a legacy record (id=%s deleted_at=%s): its payload "+
			"predates row binding and --allow-legacy=false\n", row.id, when)
		return recoveredRecord{}, format, false
	}

	plain, err := decryptEscrowed(priv, format, row.payload, row.id, row.pseudonym)
	if err != nil {
		// Wrong key or corrupt record: report on stderr and let the caller carry
		// on, so one bad row does not abort the whole restore.
		fmt.Fprintf(stderr, "recover: decrypt failed for a record (deleted_at=%s): %v\n", when, err)
		return recoveredRecord{}, format, false
	}

	var p escrowedPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		fmt.Fprintf(stderr, "recover: malformed payload (deleted_at=%s): %v\n", when, err)
		return recoveredRecord{}, format, false
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
		fmt.Fprintf(stderr, "recover: payload carries no identity (deleted_at=%s); "+
			"decrypted and parsed but has no email, so there is no account to restore\n", when)
		return recoveredRecord{}, format, false
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
		fmt.Fprintf(stderr, "recover: bound record does not describe its subject (deleted_at=%s): "+
			"payload version %d, user id present: %t\n", when, p.Version, p.UserID != "")
		return recoveredRecord{}, format, false
	}

	return recoveredRecord{
		UserID:       p.UserID,
		Email:        p.Email,
		DisplayName:  p.DisplayName,
		Roles:        p.Roles,
		CreatedAt:    p.CreatedAt,
		DeletedAt:    row.deletedAt,
		DeletedBy:    deref(row.deletedBy),
		Reason:       deref(row.reason),
		EscrowFormat: format.String(),
	}, format, true
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

// readKeyFile reads the recovery key and reports the mode of the file the bytes
// came from. The mode is taken from the open handle rather than from a separate
// os.Stat so that the permissions reported are the ones on the file that was
// actually read, not on whatever the path pointed at a moment earlier.
func readKeyFile(path string) ([]byte, fs.FileMode, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names their own key file; this tool has no fixed key location
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}
	return data, info.Mode().Perm(), nil
}

// dsnCarriesPassword reports whether the DSN embeds a password, in either of the
// two spellings pgx accepts. It looks only for the presence of one and never
// returns the value: this is called to decide whether to print a warning, and a
// warning that quoted the credential would put it in the scrollback it is warning
// about.
func dsnCarriesPassword(dsn string) bool {
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if _, set := u.User.Password(); set {
			return true
		}
	}
	// Keyword/value DSNs ("host=... password=..."), and the password query
	// parameter of a URL DSN, which pgx reads as well. A trailing separator means
	// the key was present with an empty value, which is not a password.
	if i := strings.Index(dsn, "password="); i >= 0 {
		rest := dsn[i+len("password="):]
		return rest != "" && rest[0] != ' ' && rest[0] != '&'
	}
	return false
}

// zero overwrites b in place. Go cannot wipe a string or a big.Int, so this is
// only useful on buffers that hold key material and are dropped afterwards.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func deref(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
