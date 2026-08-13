package main

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// fakePostgres is a PostgreSQL v3 wire-protocol stub that lets the gateway's
// real startup sequence run without a database server.
//
// It exists because main() is a single 100-statement function whose second act
// is `postgres.New`, and that call ends in `pool.Ping`. Anything that refuses
// the TCP connection stops main() dead at the "database error" fatal, which
// leaves the entire wiring block after it (repositories, audit logger, first
// admin bootstrap, seeding, keystore, handler construction, erasure service,
// router, mTLS, signal handling, graceful shutdown) untested. Reaching that
// code needs something on the wire that pgx accepts, and testcontainers is not
// an option in the environments where this suite has to run unattended.
//
// The stub models one specific, realistic operational state: a reachable
// PostgreSQL instance whose schema has not been created. It answers the
// connection handshake and the ping, it answers the two statements the
// migration runner needs so that AutoMigrate can be driven to success, and it
// answers everything else with SQLSTATE 42P01 (undefined_table). That is the
// database a fresh deployment points at before migrations, and it is exactly
// the state that drives main() down its degraded-but-alive branches: the first
// admin bootstrap logs and continues, seeding logs and continues, the keystore
// logs and continues, and the gateway still comes up on mTLS. A regression that
// turned any of those log-and-continue paths into a fatal would fail the tests
// that use this stub.
//
// The stub deliberately does not grow query-specific fixtures. Its job is to
// keep pgx satisfied at the protocol layer, not to reimplement PostgreSQL.
// Behavior that depends on real query results belongs in the container-backed
// suites under tests/.
type fakePostgres struct {
	ln net.Listener

	mu         sync.Mutex
	conns      []net.Conn
	statements []string
	logins     []login
	stopped    bool

	wg sync.WaitGroup
}

// login is the credential one connection presented. The stub demands cleartext
// password authentication so that the role and the secret behind each
// connection are both observable, which is what lets a test prove the gateway
// runs migrations as vault_mig and everything else as vault_admin instead of
// doing all of it with one over-privileged role.
type login struct {
	user     string
	database string
	password string
}

// startFakePostgres binds a stub server on loopback and tears it down when the
// test ends.
//
// Call it before launching any gateway child process that points at it.
// t.Cleanup runs last-registered-first, so a gateway registered afterwards is
// killed before the stub stops waiting for its sessions to end.
func startFakePostgres(t *testing.T) *fakePostgres {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake postgres: listen: %v", err)
	}

	f := &fakePostgres{ln: ln}
	f.wg.Add(1)
	go f.accept()
	t.Cleanup(f.stop)
	return f
}

// host returns the loopback host the stub is bound to.
func (f *fakePostgres) host() string {
	h, _, _ := net.SplitHostPort(f.ln.Addr().String())
	return h
}

// port returns the ephemeral port the stub is bound to.
func (f *fakePostgres) port() string {
	_, p, _ := net.SplitHostPort(f.ln.Addr().String())
	return p
}

// sawStatementContaining reports whether any SQL text the stub received
// contains substr. Tests use it to prove the gateway actually reached a
// database-backed step rather than skipping it.
func (f *fakePostgres) sawStatementContaining(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.statements {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func (f *fakePostgres) stop() {
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		return
	}
	f.stopped = true
	conns := f.conns
	f.conns = nil
	f.mu.Unlock()

	_ = f.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	f.wg.Wait()
}

func (f *fakePostgres) accept() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}

		f.mu.Lock()
		if f.stopped {
			f.mu.Unlock()
			_ = c.Close()
			return
		}
		f.conns = append(f.conns, c)
		f.mu.Unlock()

		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer func() { _ = c.Close() }()
			f.session(c)
		}()
	}
}

func (f *fakePostgres) record(sql string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statements = append(f.statements, sql)
}

func (f *fakePostgres) recordLogin(l login) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins = append(f.logins, l)
}

// sawLogin reports whether any connection authenticated with exactly these
// credentials.
func (f *fakePostgres) sawLogin(want login) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.logins {
		if l == want {
			return true
		}
	}
	return false
}

// sawAnyConnection reports whether anything completed the handshake. Tests use
// it to prove that a failure happened before the gateway reached the database
// rather than after.
func (f *fakePostgres) sawAnyConnection() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.logins) > 0
}

// loginRoles returns the database roles that have connected, in order.
func (f *fakePostgres) loginRoles() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	roles := make([]string, 0, len(f.logins))
	for _, l := range f.logins {
		roles = append(roles, l.user)
	}
	return roles
}

// session drives one client connection through the handshake and then serves
// both the simple and the extended query protocols. pgx picks between them on
// its own: statements with no bind parameters go out as a simple Query, and
// everything the statement cache handles goes out as Parse/Describe/Bind/
// Execute, so a stub that implements only one of the two stalls partway through
// startup.
func (f *fakePostgres) session(c net.Conn) {
	be := pgproto3.NewBackend(c, c)
	if !f.handshake(be, c) {
		return
	}

	// prepared maps a prepared statement name to its SQL. current is the SQL of
	// the statement the next Describe/Execute applies to.
	prepared := make(map[string]string)
	current := ""
	// failed suppresses responses between an ErrorResponse and the Sync that
	// ends the failed exchange, which is what a real backend does.
	failed := false

	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}

		switch m := msg.(type) {
		case *pgproto3.Query:
			f.record(m.String)
			f.simpleQuery(be, m.String)
			if be.Flush() != nil {
				return
			}

		case *pgproto3.Parse:
			f.record(m.Query)
			prepared[m.Name] = m.Query
			current = m.Query
			if _, _, ok := knownStatement(m.Query); ok {
				be.Send(&pgproto3.ParseComplete{})
			} else {
				be.Send(undefinedTable())
				failed = true
			}

		case *pgproto3.Describe:
			if failed {
				continue
			}
			if m.ObjectType == 'S' {
				if sql, ok := prepared[m.Name]; ok {
					current = sql
				}
				be.Send(&pgproto3.ParameterDescription{})
			}
			if fields, _, _ := knownStatement(current); fields != nil {
				be.Send(&pgproto3.RowDescription{Fields: fields})
			} else {
				be.Send(&pgproto3.NoData{})
			}

		case *pgproto3.Bind:
			if failed {
				continue
			}
			if sql, ok := prepared[m.PreparedStatement]; ok {
				current = sql
			}
			be.Send(&pgproto3.BindComplete{})

		case *pgproto3.Execute:
			if failed {
				continue
			}
			_, tag, _ := knownStatement(current)
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})

		case *pgproto3.Sync:
			failed = false
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if be.Flush() != nil {
				return
			}

		case *pgproto3.Close:
			be.Send(&pgproto3.CloseComplete{})

		case *pgproto3.Flush:
			if be.Flush() != nil {
				return
			}

		case *pgproto3.Terminate:
			return
		}
	}
}

func (f *fakePostgres) handshake(be *pgproto3.Backend, c net.Conn) bool {
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return false
		}

		switch m := msg.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			// 'N' declines the encryption upgrade. Tests connect with
			// sslmode=disable so pgx should never ask, but answering keeps a
			// misconfigured test from hanging instead of failing.
			if _, err := c.Write([]byte{'N'}); err != nil {
				return false
			}

		case *pgproto3.StartupMessage:
			be.Send(&pgproto3.AuthenticationCleartextPassword{})
			if be.Flush() != nil {
				return false
			}
			if err := be.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
				return false
			}
			reply, err := be.Receive()
			if err != nil {
				return false
			}
			pw, ok := reply.(*pgproto3.PasswordMessage)
			if !ok {
				return false
			}
			f.recordLogin(login{
				user:     m.Parameters["user"],
				database: m.Parameters["database"],
				password: pw.Password,
			})

			be.Send(&pgproto3.AuthenticationOk{})
			for _, kv := range [][2]string{
				{"server_version", "16.0 (fakepg)"},
				{"client_encoding", "UTF8"},
				{"standard_conforming_strings", "on"},
				{"DateStyle", "ISO, MDY"},
				{"TimeZone", "UTC"},
				{"integer_datetimes", "on"},
			} {
				be.Send(&pgproto3.ParameterStatus{Name: kv[0], Value: kv[1]})
			}
			be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			return be.Flush() == nil

		default:
			return false
		}
	}
}

func (f *fakePostgres) simpleQuery(be *pgproto3.Backend, sql string) {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || strings.HasPrefix(trimmed, "--") {
		// pgconn pings with the comment "-- ping", which a real backend answers
		// with EmptyQueryResponse.
		be.Send(&pgproto3.EmptyQueryResponse{})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		return
	}

	fields, tag, ok := knownStatement(sql)
	if !ok {
		be.Send(undefinedTable())
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		return
	}
	if fields != nil {
		be.Send(&pgproto3.RowDescription{Fields: fields})
	}
	be.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
}

// knownStatement recognizes the only two statements the stub answers
// successfully, both of them owned by internal/migrate. Returning zero rows for
// the applied-versions query is what makes an empty migrations directory a
// complete, successful migration run, which is how the "migrations complete"
// branch of main() is reached without executing any DDL.
func knownStatement(sql string) (fields []pgproto3.FieldDescription, tag string, ok bool) {
	switch {
	case strings.Contains(sql, "CREATE TABLE IF NOT EXISTS public.schema_migrations"):
		return nil, "CREATE TABLE", true
	case strings.Contains(sql, "FROM public.schema_migrations"):
		return []pgproto3.FieldDescription{{
			Name:         []byte("version"),
			DataTypeOID:  25, // text
			DataTypeSize: -1,
			TypeModifier: -1,
			Format:       0,
		}}, "SELECT 0", true
	}
	return nil, "", false
}

// undefinedTable is the error a real PostgreSQL returns for a query against a
// schema that was never migrated.
func undefinedTable() *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{
		Severity:            "ERROR",
		SeverityUnlocalized: "ERROR",
		Code:                "42P01",
		Message:             "relation does not exist",
		Routine:             "fakePostgres",
	}
}
