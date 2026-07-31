package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// apAuditCols is the shape audit.Query reads back.
func apAuditCols(riskOID int32) []apCol {
	return []apCol{
		apTextCol("id"),
		{name: "timestamp", oid: apOIDTimestamptz, size: 8},
		apTextCol("event_type"), apTextCol("user_id"), apTextCol("client_id"),
		apTextCol("ip"), apTextCol("user_agent"), apTextCol("fingerprint_hash"),
		apTextCol("device_id"),
		{name: "metadata", oid: apOIDJSONB, size: -1},
		{name: "risk_score", oid: riskOID, size: 4},
	}
}

func apAuditRow(riskScore string) []byte {
	return apDataRow(
		apText("a-1"), apText("2026-01-01 00:00:00+00"), apText("login_success"),
		apText("u-1"), apText(""), apText("203.0.113.1"), apText("curl/8.0"),
		apText(""), apText(""), apText("{}"), apText(riskScore),
	)
}

// The escrow log is the only copy of an erased user's address. A row it cannot
// decode must abort the listing: returning the rows read so far with a nil error
// would tell the recovery operator that the records after the bad one do not
// exist, and an erasure is not something you get to look up twice.
func TestAccountRecoveryRepo_UndecodableRowStopsTheListing(t *testing.T) {
	db := apStartPG(t, apPGRule{
		match: "FROM auth.account_recovery",
		reply: func(string) []byte {
			out := apRowDesc(
				apTextCol("id"), apTextCol("pseudonym"),
				apCol{name: "payload", oid: apOIDBytea, size: -1},
				apCol{name: "deleted_at", oid: apOIDTimestamptz, size: 8},
				apTextCol("deleted_by"), apTextCol("reason"),
			)
			out = append(out, apDataRow(
				apText("r-1"), apText("p-1"), apText("\\x00"),
				apText("not-a-timestamp"), apText("self"), apText("user_request"),
			)...)
			out = append(out, apMsg('C', apCStr("SELECT 1"))...)
			return append(out, apReadyIdle()...)
		},
	})

	recs, err := NewAccountRecoveryRepo(db).List(context.Background(), 10, 0)
	if err == nil {
		t.Fatal("List reported success on a row it could not decode")
	}
	if !strings.Contains(err.Error(), "scan account recovery") {
		t.Errorf("err = %v, want it to name the scan step", err)
	}
	if recs != nil {
		t.Errorf("a partial escrow listing was returned alongside the error: %d records", len(recs))
	}
}

// The audit log is read by an investigator after an incident, and an empty or
// short answer reads exactly like "nothing happened". Neither a row that cannot
// be decoded nor a stream that dies partway through may be passed off as the
// end of the result: both have to come back as errors, with no partial slice
// alongside them.
func TestAuditRepo_BrokenResultSetIsNeverPassedOffAsTheEnd(t *testing.T) {
	t.Run("a row that will not decode", func(t *testing.T) {
		db := apStartPG(t, apPGRule{
			match: "FROM audit.audit_log",
			reply: func(string) []byte {
				out := apRowDesc(apAuditCols(apOIDInt4)...)
				out = append(out, apAuditRow("not-a-number")...)
				out = append(out, apMsg('C', apCStr("SELECT 1"))...)
				return append(out, apReadyIdle()...)
			},
		})

		entries, err := NewAuditRepo(db).Query(context.Background(), repository.AuditFilter{Limit: 10})
		if err == nil {
			t.Fatal("Query reported success on a row it could not decode")
		}
		if !strings.Contains(err.Error(), "scan audit entry") {
			t.Errorf("err = %v, want it to name the row scan", err)
		}
		if entries != nil {
			t.Errorf("a partial audit trail was returned alongside the error: %d entries", len(entries))
		}
	})

	t.Run("a stream that dies partway through", func(t *testing.T) {
		db := apStartPG(t, apPGRule{
			match: "FROM audit.audit_log",
			reply: func(string) []byte {
				out := apRowDesc(apAuditCols(apOIDInt4)...)
				out = append(out, apAuditRow("10")...)
				out = append(out, apErrorResponse("57014", "canceling statement due to conflict with recovery")...)
				return append(out, apReadyIdle()...)
			},
		})

		entries, err := NewAuditRepo(db).Query(context.Background(), repository.AuditFilter{Limit: 10})
		if err == nil {
			t.Fatal("Query returned the rows it had managed to read as if they were all of them")
		}
		if !strings.Contains(err.Error(), "scan audit entries") {
			t.Errorf("err = %v, want it to name the truncated result set", err)
		}
		if entries != nil {
			t.Errorf("a truncated audit trail was returned alongside the error: %d entries", len(entries))
		}
	})
}

// InsertBatch buffers events and writes them in one transaction. A COMMIT that
// is refused after every INSERT in it succeeded loses the whole batch, and the
// caller has already dropped its copy, so reporting success there turns a
// visible failure into a silent hole in the log.
func TestAuditRepo_RefusedCommitLosesTheBatchLoudly(t *testing.T) {
	committed := false
	db := apStartPG(t,
		apPGRule{match: "INSERT INTO audit.audit_log", reply: func(string) []byte {
			return append(apMsg('C', apCStr("INSERT 0 1")), apReadyInTx()...)
		}},
		apPGRule{match: "commit", reply: func(string) []byte {
			committed = true
			return append(apErrorResponse("40001", "could not serialize access"), apReadyIdle()...)
		}},
		apPGRule{match: "begin", reply: func(string) []byte {
			return append(apMsg('C', apCStr("BEGIN")), apReadyInTx()...)
		}},
	)

	err := NewAuditRepo(db).InsertBatch(context.Background(), []*model.AuditEntry{
		{ID: "a-1", Timestamp: time.Now(), EventType: "login_success", UserID: "u-1"},
	})
	if err == nil {
		t.Fatal("InsertBatch reported the batch written after the commit was refused")
	}
	if !strings.Contains(err.Error(), "commit audit batch tx") {
		t.Errorf("err = %v, want it to name the commit", err)
	}
	if !committed {
		t.Error("the batch never reached a COMMIT at all")
	}
}

// The retention sweep serialises on an advisory lock and reports whether it got
// one. Both failure points below must leave acquired=false and deleted=0: a
// caller told "acquired, 0 rows" would log a successful purge that never ran,
// and the Art. 5(1)(e) horizon would look enforced while nothing was deleted.
func TestAuditRepo_FailedSweepNeverClaimsItPurged(t *testing.T) {
	tests := []struct {
		name  string
		rules []apPGRule
		want  string
	}{
		{
			name: "the lock cannot be taken",
			want: "lock",
			rules: []apPGRule{
				{match: "pg_try_advisory_xact_lock", reply: func(string) []byte {
					return append(apErrorResponse("53300", "too many connections"), apReadyTxFailed()...)
				}},
			},
		},
		{
			name: "the commit is refused after the delete",
			want: "commit",
			rules: []apPGRule{
				{match: "pg_try_advisory_xact_lock", reply: func(string) []byte {
					out := apRowDesc(apCol{name: "pg_try_advisory_xact_lock", oid: apOIDBool, size: 1})
					out = append(out, apDataRow(apText("t"))...)
					out = append(out, apMsg('C', apCStr("SELECT 1"))...)
					return append(out, apReadyInTx()...)
				}},
				{match: "cleanup_old_entries", reply: func(string) []byte {
					out := apRowDesc(apCol{name: "cleanup_old_entries", oid: apOIDInt8, size: 8})
					out = append(out, apDataRow(apText("128"))...)
					out = append(out, apMsg('C', apCStr("SELECT 1"))...)
					return append(out, apReadyInTx()...)
				}},
				{match: "commit", reply: func(string) []byte {
					return append(apErrorResponse("40001", "could not serialize access"), apReadyIdle()...)
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules := append([]apPGRule{}, tc.rules...)
			rules = append(rules, apPGRule{match: "begin", reply: func(string) []byte {
				return append(apMsg('C', apCStr("BEGIN")), apReadyInTx()...)
			}})

			deleted, acquired, err := NewAuditRepo(apStartPG(t, rules...)).
				CleanupLocked(context.Background(), time.Now().Add(-24*time.Hour))
			if err == nil {
				t.Fatal("CleanupLocked reported a successful sweep")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name the %s step", err, tc.want)
			}
			if deleted != 0 {
				t.Errorf("a failed sweep reported %d entries purged", deleted)
			}
			if tc.want == "lock" && acquired {
				t.Error("CleanupLocked claimed the advisory lock it never got an answer about")
			}
		})
	}
}

// A device list that silently drops the row it could not decode is worse than an
// error: the user reviews their sessions, does not see the attacker's device,
// and revokes nothing. Both the undecodable row and the truncated stream must
// come back as failures.
func TestDeviceRepo_BrokenResultSetIsNeverPassedOffAsTheEnd(t *testing.T) {
	cols := []apCol{
		apTextCol("id"), apTextCol("user_id"), apTextCol("fingerprint_hash"),
		apTextCol("friendly_name"),
		{name: "trusted", oid: apOIDBool, size: 1},
		{name: "trusted_until", oid: apOIDTimestamptz, size: 8},
		apTextCol("ip"), apTextCol("user_agent"),
		{name: "last_seen_at", oid: apOIDTimestamptz, size: 8},
		{name: "first_seen_at", oid: apOIDTimestamptz, size: 8},
		{name: "created_at", oid: apOIDTimestamptz, size: 8},
	}
	row := func(trusted string) []byte {
		return apDataRow(
			apText("d-1"), apText("u-1"), apText("fp"), apText("laptop"),
			apText(trusted), nil, apText("203.0.113.1"), apText("curl/8.0"),
			nil, apText("2026-01-01 00:00:00+00"), apText("2026-01-01 00:00:00+00"),
		)
	}

	tests := []struct {
		name  string
		reply apPGReply
		want  string
	}{
		{
			name: "a row that will not decode",
			want: "scan device",
			reply: func(string) []byte {
				out := apRowDesc(cols...)
				out = append(out, row("maybe")...)
				out = append(out, apMsg('C', apCStr("SELECT 1"))...)
				return append(out, apReadyIdle()...)
			},
		},
		{
			name: "a stream that dies partway through",
			want: "scan devices",
			reply: func(string) []byte {
				out := apRowDesc(cols...)
				out = append(out, row("t")...)
				out = append(out, apErrorResponse("57014", "canceling statement due to conflict with recovery")...)
				return append(out, apReadyIdle()...)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := apStartPG(t, apPGRule{match: "FROM auth.devices", reply: tc.reply})

			devices, err := NewDeviceRepo(db).ListByUser(context.Background(), "u-1")
			if err == nil {
				t.Fatal("ListByUser returned a device list it could not actually read")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name %q", err, tc.want)
			}
			if devices != nil {
				t.Errorf("a partial device list was returned alongside the error: %d devices", len(devices))
			}
		})
	}
}

// A white-label listing that quietly drops the row it could not decode would
// take a tenant's branding out of the admin UI, where the operator would see an
// app with no override and be free to save one over it.
func TestEmailRepos_UndecodableRowStopsTheListing(t *testing.T) {
	t.Run("branding", func(t *testing.T) {
		db := apStartPG(t, apPGRule{
			match: "FROM auth.email_branding",
			reply: func(string) []byte {
				out := apRowDesc(
					apTextCol("app"), apTextCol("app_name"), apTextCol("logo_url"),
					apTextCol("primary_color"), apTextCol("from_name"), apTextCol("from_address"),
					apCol{name: "created_at", oid: apOIDTimestamptz, size: 8},
					apCol{name: "updated_at", oid: apOIDTimestamptz, size: 8},
					apTextCol("updated_by"),
				)
				out = append(out, apDataRow(
					apText("beon3"), apText("BeOn3"), nil, apText("#00FF42"),
					apText("BeOn3"), apText("no-reply@example.com"),
					apText("not-a-timestamp"), apText("2026-01-01 00:00:00+00"), nil,
				)...)
				out = append(out, apMsg('C', apCStr("SELECT 1"))...)
				return append(out, apReadyIdle()...)
			},
		})

		got, err := NewEmailBrandingRepo(db).List(context.Background())
		if err == nil {
			t.Fatal("List reported success on a row it could not decode")
		}
		if !strings.Contains(err.Error(), "scan email_branding") {
			t.Errorf("err = %v, want it to name the scan step", err)
		}
		if got != nil {
			t.Errorf("a partial branding list was returned alongside the error: %d rows", len(got))
		}
	})

	t.Run("templates", func(t *testing.T) {
		db := apStartPG(t, apPGRule{
			match: "FROM auth.email_templates",
			reply: func(string) []byte {
				out := apRowDesc(
					apTextCol("id"), apTextCol("app"), apTextCol("template_name"),
					apTextCol("subject"), apTextCol("html_content"), apTextCol("text_content"),
					apCol{name: "enabled", oid: apOIDBool, size: 1},
					apCol{name: "created_at", oid: apOIDTimestamptz, size: 8},
					apTextCol("created_by"),
					apCol{name: "updated_at", oid: apOIDTimestamptz, size: 8},
					apTextCol("updated_by"),
				)
				out = append(out, apDataRow(
					apText("t-1"), apText("beon3"), apText("verification"),
					apText("Verify"), apText("<p>hi</p>"), nil,
					apText("maybe"), apText("2026-01-01 00:00:00+00"), nil,
					apText("2026-01-01 00:00:00+00"), nil,
				)...)
				out = append(out, apMsg('C', apCStr("SELECT 1"))...)
				return append(out, apReadyIdle()...)
			},
		})

		got, err := NewEmailTemplateRepo(db).List(context.Background())
		if err == nil {
			t.Fatal("List reported success on a row it could not decode")
		}
		if !strings.Contains(err.Error(), "scan email_template") {
			t.Errorf("err = %v, want it to name the scan step", err)
		}
		if got != nil {
			t.Errorf("a partial template list was returned alongside the error: %d rows", len(got))
		}
	})
}
