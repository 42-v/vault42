package audit

// Severity: one number per event class, on one scale.
//
// Before this table, risk_score was a per-call-site integer literal. The same
// class carried four different numbers depending on which branch reached it --
// a login failure scored 50 when the source address was locked out, 30 when the
// account was, 20 when the password was wrong and 10 when the address was not
// registered -- and none of those numbers was comparable to the 45 a refused
// mint carried or the 100 the admin killswitch wrote. Nothing read the field, so
// nothing noticed. A threshold over a number that means a different thing in
// every row is not a threshold, which is why AU-6 could not move while the
// number was a call-site decision.
//
// Two consequences are deliberate.
//
// The reason a login failed no longer changes the score. It stays in the
// metadata, where it belongs and where the audit log is not visible to the
// caller. Scoring it as well would have re-encoded, in a sortable column an
// operator can select ranges on, exactly the distinction the login path spends
// a dummy Argon2id hash to erase: with the old literals, "risk_score = 10"
// listed the addresses that are not registered and "risk_score = 20" the ones
// that are. It is not reachable by an unauthenticated caller, so it was never a
// live oracle, but it is an enumeration report the register would have had to
// argue about, built out of a distinction the code works hard to destroy.
//
// The outcome of a mint no longer changes the score either, for the smaller
// version of the same reason: success is already in the metadata, and a severity
// that varies with metadata is a second, weaker copy of it in a field that
// sorts.

// The scale. Five bands, because an operator setting a threshold has to be able
// to say what they are asking for in words, and because a scale with more
// resolution than the judgements behind it invites arithmetic nobody can defend.
//
// The bands are cumulative in the sense a filter needs: every row scoring at
// least Elevated is at least as interesting as every other row scoring
// Elevated, whatever class it came from. That property is the entire purpose of
// the table.
const (
	// SeverityRoutine is the ordinary operation of the product. The row exists
	// because the trail has to be complete, not because anything is wrong.
	SeverityRoutine = 0
	// SeverityNotable is security-relevant and expected during normal use: a
	// control engaged, or an authentication step completed.
	SeverityNotable = 25
	// SeverityElevated is an event touching a credential, a session or personal
	// data. Individually unremarkable; in a run, the shape of an attack.
	SeverityElevated = 50
	// SeveritySerious is a privilege, key or identity boundary being exercised
	// or probed. A single one deserves a look.
	SeveritySerious = 75
	// SeverityCritical is an event that is, on its own, evidence that something
	// is wrong. There is no legitimate traffic in this band.
	SeverityCritical = 100
)

// AdminKillswitchTriggered is the event the admin gateway writes when a
// non-loopback connection reaches it.
//
// It is declared here, apart from the vocabulary block, because the gateway
// writes that row straight to the repository rather than through Logger.Log: it
// holds an AuditRepository and no logger. Putting the string in the vocabulary
// block would fail the dead-vocabulary gate in tests/spec, which requires every
// constant there to reach Logger.Log's second argument from a production path.
// Declaring it here instead gives the number one home without claiming the event
// is on the logged path -- and it is not, which also means it raises no alert.
// That is the one severity-critical class alerting does not see, and it is named
// as remaining work rather than papered over.
const AdminKillswitchTriggered = "admin:killswitch_triggered"

// severityByEvent scores every declared event class.
//
// tests/spec asserts the table is total over the vocabulary, so a new event type
// cannot arrive unscored, and internal/audit asserts every score is one of the
// five bands.
var severityByEvent = map[string]int{
	// Ordinary product operation. The trail records it; nothing is wrong.
	LoginSuccess:     SeverityRoutine,
	Registration:     SeverityRoutine,
	TokenRefresh:     SeverityRoutine,
	TokenRevoke:      SeverityRoutine,
	ClientAuth:       SeverityRoutine,
	ConsentGranted:   SeverityRoutine,
	ConsentWithdrawn: SeverityRoutine,
	OAuth2Authorize:  SeverityRoutine,
	OAuth2Callback:   SeverityRoutine,

	// Security-relevant and expected. A failed login is the most common event in
	// any authentication service; what matters about it is the rate, which is
	// what the alert rule watches.
	LoginFailure: SeverityNotable,
	TwoFAVerify:  SeverityNotable,
	AdminLogout:  SeverityNotable,
	// The honeypot's own dispatch record. The trigger beside it is critical; the
	// note that a webhook went out is bookkeeping.
	HoneypotAlert: SeverityNotable,

	// Touching a credential, a session or personal data. A password change is
	// the classic first act after a takeover, a trusted device is persistence,
	// and a service document read is a record of who read whose data.
	PasswordChange: SeverityElevated,
	PasswordReset:  SeverityElevated,
	TwoFASetup:     SeverityElevated,
	DeviceTrust:    SeverityElevated,
	SessionRevoke:  SeverityElevated,
	RateLimit:      SeverityElevated,
	AdminAction:    SeverityElevated,
	// A login from a country this account has not been seen in. Coarse by
	// construction -- the metadata carries the country and never the address --
	// and the early signal for a stolen credential in use somewhere else.
	LoginNewCountry: SeverityElevated,
	SvcDocPut:       SeverityElevated,
	SvcDocGet:       SeverityElevated,
	SvcDocDelete:    SeverityElevated,
	// The admin plane. Every one of these is an operator acting on someone
	// else's account or on the deployment itself.
	AdminLogin:             SeverityElevated,
	AdminLoginFailure:      SeverityElevated,
	AdminSessionRevoke:     SeverityElevated,
	AdminUserLock:          SeverityElevated,
	AdminUserUnlock:        SeverityElevated,
	AdminUserResetRequired: SeverityElevated,
	AdminUserResetCleared:  SeverityElevated,

	// A privilege, key or identity boundary exercised or probed.
	KMSUnwrap:            SeveritySerious,
	TokenMinted:          SeveritySerious,
	AccountErased:        SeveritySerious,
	DataExport:           SeveritySerious,
	FingerprintAnomaly:   SeveritySerious,
	DPoPBindingMismatch:  SeveritySerious,
	AdminUserDelete:      SeveritySerious,
	AdminKeyRotate:       SeveritySerious,
	AdminKeyRevoke:       SeveritySerious,
	AdminClientCreate:    SeveritySerious,
	AdminClientRevoke:    SeveritySerious,
	AdminClientRotate:    SeveritySerious,
	AdminConfigChange:    SeveritySerious,
	AdminAccountCreate:   SeveritySerious,
	AdminAccountRevoke:   SeveritySerious,
	AdminLockout:         SeveritySerious,
	AdminAuthzDenied:     SeveritySerious,
	AdminSessionRejected: SeveritySerious,

	// No legitimate traffic reaches these. A trap credential has no user, and a
	// non-loopback connection to the admin gateway is not a misconfiguration
	// anybody has to guess about.
	HoneypotTrigger:          SeverityCritical,
	AdminKillswitchTriggered: SeverityCritical,
}

// Severity returns the score for an event class.
//
// An unscored class reads as notable rather than as routine, so a new event type
// is visible to a review filter on the day it is added rather than invisible
// until someone remembers the table. The tests/spec gate is what stops that
// default from ever being load-bearing.
func Severity(eventType string) int {
	if s, ok := severityByEvent[eventType]; ok {
		return s
	}
	return SeverityNotable
}
