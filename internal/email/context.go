package email

import (
	"context"
	"regexp"
)

// appSlugRe matches a tenant app slug. It mirrors the CHECK constraint on
// auth.email_branding.app / auth.email_templates.app so an in-flight value can
// never reference a row the database would have rejected.
var appSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidApp reports whether s is a well-formed app slug. It is a shape check
// only: it says nothing about whether a branding or template row exists for s,
// and it is not an authorisation decision. Deciding that a caller may select a
// given tenant belongs to whoever accepts the slug (see middleware.AppContext).
func ValidApp(s string) bool { return appSlugRe.MatchString(s) }

type ctxKey int

const appCtxKey ctxKey = iota

// WithApp returns a context carrying the app slug. An invalid or empty slug is
// ignored, in which case [AppFromContext] returns "" and global branding applies.
func WithApp(ctx context.Context, app string) context.Context {
	if !ValidApp(app) {
		return ctx
	}
	return context.WithValue(ctx, appCtxKey, app)
}

// AppFromContext returns the app slug stored in ctx, or "" if none is set.
func AppFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(appCtxKey).(string); ok {
		return v
	}
	return ""
}
