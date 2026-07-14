package email

import "testing"

// ValidateTemplateContent runs at admin write time, so that bad tenant branding can
// never reach the send path. The forbidden-construct checks (script, iframe, event
// handlers) were already covered; the empty-subject guard was not.
//
// It is not cosmetic. An override saved with a blank subject produces mail with no
// subject line for every user of that tenant — including the verification and
// password-reset mails, which are the two a recipient is most likely to dismiss as
// junk when they arrive headless. Rejecting it at write time is the only point where
// one person sees the error instead of every recipient living with it.
func TestValidateTemplateContent_RejectsEmptySubject(t *testing.T) {
	for _, subject := range []string{"", "   ", "\t\n"} {
		if err := ValidateTemplateContent(subject, "<p>Hello {{.DisplayName}}</p>"); err == nil {
			t.Errorf("a template with subject %q was accepted", subject)
		}
	}
}
