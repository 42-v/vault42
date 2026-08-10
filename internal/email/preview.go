package email

import (
	"bytes"
	"strings"
)

// SampleData returns placeholder TemplateData for previewing a custom template
// in the admin UI without sending a real email.
func SampleData() TemplateData {
	return TemplateData{
		AppName:      "Example App",
		URL:          "https://example.com/action?token=SAMPLE_TOKEN",
		Code:         "123456",
		IP:           "203.0.113.10",
		Device:       "Firefox on Linux",
		PrimaryColor: "#00FF42",
	}
}

// RenderPreview validates and renders a custom subject + HTML body against the
// given data, returning the rendered subject, HTML, and derived plain text. It
// applies the same safety validation as a saved template, so a preview that
// succeeds is also a template that would save.
func RenderPreview(subject, htmlContent string, data TemplateData) (renderedSubject, html, text string, err error) {
	if err = ValidateTemplateContent(subject, htmlContent); err != nil {
		return "", "", "", err
	}
	// ValidateTemplateContent above runs compileOverride on the same subject and
	// body and returns its error, so this compile cannot fail. Discarding the
	// error keeps the invariant in one place instead of implying two outcomes.
	st, ht, _ := compileOverride(subject, htmlContent)
	var sb, hb bytes.Buffer
	if err = st.Execute(&sb, data); err != nil {
		return "", "", "", err
	}
	renderedSubject = strings.TrimSpace(sb.String())
	data.Subject = renderedSubject
	if err = ht.Execute(&hb, data); err != nil {
		return "", "", "", err
	}
	html = hb.String()
	return renderedSubject, html, stripHTML(html), nil
}
