package email

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
	c, err := CompileOverride(TemplateOverride{Subject: subject, HTMLContent: htmlContent})
	if err != nil {
		return "", "", "", err
	}
	// The preview renders through exactly the path a send takes, so a preview
	// that succeeds is a template that would both save and render.
	return c.render(data)
}
