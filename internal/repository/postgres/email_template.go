package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// EmailTemplateRepo implements repository.EmailTemplateRepository against
// auth.email_templates, keyed by the unique (app, template_name) pair.
type EmailTemplateRepo struct {
	db *DB
}

// NewEmailTemplateRepo creates a new PostgreSQL-backed email-template repository.
func NewEmailTemplateRepo(db *DB) *EmailTemplateRepo {
	return &EmailTemplateRepo{db: db}
}

const emailTemplateCols = `id, app, template_name, subject, html_content, text_content, enabled, created_at, created_by, updated_at, updated_by`

func scanEmailTemplate(row pgx.Row) (*model.EmailTemplate, error) {
	var t model.EmailTemplate
	var textContent, createdBy, updatedBy *string
	if err := row.Scan(&t.ID, &t.App, &t.TemplateName, &t.Subject, &t.HTMLContent,
		&textContent, &t.Enabled, &t.CreatedAt, &createdBy, &t.UpdatedAt, &updatedBy); err != nil {
		return nil, err
	}
	t.TextContent = deref(textContent)
	t.CreatedBy = deref(createdBy)
	t.UpdatedBy = deref(updatedBy)
	return &t, nil
}

// Get returns the override for (app, templateName), or nil, nil if absent.
func (r *EmailTemplateRepo) Get(ctx context.Context, app, templateName string) (*model.EmailTemplate, error) {
	t, err := scanEmailTemplate(r.db.Pool.QueryRow(ctx,
		`SELECT `+emailTemplateCols+` FROM auth.email_templates WHERE app = $1 AND template_name = $2`,
		app, templateName))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get email_template: %w", err)
	}
	return t, nil
}

func (r *EmailTemplateRepo) queryList(ctx context.Context, where string, args ...any) ([]*model.EmailTemplate, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT `+emailTemplateCols+` FROM auth.email_templates `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list email_templates: %w", err)
	}
	defer rows.Close()
	var out []*model.EmailTemplate
	for rows.Next() {
		t, err := scanEmailTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan email_template: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListByApp returns all template overrides for an app ordered by template_name.
func (r *EmailTemplateRepo) ListByApp(ctx context.Context, app string) ([]*model.EmailTemplate, error) {
	return r.queryList(ctx, `WHERE app = $1 ORDER BY template_name`, app)
}

// List returns every template override ordered by app, template_name.
func (r *EmailTemplateRepo) List(ctx context.Context) ([]*model.EmailTemplate, error) {
	return r.queryList(ctx, `ORDER BY app, template_name`)
}

// Upsert creates or replaces the override for (app, template_name). The caller
// supplies t.ID for the insert case; on conflict the existing id is retained.
func (r *EmailTemplateRepo) Upsert(ctx context.Context, t *model.EmailTemplate) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.email_templates
			(id, app, template_name, subject, html_content, text_content, enabled, created_by, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
		ON CONFLICT (app, template_name) DO UPDATE SET
			subject      = EXCLUDED.subject,
			html_content = EXCLUDED.html_content,
			text_content = EXCLUDED.text_content,
			enabled      = EXCLUDED.enabled,
			updated_at   = NOW(),
			updated_by   = EXCLUDED.updated_by`,
		t.ID, t.App, t.TemplateName, t.Subject, t.HTMLContent, nullStr(t.TextContent),
		t.Enabled, nullStr(t.CreatedBy), nullStr(t.UpdatedBy))
	if err != nil {
		return fmt.Errorf("upsert email_template: %w", err)
	}
	return nil
}

// Delete removes the override for (app, templateName) (idempotent).
func (r *EmailTemplateRepo) Delete(ctx context.Context, app, templateName string) error {
	if _, err := r.db.Pool.Exec(ctx,
		`DELETE FROM auth.email_templates WHERE app = $1 AND template_name = $2`, app, templateName); err != nil {
		return fmt.Errorf("delete email_template: %w", err)
	}
	return nil
}

var _ repository.EmailTemplateRepository = (*EmailTemplateRepo)(nil)
