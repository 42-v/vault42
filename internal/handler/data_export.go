package handler

import (
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// maxExportAuditEvents bounds the number of audit events included in a data
// export. The right of access covers the data held, but an unbounded query
// would risk large responses and memory pressure; the most recent events are
// the relevant ones for a subject access request. Hitting the cap is reported in
// the response so the export is never silently partial.
const maxExportAuditEvents = 1000

// DataExportHandler serves the GDPR data-portability endpoint. It aggregates
// every category of personal data the service holds for the requesting user by
// reusing the existing repositories and services — it adds no storage of its
// own.
type DataExportHandler struct {
	users       repository.UserRepository
	devices     repository.DeviceRepository
	social      repository.SocialAccountRepository
	auditEvents repository.AuditRepository
	identitySvc *service.IdentityService
	blobSvc     *service.BlobService
	auditLog    *audit.Logger
}

// NewDataExportHandler creates a new data export handler. blobSvc may be nil
// when blob storage is disabled; identitySvc may be nil when the identity store
// is disabled. The handler degrades gracefully in either case.
func NewDataExportHandler(
	users repository.UserRepository,
	devices repository.DeviceRepository,
	social repository.SocialAccountRepository,
	auditEvents repository.AuditRepository,
	identitySvc *service.IdentityService,
	blobSvc *service.BlobService,
	auditLog *audit.Logger,
) *DataExportHandler {
	return &DataExportHandler{
		users:       users,
		devices:     devices,
		social:      social,
		auditEvents: auditEvents,
		identitySvc: identitySvc,
		blobSvc:     blobSvc,
		auditLog:    auditLog,
	}
}

// Export handles GET /user/data-export. It returns, as JSON, all personal data
// held for the authenticated user: account metadata, the decrypted identity
// profile, devices, blob metadata (names and sizes, never contents), linked
// social accounts, and user-scoped audit events. This satisfies the data
// subject's right of access (GDPR Article 15) and right to data portability
// (GDPR Article 20).
func (h *DataExportHandler) Export(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	userID := claims.Subject

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	resp := DataExportResponse{
		GeneratedAt: time.Now().UTC(),
		Account: DataExportAccount{
			ID:            user.ID,
			Email:         user.Email,
			EmailVerified: user.EmailVerified,
			DisplayName:   user.DisplayName,
			AvatarURL:     user.AvatarURL,
			Locale:        user.Locale,
			Roles:         user.Roles,
			MFARequired:   user.MFARequired,
			Disabled:      user.Disabled,
			Banned:        user.Banned,
			CreatedAt:     user.CreatedAt,
			UpdatedAt:     user.UpdatedAt,
			LastLoginAt:   user.LastLoginAt,
		},
		Devices:        []DataExportDevice{},
		Blobs:          []DataExportBlob{},
		SocialAccounts: []DataExportSocialAccount{},
		AuditEvents:    []DataExportAuditEvent{},
	}

	// Identity profile (decrypted PII). Absent profile is not an error.
	if h.identitySvc != nil {
		data, updatedAt, idErr := h.identitySvc.Get(r.Context(), userID)
		if idErr != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		if data != nil {
			resp.Identity = &IdentityResponse{
				GivenName:       data.GivenName,
				FamilyName:      data.FamilyName,
				Username:        data.Username,
				Country:         data.Country,
				State:           data.State,
				DateOfBirth:     data.DateOfBirth,
				Sex:             data.Sex,
				MarketingEmails: data.MarketingEmails,
				UpdatedAt:       updatedAt.Format(time.RFC3339),
				Billing:         data.Billing,
				Dynamic:         data.Dynamic,
			}
		}
	}

	// Devices.
	devices, err := h.devices.ListByUser(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, DataExportDevice{
			ID:           d.ID,
			FriendlyName: d.FriendlyName,
			Trusted:      d.Trusted,
			IP:           d.IP,
			UserAgent:    d.UserAgent,
			FirstSeenAt:  d.FirstSeenAt,
			LastSeenAt:   d.LastSeenAt,
		})
	}

	// Blob metadata (names and sizes only, never contents).
	if h.blobSvc != nil {
		metas, _, blobErr := h.blobSvc.List(r.Context(), userID)
		if blobErr != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		for _, m := range metas {
			resp.Blobs = append(resp.Blobs, DataExportBlob{
				ID:        m.ID,
				Label:     m.Label,
				Named:     m.Named,
				SizeBytes: m.SizeBytes,
				Checksum:  m.Checksum,
				CreatedAt: m.CreatedAt,
			})
		}
	}

	// Linked social accounts (provider tokens are deliberately excluded).
	if h.social != nil {
		accounts, socErr := h.social.ListByUser(r.Context(), userID)
		if socErr != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		for _, a := range accounts {
			resp.SocialAccounts = append(resp.SocialAccounts, DataExportSocialAccount{
				Provider:       a.Provider,
				ProviderUserID: a.ProviderUserID,
				Email:          a.Email,
				CreatedAt:      a.CreatedAt,
			})
		}
	}

	// User-scoped audit events. The list is capped, so the total held is reported
	// alongside it: an export that is silently partial reads as complete, and the
	// subject never learns there is more to ask for.
	if h.auditEvents != nil {
		total, countErr := h.auditEvents.CountByUser(r.Context(), userID)
		if countErr != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		entries, auditErr := h.auditEvents.Query(r.Context(), repository.AuditFilter{
			UserID: userID,
			Limit:  maxExportAuditEvents,
		})
		if auditErr != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		resp.AuditEventsTotal = total
		resp.AuditEventsLimit = maxExportAuditEvents
		resp.AuditEventsTruncated = total > len(entries)
		for _, e := range entries {
			resp.AuditEvents = append(resp.AuditEvents, DataExportAuditEvent{
				Timestamp: e.Timestamp,
				EventType: e.EventType,
				IP:        e.IP,
				UserAgent: e.UserAgent,
				Metadata:  e.Metadata,
			})
		}
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.DataExport, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks the response
			r.Header.Get("User-Agent"), "", "", nil, 0)
	}

	WriteJSON(w, http.StatusOK, resp)
}
