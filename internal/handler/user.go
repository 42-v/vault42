package handler

import (
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/sanitize"
	"github.com/42-v/vault42/internal/service"
)

// UserHandler handles user profile and session management.
type UserHandler struct {
	users    repository.UserRepository
	devices  repository.DeviceRepository
	tokens   repository.RefreshTokenRepository
	mfaSvc   *service.MFAService
	auditLog *audit.Logger
}

// NewUserHandler creates a new user handler.
func NewUserHandler(users repository.UserRepository, devices repository.DeviceRepository, tokens repository.RefreshTokenRepository, mfaSvc *service.MFAService) *UserHandler {
	return &UserHandler{users: users, devices: devices, tokens: tokens, mfaSvc: mfaSvc}
}

// SetAuditLog attaches the audit logger. Called once at wiring time; a nil
// logger is ignored.
func (h *UserHandler) SetAuditLog(l *audit.Logger) {
	if l != nil {
		h.auditLog = l
	}
}

// logSessionRevoke records that sessions were torn down, and which.
//
// This is how an account takeover ends: the attacker signs the owner out
// everywhere so the owner cannot race them for the account, and the devices row
// that would have shown an unfamiliar login is deleted in the same request.
// Until 1.0.0 that left nothing behind, so the owner's support ticket ("I was
// logged out and my password no longer works") had no evidence to sit next to,
// and a self-service sign-out was indistinguishable from a hostile one.
//
// The device is passed in the entry's own device column rather than in metadata
// so a revocation can be joined against the login that created the device. The
// blanket case has no single device and leaves it empty.
//
// Best-effort on purpose. A trail that can fail the request would leave the
// owner unable to sign an attacker out.
func (h *UserHandler) logSessionRevoke(r *http.Request, userID, deviceID, scope string) {
	if h.auditLog == nil {
		return
	}
	h.auditLog.Log(r.Context(), audit.SessionRevoke, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks the response
		r.Header.Get("User-Agent"), "", deviceID, map[string]interface{}{"scope": scope}, 0)
}

// Profile handles GET /user/profile.
func (h *UserHandler) Profile(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.users.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	mfaEnabled, mfaMethods := h.mfaState(r, user.ID)

	WriteJSON(w, http.StatusOK, ProfileResponse{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		DisplayName:   user.DisplayName,
		AvatarURL:     user.AvatarURL,
		Locale:        user.Locale,
		MFARequired:   h.mfaSvc != nil && h.mfaSvc.IsRequired(),
		MFAEnabled:    mfaEnabled,
		MFAMethods:    mfaMethods,
		CreatedAt:     user.CreatedAt,
	})
}

// mfaState reports whether the user has a factor configured and which ones.
// The method list is always a slice, never nil: with no factor configured, with
// no MFA service wired, and on a failed lookup the profile still has to answer
// with an empty array rather than null.
func (h *UserHandler) mfaState(r *http.Request, userID string) (enabled bool, methods []string) {
	methods = []string{}
	if h.mfaSvc == nil {
		return false, methods
	}
	status, err := h.mfaSvc.GetStatus(r.Context(), userID)
	if err != nil || status == nil {
		return false, methods
	}
	if status.Methods != nil {
		methods = status.Methods
	}
	return status.TOTPEnabled || status.WebAuthnEnabled, methods
}

// UpdateProfile handles PUT /user/profile.
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.users.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req UpdateProfileInput
	if err := decodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	// Merge only fields that were sent
	if req.DisplayName != nil {
		user.DisplayName = sanitize.String(*req.DisplayName, 100)
	}
	if req.AvatarURL != nil {
		user.AvatarURL = sanitize.AvatarURL(*req.AvatarURL)
	}
	if req.Locale != nil {
		user.Locale = sanitize.Locale(*req.Locale)
	}

	if err := h.users.Update(r.Context(), user); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	mfaEnabled, mfaMethods := h.mfaState(r, user.ID)

	WriteJSON(w, http.StatusOK, ProfileResponse{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		DisplayName:   user.DisplayName,
		AvatarURL:     user.AvatarURL,
		Locale:        user.Locale,
		MFARequired:   h.mfaSvc != nil && h.mfaSvc.IsRequired(),
		MFAEnabled:    mfaEnabled,
		MFAMethods:    mfaMethods,
		CreatedAt:     user.CreatedAt,
	})
}

// Sessions handles GET /user/sessions.
//
// It lists refresh-token FAMILIES, not devices. A device is a fingerprint, and
// the two are not the same thing in either direction. findOrCreateDevice is
// explicitly non-critical — its errors are logged and do not fail the auth flow —
// and it returns "" when the lookup and the insert both fail, so both the
// password path and the OAuth path can store a family with an empty device_id.
// Listing devices made such a family invisible here and unreachable by the
// per-session revoke: a live, refreshable session that only "sign out everywhere"
// could end. The inverse held too — two families sharing one fingerprint showed
// as one row, so revoking "a session" killed both, and a device carrying no live
// family still listed as an active session.
//
// Device metadata is joined on when the family has one, and its absence is not an
// error: a session with no label is still a session the owner must be able to see
// and end.
func (h *UserHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	families, err := h.tokens.ListActiveFamilies(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// A device lookup failure costs labels, never sessions. Failing the request
	// here would leave the owner unable to see a live session because a cosmetic
	// join could not be read.
	byDevice := map[string]*model.Device{}
	if devices, devErr := h.devices.ListByUser(r.Context(), claims.Subject); devErr == nil {
		for _, d := range devices {
			byDevice[d.ID] = d
		}
	}

	sessions := make([]SessionInfo, 0, len(families))
	for _, f := range families {
		lastUsed := f.LastUsedAt
		info := SessionInfo{
			ID:          f.FamilyID,
			DeviceID:    f.DeviceID,
			CreatedAt:   f.CreatedAt,
			ExpiresAt:   f.ExpiresAt,
			FirstSeenAt: f.CreatedAt,
			LastSeenAt:  &lastUsed,
		}
		if d, ok := byDevice[f.DeviceID]; ok {
			info.FriendlyName = d.FriendlyName
			info.IP = d.IP
			info.UserAgent = d.UserAgent
			info.Trusted = d.Trusted
			info.FirstSeenAt = d.FirstSeenAt
		}
		sessions = append(sessions, info)
	}

	WriteJSON(w, http.StatusOK, SessionsResponse{Sessions: sessions, Total: len(sessions)})
}

// RevokeSession handles DELETE /user/sessions/{id}.
//
// The id is a refresh-token family id, which is what Sessions now lists.
// Ownership is established by finding the family among the caller's own active
// families rather than by trusting the path value, so one user cannot end
// another's session, and an id belonging to nobody is a 404 rather than an
// existence oracle.
//
// A device id is still accepted, for one release, because a client that cached an
// id from the previous listing must not be met with a 404 on upgrade. That path
// is unchanged: it revokes the device's tokens and deletes the device row.
func (h *UserHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		WriteError(w, http.StatusBadRequest, "missing_session_id")
		return
	}

	families, err := h.tokens.ListActiveFamilies(r.Context(), claims.Subject)
	if err != nil {
		// Never fall through to the device alias on a read failure: that would
		// answer "revoked" without having established that the caller holds the
		// session named.
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	for _, f := range families {
		if f.FamilyID != sessionID {
			continue
		}
		if err := h.tokens.RevokeFamily(r.Context(), sessionID); err != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		// The device row outlives the session on purpose: it is the record of a
		// known fingerprint, and other live families may still be bound to it.
		h.logSessionRevoke(r, claims.Subject, f.DeviceID, "session")
		WriteJSON(w, http.StatusOK, StatusResponse{Status: "revoked"})
		return
	}

	// Verify device belongs to user
	device, err := h.devices.GetByID(r.Context(), sessionID)
	if err != nil || device == nil || device.UserID != claims.Subject {
		WriteError(w, http.StatusNotFound, "session_not_found")
		return
	}

	// Revoke all refresh tokens for this device first
	if err := h.tokens.RevokeByDeviceID(r.Context(), sessionID); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := h.devices.Delete(r.Context(), sessionID, claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	h.logSessionRevoke(r, claims.Subject, sessionID, "session")
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "revoked"})
}

// RevokeAllSessions handles DELETE /user/sessions (sign out everywhere).
func (h *UserHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.tokens.RevokeAllForUser(r.Context(), claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	// Also remove all devices so sessions list is cleared
	if err := h.devices.DeleteAllForUser(r.Context(), claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	h.logSessionRevoke(r, claims.Subject, "", "all")
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "all_sessions_revoked"})
}

// Devices handles GET /user/devices.
func (h *UserHandler) Devices(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	devices, err := h.devices.ListByUser(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	result := make([]DeviceInfo, 0, len(devices))
	for _, d := range devices {
		result = append(result, DeviceInfo{
			ID:           d.ID,
			FriendlyName: d.FriendlyName,
			Trusted:      d.Trusted,
			IP:           d.IP,
			UserAgent:    d.UserAgent,
			LastSeenAt:   d.LastSeenAt,
		})
	}

	WriteJSON(w, http.StatusOK, DevicesResponse{Devices: result, Total: len(result)})
}

// RenameDevice handles PATCH /user/devices/{id}.
func (h *UserHandler) RenameDevice(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	deviceID := r.PathValue("id")
	if deviceID == "" {
		WriteError(w, http.StatusBadRequest, "missing_device_id")
		return
	}

	// Verify device belongs to user
	device, err := h.devices.GetByID(r.Context(), deviceID)
	if err != nil || device == nil || device.UserID != claims.Subject {
		WriteError(w, http.StatusNotFound, "device_not_found")
		return
	}

	var req struct {
		// FriendlyName is the replacement label for this device.
		// Required. Trimmed; empty or whitespace-only is 400
		// name_required. Longer than 100 runes is 400 name_too_long.
		// Control characters other than tab are 400 name_invalid_chars.
		// This is how a user overrides the User-Agent-derived name the
		// login path stored.
		FriendlyName string `json:"friendly_name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	name := strings.TrimSpace(req.FriendlyName)
	if name == "" {
		WriteError(w, http.StatusBadRequest, "name_required")
		return
	}
	if utf8.RuneCountInString(name) > 100 {
		WriteError(w, http.StatusBadRequest, "name_too_long")
		return
	}
	// Reject control characters
	for _, r := range name {
		if r < 0x20 && r != '\t' {
			WriteError(w, http.StatusBadRequest, "name_invalid_chars")
			return
		}
	}
	name = sanitize.String(name, 100)

	if err := h.devices.UpdateFriendlyName(r.Context(), deviceID, name); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, RenameResponse{Status: "updated", FriendlyName: name})
}

// DeleteDevice handles DELETE /user/devices/{id}.
func (h *UserHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	deviceID := r.PathValue("id")
	device, err := h.devices.GetByID(r.Context(), deviceID)
	if err != nil || device == nil || device.UserID != claims.Subject {
		WriteError(w, http.StatusNotFound, "device_not_found")
		return
	}

	// Revoke all refresh tokens for this device first
	if err := h.tokens.RevokeByDeviceID(r.Context(), deviceID); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := h.devices.Delete(r.Context(), deviceID, claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	h.logSessionRevoke(r, claims.Subject, deviceID, "device")
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "device_removed"})
}
