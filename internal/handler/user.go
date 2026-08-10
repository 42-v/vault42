package handler

import (
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/sanitize"
	"github.com/42-v/vault42/internal/service"
)

// UserHandler handles user profile and session management.
type UserHandler struct {
	users   repository.UserRepository
	devices repository.DeviceRepository
	tokens  repository.RefreshTokenRepository
	mfaSvc  *service.MFAService
}

// NewUserHandler creates a new user handler.
func NewUserHandler(users repository.UserRepository, devices repository.DeviceRepository, tokens repository.RefreshTokenRepository, mfaSvc *service.MFAService) *UserHandler {
	return &UserHandler{users: users, devices: devices, tokens: tokens, mfaSvc: mfaSvc}
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
func (h *UserHandler) Sessions(w http.ResponseWriter, r *http.Request) {
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

	sessions := make([]SessionInfo, 0, len(devices))
	for _, d := range devices {
		sessions = append(sessions, SessionInfo{
			ID:           d.ID,
			FriendlyName: d.FriendlyName,
			IP:           d.IP,
			UserAgent:    d.UserAgent,
			Trusted:      d.Trusted,
			LastSeenAt:   d.LastSeenAt,
			FirstSeenAt:  d.FirstSeenAt,
		})
	}

	WriteJSON(w, http.StatusOK, SessionsResponse{Sessions: sessions, Total: len(sessions)})
}

// RevokeSession handles DELETE /user/sessions/{id}.
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
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "device_removed"})
}
