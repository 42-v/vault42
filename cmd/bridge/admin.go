package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
)

// AdminHandler provides admin API endpoints for the bridge.
type AdminHandler struct {
	flags *FlagStore
	token string
}

// NewAdminHandler creates admin handlers protected by a bearer token.
func NewAdminHandler(flags *FlagStore, token string) *AdminHandler {
	return &AdminHandler{flags: flags, token: token}
}

// ServeFlag handles POST /bridge/flag (flag an IP) and DELETE /bridge/flag (unflag).
func (ah *AdminHandler) ServeFlag(w http.ResponseWriter, r *http.Request) {
	if !ah.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodPost:
		ah.flagIP(w, r)
	case http.MethodDelete:
		ah.unflagIP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServeFlags handles GET /bridge/flags (list all flagged IPs).
func (ah *AdminHandler) ServeFlags(w http.ResponseWriter, r *http.Request) {
	if !ah.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries := ah.flags.List()
	if entries == nil {
		entries = []FlagEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ // #nosec G104 -- HTTP response encoding best-effort
		"flags": entries,
		"count": len(entries),
	})
}

func (ah *AdminHandler) flagIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(ip) == nil {
		http.Error(w, "ip is invalid", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "manual flag"
	}

	ah.flags.Flag(ip, req.Reason, 100)
	log.Printf("bridge: admin flagged %s reason=%q", ip, req.Reason)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{ // #nosec G104 -- HTTP response encoding best-effort
		"status": "flagged",
		"ip":     ip,
	})
}

func (ah *AdminHandler) unflagIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.IP == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}

	if !ah.flags.Unflag(req.IP) {
		http.Error(w, "ip not flagged", http.StatusNotFound)
		return
	}

	log.Printf("bridge: admin unflagged %s", req.IP)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ // #nosec G104 -- HTTP response encoding best-effort
		"status": "unflagged",
		"ip":     req.IP,
	})
}

func (ah *AdminHandler) authenticate(r *http.Request) bool {
	if ah.token == "" {
		return false
	}

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}

	provided := auth[7:]
	return subtle.ConstantTimeCompare([]byte(provided), []byte(ah.token)) == 1
}
