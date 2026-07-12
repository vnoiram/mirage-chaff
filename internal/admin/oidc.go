package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"golang.org/x/oauth2"
)

// oidcAuth holds the OIDC provider + role mapping for SSO login.
type oidcAuth struct {
	verifier    *oidc.IDTokenVerifier
	oauth       *oauth2.Config
	groupsClaim string
	roleMap     map[string]Role
}

// newOIDC builds an OIDC authenticator from config. It performs provider
// discovery (network), so callers should treat failure as non-fatal and fall
// back to local accounts.
func newOIDC(ctx context.Context, c config.OIDCConfig) (*oidcAuth, error) {
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	groupsClaim := c.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	rm := map[string]Role{}
	for group, role := range c.RoleMap {
		rm[group] = Role(role)
	}
	return &oidcAuth{
		verifier:    provider.Verifier(&oidc.Config{ClientID: c.ClientID}),
		groupsClaim: groupsClaim,
		roleMap:     rm,
		oauth: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  c.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
	}, nil
}

// MapGroupsToRole picks the highest-privilege role among the user's OIDC groups
// (admin > editor > viewer). ok is false when no group maps to a role.
func MapGroupsToRole(groups []string, roleMap map[string]Role) (Role, bool) {
	best, found := Role(""), false
	rank := map[Role]int{RoleViewer: 1, RoleEditor: 2, RoleAdmin: 3}
	for _, g := range groups {
		if r, ok := roleMap[g]; ok {
			if !found || rank[r] > rank[best] {
				best, found = r, true
			}
		}
	}
	return best, found
}

const (
	oidcStateCookie = "mc_oidc_state"
	oidcNonceCookie = "mc_oidc_nonce"
)

// handleOIDCLogin redirects the browser to the OIDC provider.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	state := randToken()
	nonce := randToken()
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: state, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: 300,
	})
	http.SetCookie(w, &http.Cookie{
		Name: oidcNonceCookie, Value: nonce, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: 300,
	})
	http.Redirect(w, r, s.oidc.oauth.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

// handleOIDCCallback exchanges the code, verifies the ID token, maps groups to a
// role, and starts a session. Users need not exist in the local store.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(oidcStateCookie)
	if err != nil || c.Value == "" || r.URL.Query().Get("state") != c.Value {
		http.Error(w, "invalid OIDC state", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	tok, err := s.oidc.oauth.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token", http.StatusUnauthorized)
		return
	}
	idTok, err := s.oidc.verifier.Verify(ctx, rawID)
	if err != nil {
		http.Error(w, "id_token verify failed", http.StatusUnauthorized)
		return
	}
	// Verify the ID token nonce echoes the one we set at login (replay defense).
	nc, err := r.Cookie(oidcNonceCookie)
	if err != nil || nc.Value == "" || subtle.ConstantTimeCompare([]byte(idTok.Nonce), []byte(nc.Value)) != 1 {
		http.Error(w, "invalid OIDC nonce", http.StatusBadRequest)
		return
	}
	var claims map[string]any
	if err := idTok.Claims(&claims); err != nil {
		http.Error(w, "claims decode failed", http.StatusUnauthorized)
		return
	}

	username := stringClaim(claims, "preferred_username", "email", "sub")
	role, ok := MapGroupsToRole(claimGroups(claims, s.oidc.groupsClaim), s.oidc.roleMap)
	if !ok {
		s.store.Audit(username, "oidc.login.deny", "no group mapped to a role")
		http.Error(w, "no role for your groups", http.StatusForbidden)
		return
	}

	sess := s.sess.create(username, role)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sess.id, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	s.store.Audit(username, "oidc.login", "role="+string(role))
	http.Redirect(w, r, "/", http.StatusFound)
}

func stringClaim(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := claims[k].(string); ok && v != "" {
			return v
		}
	}
	return "oidc-user"
}

func claimGroups(claims map[string]any, key string) []string {
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		var out []string
		for _, g := range v {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	default:
		b, _ := json.Marshal(v)
		_ = b
		return nil
	}
}
