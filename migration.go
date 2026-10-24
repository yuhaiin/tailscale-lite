package tailscalelite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"tailscale.com/types/key"
	"tailscale.com/types/logid"
	"tailscale.com/types/persist"
)

// MigrateLegacyState imports the single, currently selected tsnet profile into
// the lite state format without changing or deleting the old file. Old-machine
// identities must not silently register a new node on upgrade.
//
// The legacy file is Tailscale's FileStore: a JSON map of state keys to
// base64-encoded state bytes. Only the unambiguous selected profile is imported.
// All mismatched or incomplete identity records fail closed.
func MigrateLegacyState(legacyPath, litePath, controlURL string) error {
	if _, err := os.Lstat(litePath); err == nil {
		return nil // the existing lite identity is authoritative
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check lite identity: %w", err)
	}
	fi, err := os.Lstat(legacyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check legacy identity: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return errors.New("tailscale-lite: legacy state must be a private regular file (0600)")
	}
	if err := checkPrivateFile(legacyPath, fi); err != nil {
		return fmt.Errorf("legacy identity permissions: %w", err)
	}
	content, err := os.ReadFile(legacyPath)
	if err != nil {
		return fmt.Errorf("read legacy Tailnet identity: %w", err)
	}
	var entries map[string][]byte
	if err := json.Unmarshal(content, &entries); err != nil {
		return fmt.Errorf("decode legacy Tailscale store: %w", err)
	}
	var machine key.MachinePrivate
	if err := machine.UnmarshalText(entries["_machinekey"]); err != nil || machine.IsZero() {
		return errors.New("tailscale-lite: legacy store has no valid machine private key")
	}
	profileKey := string(entries["_current-profile"])
	if profileKey == "" {
		return errors.New("tailscale-lite: legacy store has no selected profile")
	}
	if strings.HasPrefix(profileKey, "_") {
		return errors.New("tailscale-lite: invalid selected profile key")
	}
	type profile struct {
		Key        string
		ControlURL string
	}
	var known map[string]profile
	if err := json.Unmarshal(entries["_profiles"], &known); err != nil || len(known) == 0 {
		return errors.New("tailscale-lite: missing or malformed legacy profile registry")
	}
	var selected *profile
	for _, p := range known {
		if p.Key != profileKey {
			continue
		}
		if selected != nil {
			return errors.New("tailscale-lite: ambiguous legacy profile identity")
		}
		copyOf := p
		selected = &copyOf
	}
	if selected == nil {
		return errors.New("tailscale-lite: selected legacy profile is not in registry")
	}
	normalizeURL := func(url string) string {
		url = strings.TrimRight(strings.TrimSpace(url), "/")
		if url == "" {
			return "https://controlplane.tailscale.com"
		}
		return url
	}
	if normalizeURL(selected.ControlURL) != normalizeURL(controlURL) {
		return errors.New("tailscale-lite: legacy profile control URL does not match configuration")
	}
	profileData := entries[profileKey]
	if len(profileData) == 0 {
		return errors.New("tailscale-lite: selected legacy profile has no preferences")
	}
	var prefs struct {
		ControlURL string
		Persist    *persist.Persist
		LoggedOut  bool
	}
	if err := json.Unmarshal(profileData, &prefs); err != nil {
		return fmt.Errorf("decode selected legacy profile: %w", err)
	}
	if normalizeURL(prefs.ControlURL) != normalizeURL(controlURL) {
		return errors.New("tailscale-lite: legacy preferences control URL does not match configuration")
	}
	if prefs.Persist == nil || prefs.Persist.PrivateNodeKey.IsZero() {
		return errors.New("tailscale-lite: legacy profile is missing its node private key")
	}
	if prefs.LoggedOut {
		return errors.New("tailscale-lite: legacy profile is logged out; refuse automatic identity migration")
	}
	id, err := logid.NewPrivateID()
	if err != nil {
		return fmt.Errorf("create migrated backend log ID: %w", err)
	}
	return writeState(litePath, diskState{
		MachineKey:   machine,
		Persist:      *prefs.Persist,
		BackendLogID: id.Public().String(),
	})
}
