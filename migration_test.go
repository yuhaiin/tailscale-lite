package tailscalelite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

func legacyFixture(t *testing.T, dir string, selected, controlURL string) (string, key.MachinePrivate, key.NodePrivate) {
	t.Helper()
	machine, node := key.NewMachine(), key.NewNode()
	machineText, err := machine.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	prefs, err := json.Marshal(struct {
		ControlURL string
		Persist    *persist.Persist
	}{ControlURL: controlURL, Persist: &persist.Persist{PrivateNodeKey: node}})
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := json.Marshal(map[string]struct {
		Key        string
		ControlURL string
	}{"id1": {Key: "profile-A", ControlURL: controlURL}})
	if err != nil {
		t.Fatal(err)
	}
	values := map[string][]byte{
		"_machinekey":      machineText,
		"_profiles":        profiles,
		"_current-profile": []byte(selected),
		"profile-A":        prefs,
	}
	b, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tailscaled.state")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	makeStatePrivate(t, path)
	return path, machine, node
}

func TestMigrateLegacyStatePreservesIdentity(t *testing.T) {
	dir := t.TempDir()
	old, machine, node := legacyFixture(t, dir, "profile-A", "https://control.example")
	next := filepath.Join(dir, "lite.json")
	if err := MigrateLegacyState(old, next, "https://control.example"); err != nil {
		t.Fatal(err)
	}
	state, err := readState(next)
	if err != nil {
		t.Fatal(err)
	}
	if !state.MachineKey.Equal(machine) || !state.Persist.PrivateNodeKey.Equal(node) || state.BackendLogID == "" {
		t.Fatal("migrated machine or node identity changed")
	}
	fi, err := os.Lstat(next)
	if err != nil {
		t.Fatalf("migrated identity permissions: %v, %v", fi, err)
	}
	if err := checkPrivateFile(next, fi); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(old); err != nil {
		t.Fatal("original state was removed", err)
	}
	// Once the new identity exists, do not replace it with a stale store.
	if err := MigrateLegacyState(old, next, "https://other.example"); err != nil {
		t.Fatal(err)
	}
	again, err := readState(next)
	if err != nil || !again.MachineKey.Equal(machine) {
		t.Fatal("existing lite identity was overwritten")
	}
}

func TestMigrateLegacyStateRejectsIncompleteOrCrossControl(t *testing.T) {
	for _, tc := range []struct{ name, selected, control string }{
		{"missing-profile", "not-listed", "https://control.example"},
		{"wrong-control", "profile-A", "https://other.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			old, _, _ := legacyFixture(t, dir, tc.selected, "https://control.example")
			next := filepath.Join(dir, "lite.json")
			if err := MigrateLegacyState(old, next, tc.control); err == nil {
				t.Fatal("invalid legacy state accepted")
			}
			if _, err := os.Lstat(next); !os.IsNotExist(err) {
				t.Fatal("invalid migration wrote lite identity", err)
			}
		})
	}
}

func TestMigrateLegacyStateRejectsWorldReadableAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	old, _, _ := legacyFixture(t, dir, "profile-A", "https://control.example")
	next := filepath.Join(dir, "lite.json")
	makeStatePublic(t, old)
	if err := MigrateLegacyState(old, next, "https://control.example"); err == nil {
		t.Fatal("world readable legacy identity accepted")
	}
	makeStatePrivate(t, old)
	link := filepath.Join(dir, "linked-state")
	if err := os.Symlink(old, link); err != nil {
		t.Skip(err)
	}
	if err := MigrateLegacyState(link, next, "https://control.example"); err == nil {
		t.Fatal("symlink legacy identity accepted")
	}
}
