package tailscalelite

import (
	"os"
	"path/filepath"
	"tailscale.com/types/key"
	"testing"
)

func TestStateRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "identity.json")
	s := diskState{MachineKey: key.NewMachine()}
	if err := writeState(path, s); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("identity permissions: %o", info.Mode().Perm())
	}
	got, err := readState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.MachineKey.Equal(s.MachineKey) {
		t.Fatal("machine key changed")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(path); err == nil {
		t.Fatal("insecure identity accepted")
	}
}
func TestStateRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	if err := os.WriteFile(original, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(original, link); err != nil {
		t.Skip(err)
	}
	if _, err := readState(link); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestStateOwnership(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"identity.json")
 release,err:=claimStatePath(path)
 if err!=nil{t.Fatal(err)}
 if _,err:=claimStatePath(path);err==nil{t.Fatal("duplicate client acquired the same state")}
 release()
 release2,err:=claimStatePath(path)
 if err!=nil{t.Fatalf("released state could not be reclaimed: %v",err)}
 release2()
}
