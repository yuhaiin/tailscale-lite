package tailscalelite

import (
    "errors"
    "testing"
)

func TestExplicitUnderlayNeverFallsBackToSystem(t *testing.T) {
    _, err := New(Config{Underlay: &Underlay{}})
    if !errors.Is(err, ErrCustomUnderlayUnsupported) {
        t.Fatalf("New with explicit underlay error = %v, want ErrCustomUnderlayUnsupported", err)
    }
}
