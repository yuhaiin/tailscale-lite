package tailscalelite

import (
	"strings"
	"testing"

	"tailscale.com/net/netns"
)

func TestUnderlayFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "require underlay", cfg: Config{RequireUnderlay: true}, want: "required"},
		{name: "partial underlay", cfg: Config{Underlay: &netns.Underlay{}}, want: "incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No device or state file: validate underlay before any side effects.
			err := validateUnderlay(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateUnderlay() = %v; want %q", err, tc.want)
			}
		})
	}
}
