package tailscalelite

import (
	"errors"
	"tailscale.com/net/netns"
)

// validateUnderlay is called before any disk or network side effect.
// A partially populated underlay is unsafe: one missing transport hook
// can bypass the embedding application's policy and dial system sockets.
func validateUnderlay(cfg Config) error {
	if cfg.RequireUnderlay && cfg.Underlay == nil {
		return errors.New("tailscale-lite: custom underlay is required; refusing system-network fallback")
	}
	if cfg.Underlay == nil {
		return nil
	}
	if cfg.Underlay.DialContext == nil || cfg.Underlay.PacketListener == nil || cfg.Underlay.DNSCache == nil {
		return errors.New("tailscale-lite: incomplete custom underlay (TCP, UDP, DNS all required)")
	}
	return nil
}

var _ *netns.Underlay
