# Architecture and acceptance criteria

## Data path

Host lightweight TCP/IP stack -> supplied tun.Device -> Tailscale wgengine -> magicsock -> direct UDP, DERP, or peer relay.

The control plane is managed directly by controlclient.Auto. The adapter applies a validated NetMap atomically from the host's perspective and publishes a bounded status snapshot. No tsnet.Server, OS TUN, DNS manager socket, embedded web client or ipnlocal LocalBackend is used.

## Security boundaries

- Do not silently use system sockets when a custom underlay was configured.
- Do not allow a Tailnet route to become an OS route when it disappears. Route lookup returns failure.
- Apply ACL filters to the engine and magicsock; never enable a permissive default.
- Fail closed when Tailnet Lock (TKA) is enabled until signature verification is implemented and tested.
- Persist identity secrets only in private state files. Do not include keys in logs or public status.
- Serialize status and control callbacks, address changes, and Close; new ownership of a state file must be explicit.

## Follow-up integration work

1. Verify the full control auth/login flow with local testcontrol and Headscale, plus reauth and key rotation.
2. Replace raw stored identity with migration from existing Yuhaiin tsnet tailscaled.state.
3. Implement MagicDNS names, ExtraRecords, split-DNS routes and negative responses as an optional host resolver adapter.
4. Verify per-peer ACL capabilities, jail rules, subnet routes, endpoint changes and TKA.
5. Test dual stack, fragmented packets, UDP rebind, Linux/macOS/Windows/Android/iOS, DERP failover and network changes.
6. Compare linked binary symbol sizes with and without the dependency; require `go list -deps` to contain no gVisor.
7. Switch Yuhaiin's outbound behind a feature flag only after the tests and benchmarking pass.

Not all properties listed here have been validated. Keeping incomplete behavior explicit is preferable to silently weakening the security model.
