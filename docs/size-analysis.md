# Binary size analysis

`gsa` is [go-size-analyzer](https://github.com/Zxilly/go-size-analyzer).

The [Binary size profile](../.github/workflows/size.yml) workflow:

1. Builds the lite control + encrypted transport with `ts_omit_netstack,ts_omit_gro`.
2. Builds a baseline that instantiates `tsnet.Server` and therefore includes its netstack dependencies.
3. Attempts to build the actual Yuhaiin application on Linux/amd64 without CGO.
4. Reports total size, stripped size, package-level `gsa` text/JSON, and a diff.

Run it manually via **Actions > Binary size profile (gsa) > Run workflow**.
The JSON and text reports are available as a `tailscale-lite-size-gsa` artifact
for 14 days. An ordinary `go.mod` dependency is not necessarily linked, and
symbol-attributed package sizes need not sum to every section byte. For byte
comparisons use matched build settings, OS, Go version and CGO setting.

To run locally:

```bash
brew install go-size-analyzer
CGO_ENABLED=0 go build -o yuhaiin ./cmd/yuhaiin
gsa --hide-sections --hide-std yuhaiin
gsa -f json --compact -o yuhaiin-gsa.json yuhaiin
```

The lite/tsnet probes are comparison tools, not benchmarks of the final integrated
Yuhaiin application: until the Yuhaiin adapter migrates to this module, no actual
application-size savings have been established by these measurements alone.
