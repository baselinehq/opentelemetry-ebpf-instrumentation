# Baseline capture fork

`baseline/capture-v0.13.0` is based on upstream **v0.13.0**. The module remains
`go.opentelemetry.io/obi`; retain upstream import paths when merging updates.

## Boundary

- `pkg/capture` exposes process discovery, selected HTTP/TLS probes, and a channel
  of `Exchange` records. Callers supply header patterns and a procfs path.
- Flowtrace owns Costgraph header names, labels, container attribution, and metrics.
- The existing upstream configuration, protocols and SDK support remain present.
- Complete TLS HTTP/2 client capture is opt-in (`ebpf.tls_http2_capture`). The
  capture adapter enables it. It replaces native client spans on those connections;
  it is not a replacement for OBI's regular tracing or GenAI body extraction.

## Patch scope

1. HTTP/1 Go payload ownership, connection role and framing fixes.
2. TLS HTTP/2 client chunks with process identity, connection generation and byte
   offsets; userspace HPACK state and per-stream accounting through END_STREAM.
3. The small capture adapter and the two complete-message byte fields on spans.
4. Generated BPF Go bindings and objects, committed separately for Go consumers.

HTTP/2 counts HEADERS, CONTINUATION and DATA frames, including their framing.
It excludes TLS overhead and connection-control frames. Attachment must precede
connection establishment. Missing chunks invalidate that connection's attribution.
Reset/incomplete streams, server push and h2c are excluded. Limits: 64 KiB decoded
headers, 1 MiB per frame/captured call, 512 pending streams per connection. HTTP/1
requires a complete framed message within its 256 KiB capture limit.

## Updating upstream

Merge a selected upstream release into the Baseline branch. Resolve source changes,
then regenerate BPF bindings rather than resolving generated code manually:

```sh
make docker-generate
```

Commit generated `*_bpfel.go` and `*_bpfel.o` files with `git add -f`. Keep generation
separate from source changes. Do not commit dependency `.d` files. Both amd64 and
arm64 artifacts are required. Run targeted Go tests with race detection and the
agent's `integration/flowtrace/run.sh` against this checkout before changing pins.
The privileged live tests currently run on Linux arm64; amd64 is compile-checked.

Publish the fork revision before updating Flowtrace and its consumers. Each main
module must replace `go.opentelemetry.io/obi` with the same immutable Baseline fork
revision: Go does not inherit replacement directives from dependencies. Local
workspaces or the integration harness can replace it with a sibling checkout.

Upstream contributions use separate branches based on upstream/main, containing
only the relevant source change and tests, without Baseline adapters or generated
artifacts. Their acceptance does not gate Baseline releases.
