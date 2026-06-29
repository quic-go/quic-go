# Repositories, Branches & Dependencies

This document records every repository touched by the post-quantum work, which
branch holds what, and how they depend on each other.

## Dependency graph

```
            depends on (build/run)            captured as patch in
  quic-go-pqc ──────────────────────▶ go-pqc ──────────────────▶ quic-go-pqc
  (pqc-native)   patched toolchain    (pqc-crypto-tls)   docs/pqc-tls/crypto-tls-pqc.patch
       │                                   │
       │ forked from                       │ forked from
       ▼                                   ▼
  quic-go (upstream/master)           golang/go (master @ 6565f551)
```

- **quic-go-pqc @ `pqc-native`** is a near-stock quic-go that **must be built and
  run with the patched Go toolchain** (`go-pqc`). Its only PQC code is the
  `pqctls/` package + examples/tests; the quic-go core is unchanged from upstream.
- **go-pqc @ `pqc-crypto-tls`** is the patched Go toolchain providing the PQC
  primitives in `crypto/tls` + `crypto/x509`.
- The toolchain patch is also stored **inside** quic-go-pqc as
  `docs/pqc-tls/crypto-tls-pqc.patch`, so the changes are version-controlled in
  the pushable repo even before the Go fork is published.

## Repositories

### 1. `quic-go-pqc` — application repo (your fork)

- **Remote (origin):** `git@github.com:MauricioMachadoFF/quic-go-pqc.git`
- **Upstream:** `https://github.com/quic-go/quic-go.git`
- **Local checkouts:**
  - `~/Development/quic-go-pqc` — main working tree (branch `pqc-tls-module`)
  - `~/Development/quic-go-pqc-native` — git worktree (branch `pqc-native`)

| Branch | Status | Contents |
|--------|--------|----------|
| `master` | local mirror | (do not use for PQC) |
| `post-quantum-crypto-draft` | **kept, untouched** | Original embedded-qtls + cloudflare/circl approach |
| `pqc-tls-module` | **kept, untouched** | Consolidation of PQC into embedded `internal/qtls` (superseded) |
| `pqc-native` | **current** | Native adoption: pure upstream core + `pqctls/` + docs; built with patched toolchain |

Changed/added on `pqc-native` (vs `upstream/master`): `pqctls/*`,
`example/pqc_client`, `example/pqc_server`, `pqc_test.go`, `docs/pqc-tls/*`.
**No** changes to quic-go core files.

### 2. `go-pqc` — patched Go toolchain (NOT yet published)

- **Remote (origin):** `https://go.googlesource.com/go` (read-only Google source)
- **Local checkout:** `~/Development/go-pqc`
- **Branch:** `pqc-crypto-tls` (base: `golang/go` master @ `6565f551`)
- **Commit:** `crypto/tls,crypto/x509: add pure ML-KEM-768 and composite Ed25519+ML-DSA`

> There is currently **no personal GitHub fork** of Go to push this to. To
> publish it, create a fork (e.g. `github.com/MauricioMachadoFF/go`), add it as a
> remote, and push `pqc-crypto-tls`. Until then, the patch lives in
> `quic-go-pqc/docs/pqc-tls/crypto-tls-pqc.patch`.

## Reproducing the toolchain from the patch

```sh
git clone https://go.googlesource.com/go go-pqc
cd go-pqc
git checkout 6565f551 -b pqc-crypto-tls
git apply /path/to/quic-go-pqc/docs/pqc-tls/crypto-tls-pqc.patch
cd src && GOTOOLCHAIN=local ./make.bash
# toolchain is now at ../bin/go
```

(The new file `src/crypto/x509/composite.go` is included in the patch.)

## Build/run wiring

```sh
export GOROOT=~/Development/go-pqc
export GOTOOLCHAIN=local
cd ~/Development/quic-go-pqc-native
$GOROOT/bin/go test -run TestPQC .
```

## Push status (as of writing)

| Repo / branch | Remote | Pushable? |
|---------------|--------|-----------|
| quic-go-pqc / `pqc-native` | `origin` (your fork) | ✅ yes |
| go-pqc / `pqc-crypto-tls` | none owned by you | ⚠️ needs a Go fork first |
