# saker-common

Common Go libraries shared by Saker services.

## Packages

### `internaljwt`

`internaljwt` contains the internal JWT claim model, signing, verification,
audience constants, scope constants, and authorization helpers used by Saker
services.

Import path:

```go
import "github.com/saker-ai/saker-common/internaljwt"
```

### `warden`

`warden` contains the core IAM domain used by the Warden service, including
principal/session models, policy evaluation, token issuing, OIDC helpers,
directory reconciliation, stores, and HTTP handlers.

Import path:

```go
import corewarden "github.com/saker-ai/saker-common/warden"
```

Browser OIDC, PKCE exchange, dynamic Casdoor directory projection and SakerWeb
policy setup are described in [OIDC and directory integration](docs/oidc-directory.md).

### `discovery`

Service registration and discovery contracts, environment-based resolution,
Consul, Redis and mDNS helpers live in [discovery/](discovery/).

### `webhub/notify`

The WebHub notification HTTP client and its tests live in
[webhub/notify/](webhub/notify/).

## Development

The current module requires Go 1.26.4 or newer. Run `go test ./...` from
this module for the package suite; external OIDC/directory integration
tests have their own environment requirements. Shared library tests are
not evidence that every downstream service integration has been deployed.

## Versioning

This module is consumed by service repositories through tagged Go module
versions. Do not depend on a local checkout from service `go.mod` files.

```bash
go get github.com/saker-ai/saker-common@v0.1.1
go mod tidy
go test ./...
```

## Compatibility

The current package names preserve the original service imports to keep the
first extraction low risk. Future package renames or deeper splits should be
released as explicit breaking changes with service import updates in the same
change set.
