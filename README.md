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

### `wardn`（独立应用接入 SDK）

新应用对接 Wardn 使用独立 module `github.com/saker-ai/saker-common/wardn`，不引入根 module 的旧 IAM 和存储实现。

```sh
go get github.com/saker-ai/saker-common/wardn@v0.1.0
```

导入 `github.com/saker-ai/saker-common/wardn`。API 与验证规则见 [SDK 说明](wardn/README.md)，应用排查、适配边界和发布状态见 [接入方案](docs/wardn-sdk-integration.md)。根 module 的测试不覆盖此子 module；请另执行 `cd wardn && GOWORK=off go test -race ./...`。
