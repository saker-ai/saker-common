# Wardn 应用接入 SDK

独立 Go module（Go 1.25+），import：

```go
import "github.com/saker-ai/saker-common/wardn"
```

本 module 不依赖 saker-common 根 module、旧 `warden` IAM、GORM、Casdoor 服务端或数据库驱动。它只依赖 coreos OIDC、go-jose 和 oauth2；不创建第二套身份权威。

## 新应用的完整登录流程

服务器初始化一次 `wardn.New(ctx, wardn.Config{...})`。`Issuer` 使用规范地址 `https://wardn.bxf.me/identity`，`DiscoveryURL` 可使用区域应用端点（例如 `/cn/identity/.well-known/<app>/openid-configuration`）。区域 discovery、授权、换码、JWKS 地址的路径可以不同，但必须来自同一 issuer origin；禁止把 `/cn/identity`、`/global/identity` 当成不同身份的 issuer。

`ClientID`、`ClientSecret`、`RedirectURL` 必须属于当前应用；网页、手机、桌面分别注册客户端。凭据只存服务端配置，不能放进前端 bundle。

1. 应用产生至少 32 字节的随机浏览器绑定值，存于自己的 `Secure; HttpOnly; SameSite=Lax` cookie。
2. 实现 `AttemptStore`，用应用数据库保存 `Attempt`。`Consume` 必须按 state 摘要、浏览器摘要原子删除并返回一条记录。例如 SQLite/PostgreSQL：`DELETE FROM login_attempts WHERE state_hash=? AND browser_hash=? RETURNING ...`。过期记录定期清理；不能先查再删。
3. `target, err := client.Begin(ctx, store, browserCookie, false)`；成功后重定向 `target`。默认复用 Wardn 浏览器会话；用户主动重新认证时才传 `true`。
4. 回调使用 `client.Complete(ctx, store, browserCookie, state, code, responseIssuer)`。不记录 query、code、token、cookie、secret 或完整上游错误。
5. 用结果中的 `(identity.Issuer, identity.Subject)` 查找本地账号，再创建应用自己的业务会话。错误时停止登录，不回退到其他身份。`Identity.Key()` 仅供新应用选择存储键格式；已有应用不能修改原先的键编码。
6. 页面私有账号名使用 `identity.Profile.AccountName()`；为空时显示本地化的“已登录账户”。公开昵称使用显式用户资料或 `PublicName()`，不能自动把邮箱公开。

SDK 校验签名、issuer、audience、nonce、azp、nbf、iat、owner 和可选 at_hash；拒绝弱算法、异源 discovery 端点、HTTP 远端、重定向及超过 1 MiB 的响应。换码不自动重试。`AllowInsecureLoopback` 只供显式本地测试；生产必须为 HTTPS。每个请求仍需要应用自己的限流、超时和通用错误页面。

## 现有应用渐进接入

已有安全的事务存储和 OIDC 校验可先复用 `Claims`。先验证令牌，再通过令牌库的 `Claims(&profile)` 解码；`Claims.AccountName()` 本身不验证 JWT，也不能用来授权。

字段规则统一为：`displayName` → 非内部 ID 的 `name` → 非内部 ID 的 `preferred_username` → 已验证邮箱。原生 `emailVerified` 和标准 `email_verified` 都支持；缺失、false 或冲突均不算已验证。UUID、sub、控制字符和过长文本不展示为昵称。完整邮箱只能用于私有账号资料，公开昵称与业务用户名由应用保持现有规则。

各应用继续持有业务数据库、session、角色、租户、账号关联和区域 home。不得按相同邮箱自动合并原账号。登录 Wardn 一次之后，各应用仍分别完成一次 OIDC 回调以建立自己的 session；SDK 不跨子域共享业务 cookie。已有有效 session 的名称缓存何时刷新由应用明确处理。

## 验证与发布

```sh
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
GOWORK=off go build ./...
```

本 module 是子 module，根目录 `go test ./...` 不覆盖它。版本标签采用 `wardn/v0.1.0`；消费者固定已发布版本或不可变伪版本，禁止依赖相邻源码或交付本地 replace。登录协议和账号名称策略的变更必须通过签名令牌、拒绝路径和回调重放测试。
