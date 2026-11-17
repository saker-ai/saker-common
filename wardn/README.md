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

## 现有应用的完整协议适配（v0.2）

应用已有原子事务、cookie 和 PKCE 存储时，使用同一 `Client` 的 `AuthorizationURL(AuthorizationRequest)`、`ExchangeCode`、`VerifyToken`；必须先匹配浏览器、验证一次性 state 并原子消费事务，随后才换码。SDK 的 `Begin/Complete` 也使用这些相同协议函数，没有两套令牌验证实现。应用不能省略 nonce 验证或退回自行解析未验证令牌。

`Config.Region` 只选择 Wardn 的传输端点，不改变规范 issuer。已有可信显式配置可使用 `NewWithMetadata`，仍检查所有端点同源和算法。原生客户端提交 S256 challenge，通过 `AuthorizationRequest.CodeChallenge` 保留设备端 PKCE；应用注册的私有回调协议通过 `NativeRedirectScheme` 显式允许且保持回调固定。桌面 loopback 回调需显式允许 loopback HTTP；公开服务端和远程 issuer 仍要求 HTTPS。

## v0.3：会话撤销与资料刷新

用同一服务端配置构造 `accounts, err := wardn.NewAccounts(cfg)`。OIDC 验证通过后，在原生 ID token 尚有效时调用 `Capture(ctx, subject, rawIDToken)`，将返回的 `Revision` 和原有 issuer/sub 一起保存到业务会话；不要持久化该 ID token。

每次受保护访问调用 `Check(ctx, subject, storedRevision)`；成功时可用 `state.Profile().AccountName()` 刷新私有展示名。缓存上限两秒，过期授权遇到上游故障不会继续放行。`ErrRevoked` 对应身份/会话失效，`ErrUnavailable` 对应暂时故障，应返回 503 并保留可重试凭据。

每组固定的 issuer/client/organization/region 配置在服务启动时创建一个 `Accounts` 并复用；不要逐请求创建客户端或再加业务侧身份缓存。SDK 直接访问固定原生账号端点，无需 discovery，也不携带浏览器 Cookie。成功的 `Capture` 会预热至多两秒的正向缓存，让登录后的首屏复用刚验证的账号状态；并发失效或查询时保守跳过预热，晚到的旧版本不能覆盖已知新版本。

同一账号的并发 `Check` 共享一次请求，包括这次请求的失败结果，避免故障时等待者逐个重试；失败不写入缓存，后续独立调用仍会重新查询。过期数据不会在故障时延用，撤销版本必须精确匹配。`Capture` 始终在线验证本次 ID token，不从缓存完成登录。

普通退出撤销应用自己的会话；全局退出跳转 `accounts.GlobalLogoutURL()`，由 Wardn 原生确认页验证用户与 CSRF。派生设备凭据继承签发来源的版本；不能在请求校验时用当前版本覆盖旧版本。

发布、兼容策略和可运行的跨应用巡检见 [统一账号运维说明](../docs/wardn-operations.md)。
