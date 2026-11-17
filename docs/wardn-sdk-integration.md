# Wardn SDK 接入（2026-11-17）

依赖 `github.com/saker-ai/saker-common/wardn v0.1.0`。这是独立子 module，不引入旧 Warden IAM、Casdoor 服务端或数据库依赖。完整 SDK 和新应用示例见 https://github.com/saker-ai/saker-common/tree/wardn/v0.1.0/wardn 。

SDK 的完整网页 OIDC 客户端提供 discovery 校验、一次性事务接口、state/nonce/S256 PKCE、签名/issuer/audience/owner 校验及默认 SSO 复用。已有应用本次先复用资料归一化；原有事务持久化、JWT 校验、账号绑定、业务会话、权限和区域 home 保持原路径，不声称已全部改用 SDK 的 Begin/Complete。

资料规则：原生 `displayName` 优先，兼容标准 `name` / `preferred_username`；UUID、sub 和无效文本不当昵称。仅接受已验证邮箱（原生 `emailVerified` / 标准 `email_verified`；冲突拒绝）。邮箱不参与账号合并，公开昵称不自动使用完整邮箱。

## 应用排查结果

| 应用 | 原有问题 | 本次适配 |
| --- | --- | --- |
| Chat / SakerWeb | 网页及 native 直接 name → preferred_username → sub，可能显示 UUID | 三入口统一 SDK 私有名称 |
| Peek | 已有邮箱默认名修复，原生 displayName/emailVerified 与标准字段处理不统一 | SDK 归一化，再保留 Peek 自身显示规则 |
| Lanner | UUID 展示已在 98333cf 线上修复，但存在重复逻辑 | 改为共享 SDK，身份编码和公开昵称不变 |
| Corpus | 新 OIDC 业务用户名可取内部 UUID | 使用 SDK 可读昵称，再按原有产品规则生成业务用户名；旧账号不重命名 |

## SDK 与业务边界

Wardn 是唯一身份权威，SDK 是客户端。稳定身份必须是 issuer/sub；email、username、displayName 都是可变资料。SDK 不创建业务用户或持有业务角色，不维护密码库，也不把不同应用的 session cookie 共享到父域。应用自己的登录回调、账号关联、权限、会话撤销和区域目录需要继续保留。

所有业务后端均为 Go，因此第一版发布独立 Go module。网页前端通过自己的服务端登录，不在浏览器中 import 含 ClientSecret 的 SDK。新应用可用完整 New/Begin/Complete；已有应用先复用 Claims，本次没有将经过验证的现有事务存储和授权路径一次性替换。

## 验收和当前发布范围

SDK 标签 `wardn/v0.1.0` 对应代码提交 4622d9a351ef9abdccbe77ab5196e5dbef89945a。`GOWORK=off` 下 SDK race/test/vet/build 通过；独立 consumer 通过远端 go get（无本地 replace）构建，并对线上 cn/global 两条真实原生 OIDC 流程验证了 SSO、稳定身份一致、已验证邮箱回退、公开昵称不暴露邮箱和回调重放拒绝。临时原生账号已删除并复查不存在。

四个应用的适配和检查范围见各自 docs/wardn-sdk.md。应用适配代码尚未部署到线上；SDK 发布不等于各应用发布。Chat 原有 session 的名称仍需重新登录后更新；Corpus 旧业务用户名保留，不承诺登录自动改名。
