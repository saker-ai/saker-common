# Wardn SDK v0.2.0 全量接入与线上验收

2026-11-17 已将 SDK 及四个应用的完整 Wardn 登录路径提交、推送并合入主干，随后上线。SDK 独立 module 为 `github.com/saker-ai/saker-common/wardn@v0.2.0`。现有应用的 discovery、授权 URL、换码、签名/issuer/audience/nonce/owner 校验统一由 SDK 执行，数据库一次性事务消费、业务权限、原账号与区域归属由应用适配。

| 组件 | 线上运行提交 | 验收 |
| --- | --- | --- |
| SDK | `wardn/v0.2.0` / `1ad6633` | 独立远端 import、race/vet/build、国内与海外真实 OIDC、重放拒绝 |
| Chat / SakerWeb | `a07d81ee` | 网页 SSO、发布前 Chat 会话、subject/tenant 保持、手机及桌面真实 PKCE/刷新/退出撤销 |
| Peek | `9ac0c9b3` | 真正 Wardn SSO、账号显示、后续会话访问、全包 race；独立 peek schema 19→25 |
| Lanner 国内和海外 | `21ff2cc9` | 双区真实 OIDC、原账号 ID/slug 保持、私有邮箱与公开昵称区分；两库迁移 2→4 |
| Corpus | `572a53be` | 原生账号保留启动门禁、真实 SSO、原生 ID 保持、普通用户权限、昵称非 UUID、原生工具构建与 Debian 12 运行探针 |

Chat 的同期输入框按钮修复也保留在 a07 中。浏览器本地 OIDC fixture 补齐原生签名 owner 字段后通过联合验收；生产 SDK 不放松校验。主干后续 fixture/docs 提交为 c925ac54，运行源码仍准确记录为 a07。

同一真实 Wardn 浏览器会话连续两轮进入 Chat、Peek、Lanner 国内/海外、Corpus，均无再次输入凭据，账号 ID 保持。独立手机与桌面会话完成 PKCE 登录、名称显示、bearer 请求、刷新和退出撤销。账号展示采用昵称或已验证邮箱；各应用业务用户名的既有规则保留，邮箱不用于自动合并账号。

旧 Chat cookie 在发布后实际验证仍可用。Peek 的原 cookie 在中间验收时主动重新登录续建，故没有把后续 cookie 冒称为发布前 cookie；已验证新会话及原账号，服务配置、身份绑定键和会话策略保持。旧客户端缓存的名称须重新登录后刷新。

数据库升级前保留备份，Lanner 两个库的增量迁移先做事务回滚演练，Peek 仅备份/迁移专用 peek schema，共用 public schema 未改。为这两个应用准备了兼容新 schema 的回退构建。Corpus 保持原生 schema 与全部原有密码、知识库、账号绑定。

SDK、Chat 完整 Go race/integration、Peek 标准门禁与全包 race、Lanner 标准门禁及签名登录/隐私回归均通过。Corpus 的相关 Wardn/OIDC race、原生工具标签认证/表格摘要检查、enterprise 全模块 race、根模块与前端类型/18 项测试通过。额外未启用原生工具标签的 WeKnora service 全包检查未通过；其中历史 fake 竞态已在未修改主干复现，详见 Corpus `docs/wardn-sdk-test-boundaries-20261117.md`，不把它标为通过。

全部活跃健康端点 200，已退役的 Chat/Peek global 路由保持 410。临时账号仅为本次 SDK 验收创建；结束后业务会话已退出、Corpus 原生令牌已撤销、Wardn 临时账号已删除并复查不存在；业务审计投影保留。未修改或登录任何真实用户账号。

准确二进制校验值、日志 SHA-256、构建/迁移与线上验收范围见 [结构化验收记录](wardn-sdk-rollout-20261117.json)。密钥、cookie、令牌、数据库和原始响应仅保存在本机受限目录，未进入仓库。
