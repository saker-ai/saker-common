# 统一账号生命周期与发布验收

适用范围：Chat、Peek、Lanner 国内/海外和 Corpus。微信扫码的申请、平台发布及真机验收不在本批范围。

## 身份与会话

Wardn 原生 Casdoor 是唯一账号、停用和全局撤销权威。共享 SDK 的 `Accounts` 查询固定同源端点，使用服务端应用凭据，按 issuer/client/region 配置隔离缓存。缓存最多两秒、有界、合并并发查询；过期正向结果不会在故障时继续使用。故障返回 `ErrUnavailable`，停用、删除或版本不符返回 `ErrRevoked`，两者必须区分。

登录回调先校验 OIDC，再用仍有效的原生 ID token 调用 `Capture`。业务会话保存不可变 subject 与原生撤销版本，不保存上游 bearer token。原生退出所有应用、停用账号会提升持久化版本；重新启用或重新登录不能使旧版本会话恢复。业务权限、租户、显式账号关联仍由各应用维护，不按邮箱合并。

普通退出只结束本应用会话；“退出所有应用和设备”打开 Wardn 原生确认页。GET 不执行退出；确认 POST 验证原生用户、来源与 CSRF，再复用原生全局退出逻辑。所有设备指继承该统一身份的业务设备凭据，不包含应用独立密码账号或独立管理员服务密钥。账号状态在下一次受保护请求时核验，正向缓存上限两秒；浏览器界面更新时间还取决于请求频率和网络延迟。

Chat 将版本带入网页、原生设备与派生执行授权，并在持续执行授权核验时检查。Lanner 配对码、执行器、Pulse 设备/API token 继承签发来源的版本，不直接拿当前版本给旧凭据升级。Corpus 在本地 access/refresh JWT 中签入来源及版本，刷新、租户切换须保留来源；独立密码登录仍保留。本地退出和业务撤销仍有效。

旧 Chat/Peek 会话的缺省版本为零，第一次全局撤销后失效。Lanner 旧的摘要身份无法反查原生 subject，需重新登录一次建立绑定。Corpus 旧 JWT 未记录登录来源，在启用 Wardn 的部署中要求重新登录一次；重新签发的独立密码会话带明确 local 来源。该升级不修改原账号、密码、知识库、公开昵称或权限。

## 私有资料

资料刷新与状态检查共用一次请求，统一过滤 UUID 和未验证邮箱形状的名称。Chat 更新当前账号名称；Peek 仅更新仍等于提供方默认值的名称，保留用户自定义昵称；Lanner 更新私有 work_users 名称，社区公开别名保持原值；Corpus 返回 `account_name/account_avatar`，不重命名业务 username。Corpus 打开账号菜单时重新校准 `/auth/me`，首屏继续合并重复请求。

## 发布清单与门禁

`python3 scripts/wardn_release.py inventory --root /workspace --output source.json` 记录六个独立仓库的提交、工作区状态与 SDK 版本。最终发布使用干净、已提交、远端可独立 import 的同一 SDK 版本；不能用临时 go.work 或本地 replace 作为交付结果。

在 source.json 的服务组件中填入构建收据的 `binary_sha256`。运行收据的 `components` 按相同组件名提供：`commit`、`binary_sha256`、`backup_sha256`、`rollback_sha256`、`schema_version`、`migration`（PASS/UNCHANGED）、`health`（PASS）、`data_preservation`（PASS）；sdk 提供提交及 `consumer_import: PASS`。`acceptance` 必须包含 `sso/profile_refresh/disable_reenable/global_logout/old_token_replay/rollback` 的实际 PASS，另需 `cleanup: PASS`。

执行 `python3 scripts/wardn_release.py verify --manifest source.json --runtime runtime.json --root /workspace --output verification.json`。任何缺项、NOT_RUN、SDK 不一致、源码漂移、二进制摘要不符或清理失败均为非零退出；工具不部署、不迁移、不调用 hosted CI，也不会自行把未执行项目填为 PASS。备份/回退的摘要来自各应用既有发布脚本；回退二进制必须兼容已应用的增量迁移，并验证不会使已撤销会话恢复。

## 巡检

公开健康检查：`python3 scripts/wardn_release.py health --config deploy/wardn-probe/health.example.json --output health.json`。它访问实际就绪/元信息接口、检查已退役 global 路由仍为 410，不跟随重定向。健康检查不能替代真实登录验收。

完整生命周期：`python3 scripts/wardn_probe.py --config ~/.config/wardn-probe/lifecycle.json --output lifecycle.json`。配置文件和密码文件均须权限 0600，密码只从本机文件读取。示例结构（没有真实凭据）：

```json
{
 "issuer":"https://wardn.bxf.me/identity",
 "admin_name":"admin",
 "admin_password_file":"/private/wardn-admin-password",
 "login_application":"saker-web",
 "apps":{
  "chat":"https://chat.bxf.me/cn",
  "peek":"https://peek.bxf.me/cn",
  "lanner-cn":"https://lanner.bxf.me/cn",
  "lanner-global":"https://lanner.bxf.me/global",
  "corpus":"https://corpus.bxf.me"
 }
}
```

脚本只创建带 `wardn-probe-` 前缀的随机临时原生账号；一次密码登录后验证所有应用 SSO、名称更新、稳定 ID、公开别名保留、停用后旧会话拒绝、重新启用不复活旧会话、重新登录和全局退出。finally 删除并复查自己的临时 Wardn 账号；输出只有检查结果、耗时和清理状态，不保存密码、cookie、JWT 或原始响应。SIGTERM 会进入清理。应用内审计投影保留；若进程被 SIGKILL 或服务器失联，应按审计记录清理遗留 synthetic 账号，不能把该次验收标为通过。

提供 `deploy/wardn-probe/` 的 systemd user service/timer 模板：健康检查五分钟一次，完整生命周期每周一次。先建立 `~/.local/state/wardn-probe`、受限配置和日志告警接收机制，再安装 user units 并启用 timer。完整生命周期 timer 只应在全部应用升级并通过首次人工观察后启用；否则保持未启用并记录 NOT_RUN。服务以最小文件写入范围运行，不含任何凭据。

## 本地验证

工具回归：`python3 -B -m unittest discover -s scripts -p 'test_wardn_operations.py' -v`。验证缺失证据不能放行、二进制及源码漂移、清理范围、凭据文件权限、禁止携带 token 的跨域跳转。

应用门禁使用各仓库 Makefile。Corpus service 额外检查应区分普通构建和 `corpus_native_tools` 构建：原生 DuckDB 用例只能在原生工具构建运行，默认回归不应因缺少原生工具而虚假失败；外部服务验收需独立、限时并记录真实执行情况。
