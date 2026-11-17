# Wardn 账号生命周期优化验收

2026-11-17 完成第 1–4 项优化，微信小程序申请和真实扫码验收不在本批范围。四个应用统一使用可独立 import 的 `github.com/saker-ai/saker-common/wardn v0.3.1`，没有本地 SDK replace。

| 服务 | 实际部署源码 | 结果 |
| --- | --- | --- |
| Chat | `7a17e66e` | 上线，进程二进制、工作台及客户端下载校验通过 |
| Peek | `b247784e` | 上线，API 和 worker 实际进程均为 v0.3.1 |
| Lanner 中国 / 国际 | `1971fa43` | 双区上线，数据库 4→5，旧表指纹及权限检查通过 |
| Corpus | `640cef03` | 原生 Debian 12 构建上线，保留 Jieba、DuckDB，schema 53 不变 |
| Wardn 原生权威 | 中国 `1679fa2b` / 国际 `88a351fe` | Git 源树相同，原生持久化撤销版本生效 |

## 实际验收

五个应用入口在正式 systemd 巡检服务中完整通过，耗时 197.642 秒，临时账号删除并复查成功。最终使用国际区为 Lanner home，另一次中国区 home 的四入口联合验收也通过。

- 一次 Wardn 登录后访问全部应用，无需再次输入密码。
- 普通退出 Chat 后，Peek 和 Wardn 原生 SSO 仍有效。
- 修改私有昵称后全部应用更新，业务 ID、租户及 Lanner 公开别名保持原值。
- 停用账号后所有旧会话被拒绝；重新启用和再次登录均不复活旧会话。
- 原生全局退出后，旧浏览器、移动端和桌面端凭据失效。
- 移动端、桌面端 PKCE、刷新及旧 refresh token 重放拒绝通过。

第一次五站验收发现 Corpus 的 `ToUserInfo` 丢失私有资料字段，结果记为 FAIL 并清理测试账号；PR #69 补齐响应投影并通过 JSON 响应回归后重发。最终 PASS 不覆盖或改写该失败历史。

## 回归和发布证据

Corpus 默认 service 全包 race 通过（666.255 秒），历史目录/安装竞态重点回归连续 10 次通过，root、enterprise、前端检查通过。最终资料响应修复通过专项 race；兼容 SDK v0.3.0 的回退构建通过同一专项及 Debian 12 运行校验。原生工具全包此前完成 669 秒回归，构建边界见 Corpus 文档。

Chat 认证及关联包集成 race、前端类型及构建检查通过。发布前后有效账号记录及 10 个用户文件指纹相同。Lanner 两区新鲜数据库备份均已隔离恢复，迁移先演练事务回滚再应用；Peek 原有 ledger 及关键业务记录保持。

回退策略已保留兼容撤销版本的构建与证据：Chat、Corpus、Lanner 提供同生命周期源码配 SDK v0.3.0 的离线验证版本；Peek、Wardn 保留当前已验收版本作为已知良好恢复点。没有在线降级或恢复生产数据库，也不允许回退到绕过撤销校验的 v0.2.0 业务包。

发布门禁对六份干净的实际构建提交建立独立 worktree 清单，绑定真实二进制摘要，再校验运行、备份、回退、迁移、账号数据保护与全链路验收，结果 PASS。后续纯文档提交与二进制构建提交分开记录。

## 持续巡检

健康检查每五分钟运行，完整生命周期每周日 04:00（Asia/Shanghai，随机延迟最多 15 分钟）运行，两项 timer 均已启用。巡检从带摘要的受控脚本副本执行，配置与密码文件权限 0600，凭据不进入回执。结果写本机 state，失败进入 systemd failed 状态及 journal；本次也实际捕获 Corpus 单写者发布排空期间的 429，并确认发布后恢复 PASS。

完整回执和日志摘要：[验收结果](verification/wardn-lifecycle-acceptance-20261117.json)、[源码清单](verification/wardn-lifecycle-acceptance-20261117-source.json)、[运行证据](verification/wardn-lifecycle-acceptance-20261117-runtime.json)、[严格门禁](verification/wardn-lifecycle-acceptance-20261117-gate.json)。运维方式见 [wardn-operations.md](wardn-operations.md)。Lanner 和 Corpus 的旧会话需重新登录一次以建立明确身份来源。
