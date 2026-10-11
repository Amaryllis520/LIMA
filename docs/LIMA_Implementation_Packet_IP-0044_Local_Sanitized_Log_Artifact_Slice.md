# LIMA Implementation Packet — IP-0044 本机脱敏日志 Artifact 存取（首片）

- Packet 版本：`2.0`（2026-10-11；状态 `DESIGN-REWORK / PENDING-MERGE`，docs-only PR #283 呈审对象）
- 修订批次：D1R——v1.0（@`1e6a68743b38795089c56a6edd80d49d0c770e08`）被 Maintainer 否决合并
  （"仅余 P3 文字级"结论被 `MR-66-PR283-D1-REPAIR-AND-IMPLEMENTATION-20261011/v1` 替代）；
  本版按六项 R66 修正整体修订并取代 v1.0，v1.0 保留为历史证据
- Assignment：`ASN-D1R-IP-0044-66-LOCAL-LOG/v1`（2026-10-11；授权指针
  `MR-66-PR283-D1-REPAIR-AND-IMPLEMENTATION-20261011/v1`）
- 编制角色：Packet & Verification Agent（运行模型：无法核验——未取得可独立核验的运行元数据，
  TELEMETRY-MISSING / RUNTIME-UNVERIFIED，不伪造）
- 设计探针：`.pv_tmp/issue66-local-log-2026-10-10/probes/`（P1–P4 为 D1 记录；P5–P8 为 D1R
  新增实测/模型记录，均可复现；下文标注「设计探针实测（probe Px，可复现）」处均以该记录为据）
- 审核探针证据（引用，只读）：`output/issue66-pr283-review-2026-10-11/probe_results.json`

## 1. Header

```text
Source Issue：#66（Artifact Registry 与不可变对象存储；OPEN；labels feature/security/area:storage/priority:high/status:blocked，本片不动 labels）
Issue specification revision：正文 updated_at 2026-09-11T17:39:36Z（V4 FR/NFR/AC/T + V5 覆盖层；V5 节与前文冲突时以 V5 为准）
Delivery role：vertical-slice（#66 首片）
Issue closure impact：PARTIAL（首片完成 ≠ #66 关闭；说明书 §5 清单仍是 mandatory 缺口）
Covered requirements（本片贡献，均为部分/设计层，零 SATISFIED）：FR-01/02/03/04、NFR-01/02、AC-01..03（本机 SQLite/日志子集）、V5-FR-01/02/03/04、V5-AC-01..03（逐条见 §9 映射表）
Not covered requirements：FR-05（migration registry）、FR-06（retention/pin/删除）及 PostgreSQL/report_json 迁移/TTL/GC/tombstone/lineage DAG/多领域 dispatch/S3/生产接线（说明书 §5 全清单）
Upstream IP/PR/merge commits：#58 契约基线与 #94 隐私核心已并入 main `fbbbd619fb0b96efbbb903916ab46dc0daed2214`（本 Packet exact base；详见 §2 DI-007/DI-008）
```

用户可观察结果（首片完成后的真实行为）：调用者提交一份有界 UTF-8 日志及真实租户/任务上下文 →
经真实 #94 storage policy 净化 → 只保存获准内容（净化后字节）并返回既有 `ArtifactReference` →
另一进程重启后仅凭引用与访问上下文读回同一已封存字节并核验身份/权限/大小/摘要。失败不返回未校验
内容、不退回保存原文、不以内联巨型 JSON 降级。

D1R 交付性质声明：本文是**设计冻结（修订版）**——零产品实现、零冻结测试、零 CI 产品证据。六项
R66 修正（R66-01..06）已收敛为唯一合同（§1.2），全部旧相反条款已替换核销（§1.3）。D2 才冻结
验收测试与有效 RED；Implementation 只能在修订 Packet 合并 + 测试冻结 + 有效 RED + Coordinator
IMPL Assignment + 主会话真实派发五条件齐备后启动。

### 1.1 修订说明（D1R）

- 否决与取代：旧 head `1e6a6874`（Packet v1.0）不批准合并；本 v2.0 在同一文件、同一 PR #283、
  同一 IP-0044 上以新 commit 修订，保留 `de7181b3`/`1e6a6874` 历史（不 amend/force）。
- 修订依据：说明书 §4（`e27009ae…93b7`）采纳的六项修正 + D1R Assignment §7 规约与 §11 单值
  裁定 + 审核报告（`da11ba2f…4d0`）与审核探针证据。旧 ER（ERR-IP-0044-D1-v1/v2）与旧 Brief
  结论只适用旧 head（DI-018）；其 SF-01（schema name 计数）复核事实仍有效，SF-04/SF-05/
  SF-07/SF-08 相关表述被本版取代或核销。
- 修订面：协议步骤与签名、错误副作用、预算与限额、故障矩阵、验收映射全部同步；不只追加六段
  声明——§1.3 十六行替换清单逐项核销，全文（含示例、恢复规则、测试计划）无并存反义表述。
- 新增探针：P5（R66-01 字段贯通，真实 API）、P6（R66-03 hash 物理键，win32 文件系统实验）、
  P7（R66-04 预算前置，真实净化复现+协议顺序模型）、P8（R66-02 复用核验，协议模型——非产品
  实测，明确标注）。
- 唯一新错误码：`STORE_CONFIG_CONFLICT`（R66-05，open 时同 root limits 不一致拒绝）；其余错误
  语义复用既有码扩展触发面（R66-02 映射）。
- journal 模式单值选定：**rollback journal（DELETE）**（Assignment §7.5 第 7 条唯一下放项；
  理由与验证边界见 §7.3）。

### 1.2 六项 R66 ↔ 受影响章节/被替换旧条款对照表

| 修正 | 规则摘要（单值） | 本版落点 | 被替换旧条款（v1.0 @1e6a6874 锚点） | 证据/探针 |
|---|---|---|---|---|
| R66-01 | S2 租户绑定检查 `SanitizedPayload.tenant_id`（真实字段层级）；manifest 分项核验（policy_digest 实算比对、classification/retention 接受面） | §4.2 S2、§2.2、§6.1 表述、§8 隐私组 | §4.2 S2 `manifest.tenant_id == store tenant`（约 L121–123） | P5（真实 API 实测）；审核 `probe_results.json`（manifest_has_tenant_id=false） |
| R66-02 | P1 三分支（无目标→发布 / 已存在→受控核验后复用 / 竞态→同等核验）；核验失败稳定失败零副作用；幂等成功同样核验实物；发布+commit 同临界区；错误码复用映射 | §4.2 P1、§4.3、§4.4、§6.1、§7.1d | §4.2 P1「已存在同 digest 文件则复用」+无条件 `os.replace`（约 L131–134）；§4.4 幂等段只看 DB 行（约 L190–194） | P8（协议模型，`is_product_implementation_test=false`）；审核 `existing_blob_protocol_model` |
| R66-03 | `tenant_storage_key=SHA256(tenant_id 精确 UTF-8 字节).hexdigest()`（小写 64-hex，仅物理目录）；逻辑身份精确比较不变；映射版本绑定 fail-closed（`METADATA_CORRUPT`） | §4.4、§7.2、§8 路径组 | §4.4 blob 键 `blobs/<tenant_id>/...`（约 L187–189）；§7.2 路径表与「尾随 `.`/空格…混叠」表述（约 L334–344） | P6（win32 实测；Linux 未验证→D2）；审核 `synthetic_fs` |
| R66-04 | 输出校验（类型/字节/上限交集）先于任何 content staging 写入；输入/输出两步分开；超限零内容写入；S4 只做重读复核；写入原语有上限 | §4.2 S2/S3/S4、§6.1、§7.1、§9.1 NFR-01、§8 | §4.2 S3→S4 时序（约 L124–129）；§6.1「staging 可留诊断行」（约 L281）；§7.1 两层说明（约 L325–327）；§9.1 NFR-01 行（约 L411） | P7（真实净化复现 262,119→365,378 + 顺序模型）；审核实测 |
| R66-05 | 统一限额表（作用域/默认/合法域/硬上限/计数单位/预留-提交-失败-崩溃/稳定错误逐行单值）；计数语义与跨进程额度冻结；单 root 串行临界区+有限等待+SQLite 小记录；同 root limits 不一致→`STORE_CONFIG_CONFLICT`；journal 单值 DELETE | §7.1、§7.3、§7.1d、§8 | §7.1 零散限额行（约 L319–323）；§7.3 无条件 `PRAGMA journal_mode=WAL`（约 L350） | 合同分析级冻结（无实现实测；多进程/crash 兑现归 D2，如实标注）；说明书 §4 R66-05 |
| R66-06 | 公共合同一次冻结：open 签名 policy 必填注入；get 六字段六步校验顺序；持久 handle 与 close 语义；lineage 最小面+`STAGING_STATE_INVALID`「已 abort」触发删除；`SealedLogReceipt`/`RetrievedLogArtifact` 分型（旧单类型删除） | §4.2 get G1–G6、§4.5、§5.1–5.3（含字段表）、§6.1、§10.1 | §4.5 open 只绑 tenant（约 L202–205）；§5.3 签名无 policy（约 L250–268）；§4.2 get G1–G4（约 L139–145）；§6.1「非本 store、已 abort」（约 L284–286）；§10.1 SF-05/SF-08 | Assignment §7.6 逐字裁定 + §11 单值；源码复核（`ArtifactReference` 六字段，§2.2） |

### 1.3 旧条款替换核销清单（Assignment §7.7 十六行，逐项核销登记）

| # | 旧条款（v1.0 锚点） | 处置与落点 | 核销 |
|---|---|---|---|
| 1 | §4.2 S2 `manifest.tenant_id == store tenant`（约 L123） | 删除；替换为 `SanitizedPayload.tenant_id` 精确比较 + manifest 分项核验（§4.2 S2b/S2c） | 已核销 |
| 2 | §4.2 P1 见在即复用 + 无条件 `os.replace`（约 L131–134） | 替换为三分支核验/发布 + 临界区（§4.2 P1、§7.1d） | 已核销 |
| 3 | §4.4 blob 键 `blobs/<tenant_id>/...`（约 L187–189） | 替换为 `tenant_storage_key` 物理键（§4.4、§7.2） | 已核销 |
| 4 | §7.2 `<tenant_id>` 直作路径 + 「尾随 `.`/空格…混叠」（约 L334–344） | hash 键示例；删除「空格」表述（identifier 域不含空格，P6-e）（§7.2） | 已核销 |
| 5 | §4.2 S3→S4 先写 content.bin 再查 `max_sealed_bytes`（约 L124–129） | 输出校验先于任何 staging 写入（§4.2 S2d/S3） | 已核销 |
| 6 | §6.1 `SEALED_BUDGET_EXCEEDED`「staging 可留诊断行」（约 L281） | 零内容写入 + 事先声明有界诊断（§6.1、§7.1 行 2） | 已核销 |
| 7 | §7.1「净化后字节预算（S4，对 staged 净化字节）」（约 L325–327） | 同步为新时序（S2 写前校验；§7.1 末段） | 已核销 |
| 8 | §9.1 NFR-01 行与旧时序矛盾（约 L411） | 与新协议对齐（§9.1 NFR-01） | 已核销 |
| 9 | §7.1 零散限额行（约 L319–323） | 并入统一限额表（§7.1，默认值全保留） | 已核销 |
| 10 | §7.3 无条件 `PRAGMA journal_mode=WAL`（约 L350） | 替换为 DELETE 单值 + 验证边界（§7.3） | 已核销 |
| 11 | §4.5 open 只绑 tenant + §5.3 签名无 policy（约 L202–205、L250–268） | 替换为 §5.3 逐字冻结签名（policy 必填） | 已核销 |
| 12 | §4.2 get G1–G4 未冻结六字段逐项校验（约 L139–145） | 替换为 §4.2 G1–G6 六步顺序表 | 已核销 |
| 13 | §6.1 `STAGING_NOT_FOUND`/`STAGING_STATE_INVALID`「非本 store、已 abort」（约 L284–286） | 「非本 store」删除（同 root 同租户跨实例可重开）；「已 abort」删除（§5.3 handle 触发面、§6.1） | 已核销 |
| 14 | §5.1/5.2/5.3 `SealedLogArtifact` 单类型与 content 双语义、§10.1 SF-08 | 替换为 `SealedLogReceipt`/`RetrievedLogArtifact`；SF-08 核销（§5.1–5.3、§10.1） | 已核销 |
| 15 | §10.1 SF-05（abort 载体 D2 二选一） | 核销（裁定=删除触发条件）；§10.1 仅保留仍真实义务 | 已核销 |
| 16 | §4.3 故障矩阵、§6.1 错误表、§8 测试计划不一致表述 | 同步改写（新增「SEALED 后实物损坏重复 seal」行、限额/计额用例、两平台租户键用例、膨胀反例用例） | 已核销 |

## 2. Design Input Manifest 与 Explicitly Rejected Inputs

### 2.1 Design Input Manifest

| ID | Type | Exact source | Revision | Used for | Authority | Conflict handling |
|---|---|---|---|---|---|---|
| DI-001 | Standard | `docs/ZCODE_LONG_TASK_ISSUE66_LOCAL_LOG_ARTIFACT_AND_DELIVERY_2026-10-10.md` | SHA-256 `947fa9fb…a3b`（编制时亲算一致） | §4 最小行为、§5 边界、§6 顺序、§7 审阅面、§9 反过度设计 | normative（原交接正文） | 与 DI-013 冲突处以 DI-013 为准 |
| DI-002 | Architecture | `docs/LIMA_Issue66_Minimal_Local_Artifact_and_Parallel_Plan_2026-10-10.md` | SHA-256 `0b9facf8…4ef4` | 首片功能边界、协议雏形、验收组 | 设计输入（已确认方向） | 从 DI-001/DI-013 |
| DI-003 | Decision | `.pv_tmp/issue66-local-log-2026-10-10/intent/Maintainer_Intent_MR-66-LOCAL-LOG-FIRST-20261010_v1.md` | SHA-256 `e1de6fff…3c84` | 三项既定选择、授权边界 | evidence | 从 DI-013 |
| DI-004 | Finding | `.pv_tmp/issue66-local-log-2026-10-10/INDEX.md`（任务索引） | 2026-10-10 快照（`eead37ac…d845`） | 恢复事实、开放 PR 零交集 | evidence | 过时时以远端实时刷新为准 |
| DI-005 | Issue | #66 正文（V4+V5）与评论 5559178921/5559627362/5638380471 | spec revision 2026-09-11T17:39:36Z（快存 `recovery/issue66_body.txt`） | 18 个 requirement ID、Add/Modify/Read-only 文件面 | normative（需求真值；V5 优先） | 从 DI-013 |
| DI-006 | Standard | 治理文档三份 + 三角色责任书 | main `fbbbd619` | Packet 结构、PR 契约、角色边界 | normative | 无冲突 |
| DI-007 | Code | `lima/contracts/{common,codec,errors}.py` @ `fbbbd619` | git blob 亲验（§2.2） | Envelope/Reference/BlobReference/codec/limits 复用契约 | current-behavior + normative（冻结 wire 面） | 只读复用，不改 |
| DI-008 | Code | `lima/evidence_privacy/{port,models,policy,classifier,content_scan,fingerprint,errors}.py` @ `fbbbd619` | git blob 亲验（§2.2） | sanitize_for_sink 语义、SanitizedPayload/ClassificationManifest 字段、PrivacyLimits、policy_digest | current-behavior + normative | 只读复用，不改 |
| DI-009 | Code | `lima/store.py`、`lima/repository_cache.py` @ `fbbbd619` | git blob 亲验 | 只读参考：单事务建表、reserve/publish/abort、原子写+fsync 模式 | background-only | 不混用 repository snapshot 生命周期 |
| DI-010 | Code | `lima/contracts/profile.py:1183`、`lima/audit/inventory.py` @ `fbbbd619` | git blob 亲验 | 下一片边界登记 | background-only | 本片不展开 |
| DI-011 | Decision | Coordinator Assignment `ASN-D1-IP-0044-66-LOCAL-LOG/v1` 及附录 A/B/C | SHA-256 `d7c91f05…b976` | 20 条冻结清单（§7.8 继续有效）、18-ID 映射基线、文件边界 | normative（Assignment） | 被 DI-017 增量取代者以 DI-017 为准 |
| DI-012 | Finding | 设计探针 P1–P4 记录（probes/PROBE_LOG.md + 3 脚本） | 2026-10-10 实测（38 PASS / EXIT=0） | 形态判定、digest 实测、绑定实测、双预算、fail-closed | evidence（PASS ≠ 产品正确） | 与源码矛盾时停并上报（本轮无） |
| DI-013 | Standard | `docs/ZCODE_LONG_TASK_ISSUE66_PR283_D1_REPAIR_TO_IMPLEMENTATION_2026-10-11.md` | SHA-256 `e27009ae6576c218f8d27aaf47a113ad357d42fe272a32589367d16f75cc93b7`（本轮复算一致） | 六项修正规则原文（§4）、三段授权、记录修正、D2 覆盖组 | normative（Maintainer 指令正文；最高优先级） | 与其他输入冲突时以本文为准 |
| DI-014 | Decision | `docs/LIMA_Issue66_PR283_D1_Review_and_Ruling_2026-10-11.md` | SHA-256 `da11ba2f4f3f4df9de921f1564e5b75bd8717f4cfdcb2379f39a86da5bdf64d0`（本轮复算一致） | 六项定义与 v1.0 锚点（经 DI-013 采纳升格为修订方向） | normative（经 DI-013 采纳） | 从 DI-013 |
| DI-015 | Finding | `output/issue66-pr283-review-2026-10-11/probe_results.json`（同目录 review_probes.py、remote_snapshot.json、synthetic_fs、复跑结果） | 审核快照（本轮复读一致） | manifest 无 tenant_id/SanitizedPayload 有；262,119→365,378；case/dot alias 实测；坏 blob 复用协议模型 | evidence | 与 P5–P8 探针互证 |
| DI-016 | Decision | `.pv_tmp/issue66-local-log-2026-10-10/intent/Maintainer_Intent_MR-66-PR283-D1-REPAIR-20261011_v1.md` | SHA-256 `076fd1d79ebf4a87651fa61a3e61aa85845339898834955741a456b754aad7d7`（本轮复算一致） | 增量变化集、三段授权触发条件、技术偏好 | evidence | 从 DI-013 |
| DI-017 | Decision | Coordinator Assignment `ASN-D1R-IP-0044-66-LOCAL-LOG/v1`（assignment/D1R_ASSIGNMENT.md） | SHA-256 `de984a61956d2d7d39cfb80461a6243bd94bd8ddf6cae81e42e815f172e122af` | §7 六项修正规约、§7.7 十六行替换清单、§8 验收判据、§11 单值裁定 | normative（Assignment） | 与本派发矛盾时以 Assignment 为准并上报 |
| DI-018 | Finding | 旧 ER 记录（ERR-IP-0044-D1-v1/v2 及勘误链 71f81a08…731）与旧 Brief | **适用旧 head `1e6a6874`**（其「仅 P3」结论被 DI-013 否决） | SF-01（schema name 计数=18）复核事实仍有效；SF-04/SF-05/SF-07/SF-08 相关表述被 R66-03/04/06 取代或核销 | background-only（历史证据） | 从 DI-013 |

### 2.2 关键源码复核（@fbbbd619 git 对象，本 Packet 编制时亲验）

`sanitize_for_sink(EvidencePayload, SinkContext, TenantPolicy)`（port.py，fail-closed）；sink allowlist
`{"storage","log","prompt","api","export"}`（policy.py:17-19）；**`SanitizedPayload`（models.py:215-221）
字段=`sink_kind`/`tenant_id`/`manifest`/`redacted_value`——`tenant_id` 在 SanitizedPayload 上；
`ClassificationManifest`（models.py:203-211）字段恰为 `classification`/`retention_class`/
`policy_version`/`policy_digest`/`entries`/`created_at` 六项，无 `tenant_id`**（P5 真实 API 实测与
DI-015 一致）；**`policy_digest(policy)`（policy.py:28-30）=`compute_content_digest(policy.digest_source())`**；
text 输出形态（classifier.py：PEM/URL 凭据→RESTRICTED 或敏感关键词→SENSITIVE 均返回
`FingerprintRecord`；bare-Base64 span→占位符替换 str；其余→NFC str）；`PrivacyLimits`（models.py:83-87：
32/1 MiB/256 KiB/10k/1000ms）；`ContractLimits`（codec.py:38-43：1 MiB/32/10k/1k/256 KiB）；
`compute_content_digest(bytes)=raw SHA-256 hex`（codec.py:187-196）；Envelope/Reference 规则
（common.py：schema name pattern/≤128B、identifier pattern `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`、
64-hex digest、payload XOR blob_ref、`content_digest==blob_ref.content_digest` hmac 比较、lineage
同租户/同快照/禁自环、4.0 禁 extensions；**`ArtifactReference`（common.py:328-349）六字段=
`schema_name`/`schema_version`/`artifact_id`/`tenant_id`/`repository_snapshot_digest`/
`content_digest`**——get 六字段绑定对象，§4.2 G3）；`TaskStore._init` 单事务建表；
`RepositoryCache` reserve/publish/abort + 原子写 + 目录 fsync。

### 2.3 Explicitly Rejected Inputs

| 被否决项 | 理由 | 出处 |
|---|---|---|
| 单 IP 全承载 #66 全范围 | 显著扩大实现与验收面 | DI-002 §3；DI-001 §5；DI-017 §2 Not-covered |
| prompt/展示/wire 层掩码替代存储前净化 | 净化点必须前置于任何持久化 | DI-001 §4.2、§7 |
| 机械沿用原 Issue「事务写 SEALED metadata→原子 rename」顺序 | 读者见 SEALED 而 blob 未就位的可见窗口 | DI-001 §4.4（DR-PACKET-1） |
| 先实现 S3 SDK / 多后端配置框架 / 插件注册器 / 动态 schema 平台 | 过度设计 | DI-001 §4.1、§9 |
| 全局跨租户 blob 去重或经错误信息泄露他租户对象 | 跨租户必须隔离 + 拒绝不可区分 | DI-001 §4.3 |
| Artifact store 不可用时回退 inline 巨型 JSON / 旧 task report_json | V5-FR-04 禁止静默降级 | DI-005 V5 节 |
| 修改共享契约或既有 schema 版本/公共字段/默认预算以适配本片 | 文件边界禁改；新类型走新增文件 | DI-001 §3；DI-017 §6 |
| 根检出 HEAD 作为源码依据 | 根检出落后；以 `fbbbd619` git 对象读取 | DI-001 §2；DI-004 |
| 用 canonical JSON 摘要或 metadata 整体身份充当封存字节摘要 | digest 必须来自实际净化后封存字节 | DI-001 §4.1；probe P2 |
| **`manifest.tenant_id` 检查层级（v1.0 S2 旧文）** | ClassificationManifest 无该字段（真实 API 实测）；检查 SanitizedPayload.tenant_id | R66-01；P5；DI-015 |
| **blob 复用「见在即用」+ 无条件 `os.replace` 覆盖发布** | seal 成功条件必须含既有实物受控核验；覆盖不是不可变保证 | R66-02；P8 模型；DI-015 |
| **原始 `<tenant_id>` 直作路径组件** | Windows 大小写/尾点目录混叠实测（P6 对照组） | R66-03；P6；DI-015 synthetic_fs |
| **先写 content.bin 再查净化输出预算（v1.0 S3→S4 时序）** | 超限内容已完整落盘，与 NFR-01 矛盾；膨胀反例 262,119→365,378 | R66-04；P7；DI-015 |
| **WAL/DELETE 双轨可选带入 D2** | Assignment §7.5 第 7 条要求单值选定 | R66-05；DI-017 |
| **「尾随空格已被 identifier 接受」表述** | identifier 字符类不含空格 | R66-03；P6-e；DI-015（trailing_space_contract_valid=false） |
| **零散限额行（无作用域/计额/预留语义）** | 统一限额表（R66-05 列规范）取代 | R66-05；DI-013 |
| **seal 返回 `content=b""` 双语义** | 「未读取」与「真实空日志」歧义；分型消除 | R66-06⑤；DI-017 §11.10 |

## 3. Goal / Non-goals

**Goal**（对齐 Assignment §2 与说明书 §1）：在 `fbbbd619` 之上新增 `lima/artifacts/`，交付
「脱敏 UTF-8 日志 Artifact 存取」的本机可运行闭环：真实净化前置（可信 policy 显式注入）、
输出校验先于落盘、blob/metadata 双介质明确提交点（发布前实物核验+跨进程临界区）、跨进程重启
读回并独立核验（六字段绑定）、租户隔离（逻辑精确+hash 物理键）、幂等/并发语义、有限资源与
路径防护、故障点可诊断；配 `tests/artifacts/` 行为验收（D2 冻结）与 `python -m
lima.artifacts.demo` 本机示例。

**Non-goals（本片不做，均为顺序安排而非删除 mandatory）**：PostgreSQL；历史 report_json 迁移；
TTL/GC/pin/tombstone/删除接口；lineage DAG 与多领域 dispatch；S3 后端与 SDK；service/API/UI/queue
接线；真实模型客户端；migration registry（FR-05）；retention 规则执行（FR-06）；真实 Profile
hydration/provenance（下一片，DI-010 边界登记）；多用户身份体系（触发即 DR）；跨租户共享。

## 4. 协议：类型契约、提交点与状态机（D1 §7 条款 1–5、12–16，经 R66 修正）

### 4.1 冻结的类型身份（条款 1、2、3、4、5、6、9）

| 冻结项 | 值 | 依据/复核 |
|---|---|---|
| schema name | `lima.sanitized-log` | 匹配 `_SCHEMA_NAME_PATTERN`，18 字节 ≤128B；与 main `fbbbd619` 既有 18 个 `lima.*` schema name（`*_SCHEMA_NAME` 常量口径亲验，经 ER 独立复核一致——ERR-IP-0044-D1-v1 第 25 项/SF-01，DI-018）零冲突；设计探针实测（probe P3）通过契约校验 |
| schema version | `4.0`（`SchemaVersion(4,0)`；仅此一个值，4.1+ 在本片 get/stage 均拒绝） | 4.0 是禁 extensions 的当前次版本 |
| 编码 | UTF-8（封存字节 = 净化后 str 的 `encode("utf-8")`） | 条款 10；probe P2 |
| media type（blob_ref.media_type） | `text/plain` | 契约 `_MEDIA_TYPE_PATTERN` 不接受 `; charset=` 参数（common.py:60-62 亲验）；UTF-8 编码作为本片不变量单列 |
| digest | `compute_content_digest(sealed_bytes)`（raw SHA-256 hex，bytes 入口） | 条款 3；probe P2 实测；同字节稳定 |
| wire 容器 | 复用 `ArtifactEnvelope`/`ArtifactReference`/`ArtifactBlobReference` + `encode_envelope`/`decode_envelope`；payload XOR blob_ref（本片恒 blob-only）；**wire 格式不改（R66-06⑤）** | 条款 2；probe P3 往返全等 |
| lineage/supersedes | 仅空 `lineage=()`、`supersedes=None`；公共 stage 不开放 lineage/supersedes 参数；envelope helper 强制空 lineage/无 supersedes——构造器实际接收对应字段时对非空**明确拒绝**（`UNSUPPORTED_LINEAGE`） | 条款 5；R66-06④；probe P3-C（契约层接受合法非空 lineage ⇒ 拒绝必须落产品层） |
| classification/retention 接受面 | 接受 = `redacted_value` 为 **str** 且 `classification ∈ {internal, sensitive}` 且 `retention_class == standard`；三条件任一不满足（RESTRICTED、整值 SENSITIVE/RESTRICTED 的 FingerprintRecord 形态、bytes/JSON 形态、非 standard retention）→ `UNSUPPORTED_REDACTED_FORM`，零内容落盘 | 条款 6、9；probe P1/P5（P5-g：clean=internal/str、span=sensitive/str、pem=restricted/FingerprintRecord） |
| 上下文 | tenant/task/workflow/attempt/snapshot/producer/toolchain 全部必填真实值（identifier/digest 校验）；**policy 必填显式注入（open 时绑定，§5.3）**；禁止全零或占位 | 条款 4；R66-06①；probe P3 |

补充：`repository_snapshot_digest`/`toolchain_digest` 为 64-hex（调用方按真实快照/工具链身份
计算）；`policy_digest` 必须等于实测 `lima.evidence_privacy.policy.policy_digest(policy)`（注入
policy 实算，不信 producer 自报——本片 ProducerContext 不含 policy 字段；probe P1/P3/P5 一致性
实测）；`created_at` 由 store 在 seal 时生成 UTC RFC3339（契约归一化 `.ffffffZ`）。

### 4.2 提交点协议与对原 Issue 文字的处置（条款 15——呈批项 DR-PACKET-1；R66-01/02/04/06 修订）

**本片冻结协议**（stage/seal/get；任一步失败即中止且不返回成功引用；协议顺序单值：
净化→输出校验→有界 staging 写入→S4 重读复核→临界区内三分支发布+metadata commit→回执）：

```text
stage_log(text, producer)
  S0  入口预检【输入检查——与输出检查分开的两步之一，R66-04】：
      text 为 str 且 UTF-8 可编码（lone surrogate → INVALID_TEXT_ENCODING，零写入）；
      输入 UTF-8 字节数 ≤ 有效输入上限=交集（max_input_bytes ∩ 注入 policy.limits.
      max_string_bytes ∩ codec 上限）（INPUT_BUDGET_EXCEEDED，零写入）；
      producer 各字段 identifier/digest 校验（INVALID_ARGUMENT，零写入）；
      store 已用尽 live-staging/逻辑对象/记录/容量额度则拒绝（CAPACITY_EXCEEDED，
      临界区内原子检查+预留，§7.1）
  S1  真实净化：sanitize_for_sink(EvidencePayload("text", text, "text/plain"),
      SinkContext("storage", tenant_id=store 绑定可信租户, tenant_key), policy)
      ← policy=open 时必填显式注入；原文只在有界内存
  S2  输出校验【在任何 content staging 写入之前，R66-04；写前四查，单值次序】：
      a. 输出类型：redacted_value 必须 str（FingerprintRecord/bytes/JSON →
         UNSUPPORTED_REDACTED_FORM，零内容落盘）
      b. 租户绑定：SanitizedPayload.tenant_id 必须 == store 绑定可信 tenant（精确比较，
         不归一化；真实字段层级——ClassificationManifest 无 tenant_id 字段，R66-01；
         不符 → SANITIZATION_FAILED 绑定类，零内容落盘）
      c. manifest 分项核验：manifest.policy_digest == 实算
         lima.evidence_privacy.policy.policy_digest(policy)（不符 → SANITIZATION_FAILED
         策略类，零内容落盘）；manifest.classification ∈ {internal, sensitive} 且
         manifest.retention_class == standard（§4.1 接受面）
      d. 净化输出 UTF-8 字节数 ≤ 有效封存上限=交集（max_sealed_bytes ∩ 注入
         policy.limits.max_string_bytes ∩ codec 上限；不得回填更宽默认）
         （SEALED_BUDGET_EXCEEDED：零内容文件、零正文入库；仅允许 §7.1 行 2 事先
         声明的有界诊断记录，不含内容/凭据）
  S3  有界 staging 写入：staging_id/artifact_id 系统生成；净化后字节按上限有界写入
      root/staging/<staging_id>/content.bin（O_CREAT|O_EXCL + fsync；写入原语达到上限
      即停止并失败——不允许「先完整写盘再拒绝」）；seal_attempts 行 STAGING
      （单事务+账本预留，§7.1d）
  S4  staging 完整性复核【职责改变：只防写入损坏，不再承担首次预算判定，R66-04】：
      从 staged 字节重读并计算 len(bytes) 与 compute_content_digest(bytes)，与 S2 判定值
      一致（不一致 → 稳定失败 INTERNAL_STORAGE_ERROR 类，残留计额）；
      expected_content_digest（如给）必须等于实测（SEAL_DIGEST_MISMATCH）
seal_log(handle)
  P1  临界区内三分支 blob 发布（R66-02；与 P2 同置于单 root 跨进程串行临界区，§7.1d）。
      目标路径 = root/blobs/<tenant_storage_key>/<d[:2]>/<d>/blob.bin（d=staged 内容
      digest；物理键见 §4.4/§7.2）：
      ① 无目标对象 → 同目录临时文件 + fsync + 原子 rename 发布（rename 仅在目标不存在
         的核验之后作为发布原语，不无条件覆盖已存在对象）；rename 后目录 fsync（Linux）/
         平台声明（Windows，§7.4）
      ② 目标已存在 → 受控、有界核验既有实物后方可复用（租户内内容寻址去重，仅 blob
         层）：常规文件（非 symlink/junction/reparse，lstat 判定）→ 实际 size == 记录
         size → 实际 SHA-256 == 目标 digest（此核验次序冻结）
      ③ 竞态分支（核验与发布之间目标出现，含不合规范外部写入者）→ 按 ② 同等核验：
         通过 → 复用；失败 → 按下行失败语义
      核验失败（任何分支）→ 本次 seal 稳定失败：不新增 SEALED metadata、不覆盖/修复/
      改动原内容与原 SEALED 记录；错误映射（复用既有码，不新增专用码）：链接/reparse
      异常 → PATH_POLICY_VIOLATION；实际 digest 不符 → BLOB_CORRUPT；size 不符 →
      BLOB_SIZE_MISMATCH；幂等重试发现实物缺失 → BLOB_MISSING。失败残留（staging 文件
      与 attempt 行）按 §7.1 统一限额表计额
  P2  同一临界区内 SQLite 单事务（BEGIN IMMEDIATE）提交可见 SEALED metadata：insert
      artifacts 行、seal_attempts STAGING→SEALED、staging 文件目录标记可清理（不自动删）
  P3  返回 SealedLogReceipt(reference, envelope)   ← 成功可见点 = P2 commit；
      回执无 content 字段（R66-06⑤：结构上消除「未读取」歧义）
get_log(reference)   【六步校验顺序冻结，R66-06②；错误映射单值】
  G1  Reference 结构/格式校验（六字段形状：schema_name pattern、identifier、64-hex、
      SchemaVersion）→ INVALID_ARGUMENT
  G2  schema 接受面（`lima.sanitized-log`/`4.0` 之外）→ UNSUPPORTED_SCHEMA
  G3  租户绑定 + 权威记录查询：store 绑定受信租户 vs reference.tenant_id；仅 SEALED 行
      可读；租户不符、未知 artifact_id、未封存、**或六字段（schema_name/schema_version/
      artifact_id/tenant_id/repository_snapshot_digest/content_digest）任一与权威记录
      不一致（含合法格式但错误的 repository_snapshot_digest/content_digest）**→
      ARTIFACT_NOT_FOUND（租户不符与对象不存在不可区分；不得验证内部三方一致后忽略
      传入错误引用）
  G4  envelope/blob 校验：envelope_wire 解码与 blob_ref 绑定（契约错误映射
      METADATA_CORRUPT/BLOB_CORRUPT，不透传原始异常文本）
  G5  实际字节核验：读取实际 blob 字节（有界，读放大上限 §7.1），重算 size 与
      compute_content_digest 与 metadata/envelope/blob_ref 三方比对 →
      BLOB_MISSING/BLOB_CORRUPT/BLOB_SIZE_MISMATCH
  G6  返回 RetrievedLogArtifact(reference, envelope, content)——content 恒为已验证封存
      字节；合法空日志 b"" 仅在该对象出现且语义唯一；绝不返回未核验字节
```

**对 #66 原文「先写临时 blob→fsync/verify→事务写 SEALED metadata→原子 rename」的处置声明
（呈批项 DR-PACKET-1；v2.0 更新：方向认可，证明补齐后随本 Packet 呈批，本轮不视为已获批）**：
本片**保留原文全部四个元素**（临时写、fsync/verify、事务化 SEALED metadata、原子 rename），但把
**原子 rename 移到 metadata 事务之前**（P1→P2）。理由与证明：成功可见点唯一化为「SQLite 提交
可见 SEALED metadata」（P2）；由于 rename（P1）先于该点完成，**且 P1 三分支核验保证「已存在即
有效、否则本次 seal 稳定失败」、发布与 P2 同置于单 root 跨进程串行临界区保证并发发布不覆盖已
存在有效对象（R66-02）**，任何读者在看到 SEALED 引用之时 blob 必已完整发布且可验证——读者无
不完整可见窗口；幂等重试同样核验实物，不因 DB 行返回假成功。崩溃残留对照：本协议在 P1 后 P2 前
崩溃留下**可诊断 orphan blob**（无 metadata，读者不可见）；reconcile 分类覆盖原文要求的 orphan/
metadata-only 集合。**覆盖范围**：本处置针对本片本机 SQLite+文件后端；未来 PostgreSQL/S3 适配
器必须在同一不变量（读者永不见「SEALED 而内容未完整发布」）下重新推导，不继承本结论。

### 4.3 状态机与故障点状态矩阵（条款 12、16；R66-02/04/05 同步）

Artifact metadata 状态本片仅使用 `STAGING`、`SEALED`（FR-02 允许集的子集；`QUARANTINED/
EXPIRED/DELETING` 不出现：corruption 不改状态、在 G5 读时 fail closed，recovery 只诊断/隔离
（可将损坏 blob 文件移入 `root/quarantine/`，不动 metadata、不虚造 SEALED、满额时拒绝移动而
诊断照常，§7.1 行 11）、不自动删除）。

| 故障点 | blob 实物 | metadata（SQLite） | 重启后分类 | get 行为 |
|---|---|---|---|---|
| S0–S2 崩溃（含 S2 输出校验失败：超限/形态/绑定/digest 不符） | 无任何写入 | 无行（S2 失败至多留 §7.1 行 2 有界诊断记录） | 干净 | 无引用存在 |
| S3 有界写入中崩溃（或达到上限即停） | 部分 staging 文件（≤上限） | 无行（写中）或 STAGING 行 | `staging`（未完成） | 该 staging 无引用可 get |
| S3/S4 完成后、P1 前 | staging 完整 | STAGING 行 | `staging` | 同上 |
| P1 临界区内临时文件写/fsync 中 | publish 临时文件 | STAGING 行 | `orphan`（临时） | 无 SEALED 行 |
| P1 发布后、P2 前 | 最终 blob 就位 | STAGING 行、无 artifacts 行 | `orphan`（blob 无 SEALED metadata） | 调用者从未获得引用；伪造 id → ARTIFACT_NOT_FOUND |
| P1 ②/③ 核验既有实物失败（坏/链接异常/缺失） | 原实物保持原样（不覆盖/修复/改动） | STAGING 行（**无新增 SEALED**） | `staging`/`corrupt` 诊断 | 无新增引用；残留计额（§7.1） |
| P2 事务中崩溃 | 最终 blob 就位 | DELETE hot journal → 重启自动回滚：有 artifacts(SEALED) 行或无 | 有行=完全成功；无行=上一种 orphan | 有行则 get 正常且 G5 全过 |
| P2 后、P3 返回前 | 就位 | SEALED | 完全成功 | 同 handle 幂等重试返回同一 artifact（且核验实物） |
| SEALED 后 blob 被外部删除/篡改/截断 | 缺失/异字节 | SEALED | `metadata-only` / `corrupt` | get：BLOB_MISSING/BLOB_CORRUPT（fail closed，metadata 不丢） |
| **SEALED 后实物损坏时重复 seal（同 handle 幂等重试）** | 损坏/缺失 | SEALED | `corrupt` | **seal 稳定失败（BLOB_CORRUPT/BLOB_SIZE_MISMATCH/PATH_POLICY_VIOLATION/BLOB_MISSING 按核验项映射），非假幂等；原 metadata 不改动** |

get 永远执行 G5 实物核验，绝不只信 SEALED 字符串（条款 16；另据**设计探针实测（probe P3-A）**：
wire 上保持内部一致的 digest 篡改能通过契约层——契约层看不到字节，故 G5 的字节级重算比对是
mandatory 不可省略）。`inspect()`（recovery 入口）输出 staging/orphan/metadata-only/corrupt 四类
分类 + 计数（扫描有界，§7.1 行 10/11），不删除、不重构、不虚造。

### 4.4 身份键、幂等与并发（条款 14；R66-02/03 修订）

- **Artifact 身份键** = `(tenant_id, artifact_id)`；`artifact_id = "art-" + uuid4hex(32)`（系统
  生成，identifier 合法）。**同字节 ≠ 同身份**：不同 stage 调用各自生成 artifact_id；metadata
  身份、上下文、身份绑定不因 blob 去重合并。
- **blob 物理键** = `blobs/<tenant_storage_key>/<digest[:2]>/<digest>/blob.bin`，其中
  **`tenant_storage_key = SHA256(tenant_id 的精确 UTF-8 字节).hexdigest()`（小写 64-hex；版本化
  内部规则 v1，与 root 元数据绑定，§7.2）**；`blob_id == content_digest`（64-hex）。blob 复用仅
  发生在**同租户同字节**（内容寻址 + 租户物理目录隔离），且复用前必须通过 P1 ② 受控核验
  （R66-02）；跨租户同字节各自独立 blob 文件，无全局去重。**逻辑身份不变**：SQL、
  ArtifactReference、ACL/权限比较仍按逻辑 `tenant_id` 精确比较（不 lowercase、不剥尾点、不合并
  租户）。
- **同请求幂等（强化，R66-02④）**：同一 staging handle 的 seal 重复/并发调用（含同 root 同可信
  租户跨实例/跨进程重开 handle 后、含 P2 已提交未返回即崩溃后的重试）返回**同一**
  SealedLogReceipt——由 P2 的单事务 + `seal_attempts.staging_id` 唯一约束裁决，后到者在事务内
  读到胜者已写的 artifact_id 并原样返回；**幂等成功同样执行 P1 的实物完整性核验**（不只看 DB
  行；核验不过 → 按 §6.1 映射稳定失败，不返回假成功）；不产生第二个 artifact。
- **并发重复 seal（不同 staging、同字节/不同字节）**：各自独立 artifact；先到者发布、后到者走
  P1 ② 核验复用；并发发布在临界区内**不覆盖已存在有效对象**；无 ACL 放宽面（本片 ACL 即租户
  绑定，无运行时放宽接口）。
- **跨进程协调**：stage 配额预留与 seal 的 P1+P2 复合段都在单 root 跨进程串行临界区内执行
  （有限等待；超时 → CONCURRENCY_LIMIT_EXCEEDED 零提交；崩溃 OS 锁自动释放，§7.1d）。
- **metadata 冲突**：同 `(tenant_id, artifact_id)` 已存在且字段值不一致 → `METADATA_CONFLICT`
  拒绝，绝不覆盖（UUID 下实际不可达，仍冻结为唯一约束违反路径的稳定语义）。
- **首片无公共 delete/update**（条款 14 末句）；SEALED 内容及其租户/身份绑定不可修改（无任何
  UPDATE 路径）。

### 4.5 权限与信任边界（条款 13；R66-06①/③ 修订）

- 信任边界 = 受控本机进程：`LocalArtifactStore.open(root, *, tenant, policy, limits=None)`
  （§5.3 逐字签名）在打开时绑定**受信租户身份**（tenant_id + tenant_key；key 仅驻内存，绝不
  持久化、绝不入错误信息）与**可信 TenantPolicy**（必填显式注入：不信 producer 自报摘要、不默
  用 DEFAULT_POLICY；policy_digest 一律用注入 policy 实算）。
- 调用者**不能**逐调用传入租户字符串充当身份；`reference.tenant_id` 只是声明，G3 以 store 绑定
  的受信租户比对，不符即 `ARTIFACT_NOT_FOUND`（与不存在同错误，杜绝存在性泄露）。
- **open 时 root 一致性核验**（R66-03/05）：`artifact_store_meta` 的 tenant-storage-key 映射
  版本不一致或可检测冲突 → `METADATA_CORRUPT` fail-closed（绝不落入另一租户目录）；limits
  指纹与既有绑定不一致 → `STORE_CONFIG_CONFLICT` 拒绝（零写入；不允许后开实例以更宽配置绕过，
  也不能借不同租户实例跳过 root 总上限，§7.1c）。
- 权限执行点 = metadata 查询（G3，租户等值过滤在 SQL 谓词中）与读取入口（G5 实物核验），双层；
  无跨租户共享、无运行时 ACL 放宽。
- 需要多用户身份体系、真实认证来源时必须提 DR（六类升 Maintainer 之一）；本片不声称防御拥有
  同等 OS 权限的恶意本机用户（§7.2 平台声明）。

## 5. 精确文件与符号（exact files 由 D2/IMPL Assignment 最终冻结，本节为 Packet 冻结的允许面、符号与公共合同）

### 5.1 Files

| 类别 | 路径 | 说明 |
|---|---|---|
| Add（产品） | `lima/artifacts/__init__.py` | 公共导出：`LocalArtifactStore`、`TrustedTenantContext`、`ProducerContext`、`ArtifactStoreLimits`、`StagedLogHandle`、`SealedLogReceipt`、`RetrievedLogArtifact`、`ArtifactStoreError`、`ArtifactStoreErrorCode`、`SANITIZED_LOG_SCHEMA_NAME` 等 schema 常量（**导出清单本轮冻结，R66-06⑤；旧 `SealedLogArtifact` 删除，不导出**） |
| Add（产品） | `lima/artifacts/schema.py` | 冻结类型身份常量 + `build_sanitized_log_envelope(...)`（校验型构造器；实际接收 lineage/supersedes 字段时对非空明确拒绝）+ `decode_sanitized_log_envelope(bytes)` |
| Add（产品） | `lima/artifacts/context.py` | `TrustedTenantContext`、`ProducerContext`（frozen dataclass；字段表见 §5.3；fail-closed 校验） |
| Add（产品） | `lima/artifacts/limits.py` | `ArtifactStoreLimits`（frozen dataclass；字段/默认/合法域=§7.1 统一限额表；域校验 fail-closed；提供 root 绑定用 canonical 指纹） |
| Add（产品） | `lima/artifacts/errors.py` | `ArtifactStoreError`/`ArtifactStoreErrorCode`（§6.1 稳定错误面 23 码，含新增 `STORE_CONFIG_CONFLICT`；错误串永不包含日志正文/凭据/绝对路径） |
| Add（产品） | `lima/artifacts/staging.py` | `StagedLogHandle`（§5.3 字段表）+ staging 写入/校验原语（S0–S4；有界写入原语） |
| Add（产品） | `lima/artifacts/metadata.py` | SQLite 层：`_init` 单事务建表（`PRAGMA user_version=1`、DELETE journal、幂等可重开）、seal 事务、限额账本（§7.1d）、租户作用域查询、`artifact_store_meta`（root_id/映射版本/limits 指纹） |
| Add（产品） | `lima/artifacts/local_store.py` | `LocalArtifactStore`（open/stage_log/seal_log/get_log/inspect/close；临界区；blob IO 与 metadata 分离） |
| Add（产品） | `lima/artifacts/recovery.py` | `inspect` 诊断（四类分类+计数；有界扫描）与隔离移动（不删不重构；满额拒绝移动、诊断照常） |
| Add（产品） | `lima/artifacts/demo.py` | `python -m lima.artifacts.demo --root <dir>`：本机可运行示例（进程内 stage→seal→get 回执→get 读结果 + 子进程重开读回 + 独立 digest 复算；合成上下文显式标明） |
| Add（测试，D2 冻结名称/符号/计数） | `tests/artifacts/__init__.py` + `tests/artifacts/test_*.py` | 方法族与最小覆盖数见 §8；exact 文件/符号 D2 冻结 |
| Modify | 无（本片零修改既有文件） | 首片不改 `lima/store.py` 等；V5-FR-01 迁移义务留在 #66 后续 |
| Read-only | `lima/contracts/`、`lima/evidence_privacy/`、`lima/audit/`、workspace、cache、`lima/store.py`/`postgres_store.py`/`repository_cache.py`、service/auth、Docker/compose、#60 全部工作面、其余一切 | 只读复用/参考 |
| Forbidden | 共享契约任何修改；既有 schema 版本/公共字段/默认预算/全局 registry；`lima/persistence/migrations.py`（FR-05 后续片）；除上述 Add 面外的任何新增仓库文件 | Assignment §6（DI-017） |

实现期文件面按 #66 Add 面收敛到 `lima/artifacts/` + `tests/artifacts/`；不新增 `ports.py`/
`retention.py` 框架性文件（防过度设计）。依赖约束：仅 Python 标准库（sqlite3/uuid/pathlib/
hmac/hashlib 等）+ 既有 `lima.contracts`/`lima.evidence_privacy`；禁网络、禁新第三方依赖、禁
容器、禁远端写。

### 5.2 Symbol-to-File Map（公共符号）

| Symbol | File |
|---|---|
| `SANITIZED_LOG_SCHEMA_NAME`/`SANITIZED_LOG_SCHEMA_VERSION`/`SANITIZED_LOG_MEDIA_TYPE`/`SANITIZED_LOG_ENCODING`/`build_sanitized_log_envelope`/`decode_sanitized_log_envelope` | `lima/artifacts/schema.py` |
| `TrustedTenantContext`/`ProducerContext` | `lima/artifacts/context.py` |
| `ArtifactStoreLimits` | `lima/artifacts/limits.py` |
| `ArtifactStoreError`/`ArtifactStoreErrorCode` | `lima/artifacts/errors.py` |
| `StagedLogHandle` | `lima/artifacts/staging.py` |
| `LocalArtifactStore`（`open`/`stage_log`/`seal_log`/`get_log`/`inspect`/`close`） | `lima/artifacts/local_store.py` |
| `SealedLogReceipt`/`RetrievedLogArtifact` | `lima/artifacts/local_store.py`（或 schema.py——模块落点为 SF-09 D2 收敛义务，§10.1；**字段与语义本轮已冻结，§5.3**） |
| `StoreHealthReport`（inspect 返回） | `lima/artifacts/recovery.py` |
| `main`（demo 入口） | `lima/artifacts/demo.py` |

### 5.3 冻结公共合同（R66-06；Assignment §7.6① 逐字）

```python
class LocalArtifactStore:
    @classmethod
    def open(cls, root: Path, *, tenant: TrustedTenantContext,
             policy: TenantPolicy, limits: ArtifactStoreLimits | None = None) -> LocalArtifactStore
    def stage_log(self, *, text: str, producer: ProducerContext) -> StagedLogHandle
    def seal_log(self, handle: StagedLogHandle, *,
                 expected_content_digest: str | None = None) -> SealedLogReceipt
    def get_log(self, reference: ArtifactReference) -> RetrievedLogArtifact
    def inspect(self) -> StoreHealthReport
    def close(self) -> None
```

- 全部关键字参数（store 打开参数与 stage 入参）；`TenantPolicy` 自 `lima.evidence_privacy.models`
  复用（不重定义、不改 #94）；测试/demo 可显式注入**已标明合成**的 policy（不冒充生产来源）。
- **open 语义**：首次打开创建目录骨架（`root/blobs`、`root/staging`、`root/quarantine`）与
  `metadata.sqlite3`（user_version=1、DELETE journal、`artifact_store_meta` 写入 root_id、
  `tenant_storage_key_map_version=1`、limits 指纹、账本清零行）；再次打开校验版本/指纹（§4.5）。
  policy 不进 root 绑定（每次注入、只收紧）。
- **handle 一次性身份语义**：seal 后 handle 不可再用于新 seal 的身份变更，仅幂等重读；业务不
  接触绝对路径（路径仅存在于 store 内部与 bounded 诊断计数中）。
- **get 六步校验顺序**：冻结于 §4.2 G1–G6（含每步错误映射）；本节不重复展开以避免双源。

**TrustedTenantContext 字段表（frozen dataclass；fail-closed，本轮冻结不留 D2）**

| 字段 | 类型 | 合法域（冻结） | fail-closed 行为 |
|---|---|---|---|
| `tenant_id` | str | 契约 identifier pattern `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` fullmatch；逻辑身份精确值（大小写/尾点差异=不同租户，不归一化） | 违反 → `INVALID_ARGUMENT`（open 拒绝，零写入） |
| `tenant_key` | bytes | 非空且 1..64 字节；仅驻内存 | 违反 → `INVALID_ARGUMENT`；绝不持久化/入错误信息/日志 |

**ProducerContext 字段表（frozen dataclass；fail-closed，本轮冻结；无 policy 相关字段——R66-06①：
不保留 producer 自报 policy 声明，store 只信注入 policy 的实算 digest）**

| 字段 | 类型 | 合法域（冻结） | fail-closed 行为 |
|---|---|---|---|
| `producer` | str | identifier pattern | 违反 → `INVALID_ARGUMENT`（stage 入口，零写入） |
| `task_id` | str | identifier pattern | 同上 |
| `workflow_id` | str | identifier pattern | 同上 |
| `stage_attempt_id` | str | identifier pattern | 同上 |
| `repository_snapshot_digest` | str | 64-hex 小写 | 同上 |
| `toolchain_digest` | str | 64-hex 小写 | 同上 |

**StagedLogHandle 字段表（frozen dataclass；有界表示——不含主机路径、不含 tenant key/任何密钥；
可序列化 canonical JSON ≤1 KiB；本轮冻结，内部表示细节可在文件边界内收敛）**

| 字段 | 类型 | 合法域（冻结） | 语义/失败行为 |
|---|---|---|---|
| `staging_id` | str | identifier；系统生成 `"stg-"+uuid4hex(32)` | staging 身份（`seal_attempts` PK）；查无此行且无可幂等返回的已 seal 身份 → `STAGING_NOT_FOUND` |
| `root_id` | str | 64-hex；root 初始化时生成并记录于 `artifact_store_meta`（**不是主机路径**） | 与当前 store 的 root_id 不符 → `STAGING_STATE_INVALID`（外来 root handle） |
| `tenant_id` | str | identifier；逻辑租户绑定（非 tenant_key） | 与当前 store 可信租户不符 → `STAGING_STATE_INVALID`（外来租户 handle） |
| `declared_state` | str | `{"staged","sealed"}`（权威=`seal_attempts` 行） | 与权威行矛盾 → `STAGING_STATE_INVALID` |
| `created_at` | str | UTC RFC3339 | 仅诊断 |

- **重开与重试（R66-06③）**：同 root、同可信租户重开（含跨实例/跨进程新 `open`）后**可重试原
  staging**（含 close 后再重开的场景）；外来 root/tenant handle 拒绝（`STAGING_STATE_INVALID`）；
  P2 已提交未返回即崩溃后，原 handle 幂等取得同一身份（且按 R66-02 核验实物）。
- **close() 只释放本实例资源**：不批量 abort、不删除/移动持久 staging；关闭后 inspect/重开/重复
  seal 行为明确（重开后原 handle 仍可用）。「非本 store」不再是 handle 拒绝理由（§6.1）。

**SealedLogReceipt 字段表（frozen dataclass；本轮冻结类型名与公共导出）**

| 字段 | 类型 | 语义 |
|---|---|---|
| `reference` | `ArtifactReference` | 既有契约 wire（不改） |
| `envelope` | `ArtifactEnvelope` | 既有契约 wire（不改） |

（**无 content 字段**——结构上消除「未读取」歧义；不用 `content=b""`/`None` 编码未读取语义。）

**RetrievedLogArtifact 字段表（frozen dataclass；本轮冻结类型名与公共导出）**

| 字段 | 类型 | 语义 |
|---|---|---|
| `reference` | `ArtifactReference` | 既有契约 wire（不改） |
| `envelope` | `ArtifactEnvelope` | 既有契约 wire（不改） |
| `content` | `bytes` | **恒为已验证封存字节**（G1–G6 全过后返回）；合法空日志 `b""` 只在该对象出现且语义唯一 |

## 6. 状态/错误/权限语义（条款 8、11、13、16；R66-02/04/06 同步）

### 6.1 稳定错误码表（`ArtifactStoreErrorCode`，wire 值冻结；23 码，**唯一新增=`STORE_CONFIG_CONFLICT`**）

| code | 触发条件 | 副作用保证 |
|---|---|---|
| `INVALID_ARGUMENT` | 参数类型/形状错误（非 str text、非法 context 字段、非 ArtifactReference、G1 六字段形状不符） | 零写入 |
| `INVALID_TEXT_ENCODING` | text 非 UTF-8 可编码（lone surrogate 等） | 零写入（S0 预检；probe P4.2e：裸 UnicodeEncodeError 会逃出隐私端口，必须前置） |
| `INPUT_BUDGET_EXCEEDED` | 输入 UTF-8 字节数 > 有效输入上限交集（S0） | 零写入 |
| `SEALED_BUDGET_EXCEEDED` | 净化输出 UTF-8 字节数 > 有效封存上限交集（**S2 输出校验，先于任何 content staging 写入**，R66-04） | **零内容文件、零正文入库**；仅允许 §7.1 行 2 事先声明的有界诊断记录（无内容/凭据） |
| `SANITIZATION_FAILED` | 隐私端口 PrivacyError（含 MISSING_TENANT_KEY/UNKNOWN_SINK/MAX_STRING_LENGTH_EXCEEDED 等，bounded context 携带 privacy_code）；**或 S2b 租户绑定不符 / S2c policy_digest 不符（R66-01）** | 零内容落盘、无 staging 内容文件 |
| `UNSUPPORTED_REDACTED_FORM` | redacted_value 非 str（FingerprintRecord/bytes/JSON）或 classification/retention 不在接受面（S2a/S2c） | 零内容落盘、不取回原文、不声称已保存全文 |
| `UNSUPPORTED_LINEAGE` | 非空 lineage/supersedes 进入 stage 或 envelope helper 构造器 | 零写入 |
| `UNSUPPORTED_SCHEMA` | get 的 schema name/version 非 `lima.sanitized-log`/`4.0`（G2） | 只读失败 |
| `STAGING_NOT_FOUND` | handle 的 staging 身份在权威 `seal_attempts` 中不存在**且无可幂等返回的已 seal 身份**（R66-06③改写：「非本 store」不再是触发） | 只读失败 |
| `STAGING_STATE_INVALID` | (a) handle 绑定 root/tenant 与当前 store 不符（外来 handle）；(b) handle 声明状态与权威 `seal_attempts` 行矛盾（**「已 abort」触发已删除——本片无公共 abort 入口、close 不批量 abort，该状态不可达，R66-06④裁定**） | 只读失败 |
| `SEAL_DIGEST_MISMATCH` | expected_content_digest ≠ 实测（S4） | 不发布、不提交 |
| `ARTIFACT_NOT_FOUND` | G3：租户不符、未知 artifact_id、未封存、**或六字段任一与权威记录不一致（含合法格式但错误的 repository_snapshot_digest/content_digest，R66-06②）** | 只读失败；绝不泄露他租户对象存在性 |
| `BLOB_MISSING` | G5 实物缺失（metadata-only）；**或 seal/幂等重试路径核验发现实物缺失（P1，R66-02 扩展触发面）** | metadata 不丢；不返回内容；seal 路径零新增 SEALED |
| `BLOB_CORRUPT` | 实际字节 digest 不匹配（G5）；**或 P1 ②/③ 核验既有实物 digest 不符** | fail closed；可隔离不改状态；seal 路径不覆盖/不修复原内容与原 SEALED 记录 |
| `BLOB_SIZE_MISMATCH` | 实际 size ≠ 记录 size（G5）；**或 P1 ②/③ 核验 size 不符** | 同上 |
| `METADATA_CORRUPT` | metadata 行/envelope 无法解码或互相矛盾；**或 open 时 root 元数据/tenant-storage-key 映射版本绑定不一致（R66-03）** | fail closed；报告分类 |
| `METADATA_CONFLICT` | 身份键冲突且字段不一致 | 拒绝，不覆盖 |
| `CAPACITY_EXCEEDED` | §7.1 统一限额表任一容量/对象/记录/残留类限额超限 | 拒绝新写；不自动清理活对象；不 fallback |
| `CONCURRENCY_LIMIT_EXCEEDED` | 并发 seal 超 max_concurrent_seals；**或临界区/锁有限等待超时（R66-05；含 DELETE 模式写事务期间读者 busy_timeout 超时）** | 拒绝/稳定失败（零提交） |
| `STORE_CONFIG_CONFLICT` | **新增（唯一新码，R66-05）**：open 发现同 root 已绑定的 limits 指纹与本次 open 传入（或默认）limits 不一致 | 拒绝 open，零写入（不允许后开实例以更宽配置绕过 root 上限） |
| `PATH_POLICY_VIOLATION` | 解析路径越出私有 root、symlink/junction 命中发布/读取路径；**或 P1 ②/③ 核验链接/reparse 异常（R66-02）** | 拒绝该 IO；零越界访问 |
| `IO_ERROR` | 磁盘满/权限拒绝/IO 异常（bounded：仅异常类型与 errno 级元数据） | 稳定失败；不回显日志原文 |
| `INTERNAL_STORAGE_ERROR` | 不可预期异常兜底（bounded：仅异常类型；含契约层 encode 资源上限映射——正常不可达） | 稳定失败；不回显内容 |

契约层 `ContractError`（如 decode 时的 DIGEST_MISMATCH）在 get 路径被映射为上表对应存储错误
（G4/G5 阶段 → `BLOB_CORRUPT`/`METADATA_CORRUPT`），不把原始异常文本透传给业务。所有错误信息
只含：code、field 级定位、`{"limit","actual","privacy_code","exception_type"}` 式 bounded 元数据
——**无日志正文、无 tenant_key/token/Secret、无主机绝对路径**（条款 11）。

### 6.2 权限校验入口

两处强制：metadata 查询（G3，租户等值过滤在 SQL 谓词中）与读取入口（G5 实物核验）。ref 自带
tenant 与调用者传入字符串均不作为身份认证依据（§4.5）。

## 7. 预算与资源（条款 10、17、18、19、20；R66-04/05 修订）

### 7.1 统一限额表与跨进程额度（R66-05 列规范；替换 v1.0 零散限额行——Assignment §7.7 第 9 行，本 Packet §1.3 已核销）

#### 7.1a 统一限额表

| # | 限额 | 作用域 | 默认值 | 合法域（open 可调） | 硬上限 | 计数单位 | 预留/提交/失败/崩溃（每行单值） | 稳定错误 |
|---|---|---|---|---|---|---|---|---|
| 1 | `max_input_bytes` 单条日志输入 UTF-8 字节 | 每次调用（叠加注入 policy 更严值） | 262,144 | [1, 262,144] | 262,144（=PrivacyLimits∩ContractLimits string 上限，**不可扩**） | 输入字节 | 无预留（S0 纯校验）；失败=零写入；崩溃=无副作用（任何写入前） | `INPUT_BUDGET_EXCEEDED` |
| 2 | `max_sealed_bytes` 净化输出封存字节 | 每次调用（同上） | 262,144 | [0, 262,144] | 262,144（同上交集；更严 policy 收紧，不回填宽默认） | 净化输出字节 | 无预留（S2 写前校验）；失败=零内容文件+零正文入库+仅本表声明有界诊断（无内容/凭据，上限 1 条/attempt、≤256 B）；崩溃=写前失败无内容 | `SEALED_BUDGET_EXCEEDED` |
| 3 | `max_envelope_bytes` envelope wire | 进程内 | 1,048,576 | 固定（契约 `ContractLimits.max_input_bytes`） | 1,048,576 | wire 字节 | encode 时校验；失败=拒绝封存（本片 envelope 字段全有界，正常不可达） | `INTERNAL_STORAGE_ERROR`（契约资源上限映射） |
| 4 | `max_blob_objects` root 持久对象总数 | root 跨进程 | 10,000 | [1, 1,000,000] | 1,000,000 | 唯一物理 blob（内容寻址去重后） | 临界区内写前原子检查+预留；提交=占用；失败=释放预留（staging 残留转行 7/11 计额）；崩溃=已发布实物残留计额 | `CAPACITY_EXCEEDED` |
| 5 | `max_total_root_bytes` root 磁盘总字节（原 `max_total_blob_bytes` 更名扩域：blob+staging+orphan+quarantine+envelope/metadata+SQLite 数据与 journal+锁文件） | root 跨进程 | 512 MiB | [1 MiB, 64 GiB] | 64 GiB | root 下实际字节 | 同行 4（预留按实测字节数入账；含 SQLite 数据与 journal） | `CAPACITY_EXCEEDED` |
| 6 | `max_logical_artifacts` 逻辑 Artifact 总数（**新增**） | root 跨进程 | 10,000 | [1, 1,000,000] | 1,000,000 | 身份键 `(tenant_id, artifact_id)` 计 | 临界区内检查+预留（P2 提交=占用）；同 handle 幂等重试不重复计数；新 stage 不是免费重试 | `CAPACITY_EXCEEDED` |
| 7 | `max_live_staging` live staging/seal attempt 数 | root 跨进程 | 256 | [1, 10,000] | 10,000 | 活跃 `seal_attempts` 行（STAGING 态） | stage 时临界区内检查+预留；失败/崩溃=行与 staging 文件残留计额（无删除授权不释放） | `CAPACITY_EXCEEDED` |
| 8 | `max_concurrent_seals` 并发 seal 数 | root 跨进程 | 8 | [1, 64] | 64 | 临界区并发持有者 | 获取临界区时检查；等待超时=稳定失败零提交；崩溃=OS 文件锁随进程终止自动释放（不悬挂） | `CONCURRENCY_LIMIT_EXCEEDED` |
| 9 | `max_metadata_record_bytes` metadata 单条记录上界（**新增**） | 进程内不变量 | 8 KiB | 固定 | 8 KiB | 单行+envelope_wire 合计 | 构造时校验；超限拒绝封存（字段全有界，正常不可达） | `INTERNAL_STORAGE_ERROR` |
| 10 | `max_metadata_records` metadata 记录总数上界（**新增**：artifacts+seal_attempts+诊断行） | root 跨进程 | 100,000 | [10,000, 1,000,000] | 1,000,000 | metadata 行 | 临界区内检查；幂等重试不新增行；失败/崩溃残留行计额 | `CAPACITY_EXCEEDED` |
| 11 | `max_quarantine_items` 诊断与隔离残留计数（**新增**） | root 跨进程 | 1,000 | [1, 100,000] | 100,000 | quarantine 条目+诊断残留记录 | 残留恒计额（无删除授权仍占额）；inspect 隔离移动满额时拒绝执行、诊断报告照常输出 | `CAPACITY_EXCEEDED` |
| 12 | `max_auxiliary_bytes` 辅助文件预算（**新增**：DELETE journal 峰值+锁文件） | root 跨进程 | 4 MiB | [64 KiB, 64 MiB] | 64 MiB | journal+锁文件字节 | journal 峰值≤单事务脏页上界（本片事务=有界小记录，行 9）；hot journal 残留计额至下次打开回滚；锁文件恒 0 字节；计入行 5 | `CAPACITY_EXCEEDED` |
| 13 | `max_read_bytes_per_get` 单次 get 读放大 | 进程内 | = `max_sealed_bytes`+`max_envelope_bytes` | 随前两者 | 同左 | 单次 get 读取字节 | 读取硬限：实际 size 超界先由 G5 size 校验拒绝，**永不读入超界字节** | `BLOB_SIZE_MISMATCH`（size 前置拒绝） |

新增限额理由（有限、不为演示提高额度）：行 6（逻辑计数与物理计数分开是 R66-05 要求——同内容
dedup 与空日志照样消耗逻辑额度）；行 9/10（metadata 每条/总数上界是 R66-05 要求的运维占用有界）；
行 11（隔离/诊断残留占额）；行 12（journal/锁文件预算）。原适用限额默认值全部保留（行 1–5、8、
13 与 v1.0 一致）。

**计数语义（7.1b，冻结）**：唯一物理 blob（行 4，内容寻址去重后）/ 逻辑 Artifact（行 6，身份键计）/
staging-seal attempt（行 7/10）/ 诊断隔离残留（行 11）**分开计数**；同内容 dedup 与 0 字节日志
照样消耗逻辑对象/记录额度；同 handle 幂等重试不重复生成 Artifact、不新增 attempt 行；**新 stage
不是免费重试**（消耗 attempt/逻辑额度）。更严 policy 只收紧行 1/2 的每次调用上限，不构成另一个
root 配额。

**作用域与配置绑定（7.1c，冻结）**：行 4–8、10–12（root 跨进程作用域）跨实例/跨进程共享同一账本；
**同 root 存储限制配置绑定一致**——`artifact_store_meta` 记录 `ArtifactStoreLimits` 全字段的
canonical 指纹（`compute_content_digest` 规则实算），`open()` 发现与既有绑定不一致 →
`STORE_CONFIG_CONFLICT` 拒绝（零写入）；不允许后开实例以更宽配置绕过，也不能借不同租户实例
跳过 root 总上限；TenantPolicy 不进 root 绑定。无删除授权的残留仍占额度；达上限拒绝新写（稳定
错误），不自动 GC、不删除活对象、不 fallback。

**原子性与协调规则（7.1d，冻结，单值实现形态）**：**单 root 跨进程串行临界区 + 有限等待 + SQLite 小
记录**。临界区 = root 锁文件（OS 独占文件锁：win32 `LockFileEx` / POSIX `flock` 等价语义）+
有限等待（默认 10,000 ms，与 busy_timeout 一致）；stage 的配额检查/预留事务与 seal 的「blob
发布 + metadata commit」复合段（P1+P2）都在临界区内执行（R66-02 第 3 条联动）；写入前原子
检查/预留——账本行（计数）与业务行同库同事务（BEGIN IMMEDIATE）更新；失败释放哪些预留、哪些
实际残留继续入账 = 表中每行单值；进程崩溃后不丢账（事务原子）、不使一次检查永久挂死（OS 文件
锁随进程终止自动释放；DELETE hot journal 下次打开自动回滚）；临界区有限等待超时 →
`CONCURRENCY_LIMIT_EXCEEDED` 稳定失败（零提交）。**不建**配额服务、多池调度、分布式锁。

预算两层说明（7.1e；条款 10，R66-04 同步）：**输入预算**（S0，对原始 text 的 UTF-8 字节数）与**净化
输出预算**（S2，对净化后字节数——**在任何 content staging 写入之前**）分别执行，大小一律按
UTF-8 字节数（设计探针实测 probe P4.2：1 emoji=1 字符/4 字节、6 CJK 字符=18 字节、100 emoji=
100 字符/400 字节——字符计数与字节计数必须分离）。**预算内输入可能因净化占位符膨胀触发输出
预算**——实测反例 262,119 B 输入膨胀至 365,378 B（cap 262,144 B）→ 新时序下 S2 写前拒绝：
`SEALED_BUDGET_EXCEEDED`（稳定失败、零内容写入、无数据丢失、无降级；P7 复现+审核实测；
ERR-IP-0044-D1-v1 SF-07 事实保留，其「S4 检查」时序表述已被本表取代）。默认限额触发实例实测：
262,145 字节 → `MAX_STRING_LENGTH_EXCEEDED {limit:262144,actual:262145}`（probe P4.1）。容量
不足拒绝新写（`CAPACITY_EXCEEDED`）：不无限积累、不自动清理活对象、不 fallback 到旧 task
report_json、不回退 inline。既有 privacy/codec 限制零扩大；**不改 privacy foundation**（#94 只读
复用）。

### 7.2 路径与键（条款 18；R66-03 修订）

- 存储键全部系统生成：`blobs/<tenant_storage_key>/<d[:2]>/<d>/blob.bin`、
  `staging/<staging_id>/content.bin`、`quarantine/…`、`metadata.sqlite3`、锁文件；API 面无任何
  调用者路径参数（系统生成 staging key 同样不接受调用者路径）。
- **tenant_storage_key（冻结版本化内部规则 v1）= `SHA256(tenant_id 的精确 UTF-8 字节)
  .hexdigest()`（小写 64-hex）**；**仅用于本地物理目录命名**（blob 分桶、quarantine 等 root
  物理布局）。hash 物理键使租户目录名不再包含冒号/尾点/大小写敏感情形——该类混叠（Windows
  `Tenant-A`/`tenant-a`、`tenant-end`/`tenant-end.` 目录混叠）在物理键层面消除（**设计探针实测
  probe P6，win32**：四租户 hash 键互不相同、目录互不混叠，对照组直接命名混叠复现；**Linux 未
  验证，D2 双平台覆盖**；审核 synthetic_fs 实测互证）。原「冒号在 Win32 触发 OSError
  fail-closed」保留为**纵深防御姿态**（P6-d 实测 `NotADirectoryError`），非主消除手段。
  v1.0「尾随 `.`/空格的名称规范化混叠」表述已删——identifier 字符类不含空格（P6-e；审核
  `trailing_space_contract_valid=false`）。
- **逻辑身份不变**：SQL、ArtifactReference、ACL/权限比较仍按逻辑 `tenant_id` 精确比较——不
  lowercase、不剥尾点、不把两个逻辑租户合并。
- **版本绑定 fail-closed**：内部映射规则版本（`tenant_storage_key_map_version=1`）与 root 元数据
  （`artifact_store_meta`）绑定；打开时发现不一致或可检测冲突 → `METADATA_CORRUPT`
  fail-closed，绝不落入另一租户目录。
- 终点 containment 与链接防护**保留且不被物理键替代**：每次 IO 前 `Path.resolve()` 结果必须
  `is_relative_to(root.resolve())`，否则 `PATH_POLICY_VIOLATION`；tenant_id 虽受契约 identifier
  pattern 约束（首字符必为字母数字，`/`、纯 `..` 不可构造），仍执行该防御性终点校验；
  symlink/junction/reparse/hardlink：发布/读取路径上的符号链接与 junction 拒绝（Linux
  `O_NOFOLLOW` 等价语义；Windows 显式 reparse-point 检查）；发布使用同目录临时文件 + 核验后
  原子改名（同卷原子，不无条件覆盖已存在对象）；blob 发布后只读打开；hardlink 到同内容 blob
  文件无害（内容寻址），威胁是替换，由独占创建/只读打开缓解。
- 受控 root：`root/` 与子目录以最小权限创建（POSIX 0o700；Windows 继承 ACL 并声明限制）。
  **不声称防御同等 OS 权限的恶意本机用户**（条款 18 末句）。#58 identifier 合法域零改动、
  不新增租户注册服务。

### 7.3 SQLite schema（条款 19；R66-05 修订——journal 模式单值）

- 文件：`root/metadata.sqlite3`；**`PRAGMA journal_mode=DELETE`（P&V 选定单值，2026-10-11；
  替换 v1.0 无条件 `PRAGMA journal_mode=WAL`——Assignment §7.7 第 10 行，本 Packet §1.3 已
  核销；不得两套可选实现并存带入 D2）**、`busy_timeout=10000`、`foreign_keys=ON`（连接纪律：
  每操作一连接、异常回滚、finally close，参考 `TaskStore`，只读借鉴）。
- **选择理由（Assignment §7.5 第 7 条唯一下放项的裁定）**：① 辅助文件预算单值——唯一
  transient `metadata.sqlite3-journal` 仅事务期间存在，无持久 `-wal`/`-shm` 对、无 checkpoint
  治理（§7.1 行 12）；② 写路径已由 §7.1d 单 root 临界区序列化，WAL 的读写并发优势非必需，
  读者以 busy_timeout 有限等待；③ 说明书 §4 R66-05 明示「SQLite 可采用 rollback journal
  （DELETE）降低 WAL 治理负担；若保留 WAL 必须交代并验证其边界」。
- **验证边界（如实声明）**：journal 峰值 ≤ 单事务脏页上界（本片每事务仅写有界小记录，行 9/12
  计账）；事务中崩溃留下 hot journal（`metadata.sqlite3-journal`），下次在临界区内打开时
  SQLite 自动回滚后删除——残留存续期计入行 5/12，重启后仅见「已提交」或「净回滚」两态（无第
  三态，D2 kill 验证义务）；回滚自身 IO 失败 → fail-closed（`IO_ERROR`/`METADATA_CORRUPT`
  路径），不虚造状态；DELETE 模式下写事务期间读者阻塞，busy_timeout 超时映射
  `CONCURRENCY_LIMIT_EXCEEDED` 语义面；DELETE 为 SQLite 默认 journal 模式，win32/Linux 均可用、
  无 WAL 共享内存依赖（`-shm` 在部分网络文件系统不可用的平台差异一并规避）；Windows 无目录
  fsync（§7.4 声明，文件级尽力）。
- 版本化：`PRAGMA user_version=1`（本片唯一版本）；初始建表在**单事务**内执行
  `CREATE TABLE IF NOT EXISTS artifacts / seal_attempts / artifact_store_meta`（幂等、可重开；
  模式参考 `TaskStore._init`，只读借鉴）。不建跨数据库迁移框架（FR-05 归后续片）。
- 表结构（实现细节，D2/IMPL 可在语义列不变下微调列组织，SF-09）：语义列与唯一约束冻结——
  `artifacts(artifact_id PK, tenant_id, task_id, workflow_id, stage_attempt_id,
  repository_snapshot_digest, schema_name, schema_version, producer, policy_digest,
  toolchain_digest, content_digest, blob_id, size_bytes, media_type, classification,
  retention_class, created_at, sealed_at, state, envelope_wire TEXT)`；
  `seal_attempts(staging_id PK, artifact_id, tenant_id, stage_attempt_id, state, created_at,
  updated_at, blob_id, content_digest)`；`artifact_store_meta(key PK, value)` 载荷至少含
  `root_id`（64-hex，handle 外来判定）、`tenant_storage_key_map_version=1`、`limits_fingerprint`
  （§7.1c）、限额账本行（计数）。所有查询以 `tenant_id = <store 绑定租户>` 为谓词（G3）。
- `envelope_wire` 存 `encode_envelope` 的 canonical JSON 文本（envelope 本身无日志正文；每条
  记录上界=行 9）。

### 7.4 崩溃/重启验证与平台分层声明（条款 20）

- 验证方式：**真实子进程 + 真 kill**（非模拟）：测试在子进程内于各协议步（S3 后/P1 前/P1 后/
  P2 前/P2 后）设置标记文件，父进程观测标记后调用 `subprocess.Popen.kill()`（Windows=
  TerminateProcess；Linux=SIGKILL）终止，再以**新进程**重开 root/SQLite 断言 §4.3 矩阵；
  P2 中崩溃必须断言 DELETE hot journal 回滚两态（已提交/净回滚，无第三态）；临界区内崩溃必须
  断言 OS 锁自动释放、账本不丢不重（§7.1d）。
- 持久化分层声明：本片验证与保证**进程崩溃**层面（进程死、OS 活）；API 边界 fsync（文件级
  `os.fsync`；Linux 目录 fsync；Windows 无目录 fsync API，仅文件级）尽力缩小 OS 缓存窗口；
  **不声称**文件系统/物理断电层面的跨平台原子性或持久性证明。Windows 与 Linux 都必须实际运行
  kill/重启验收（缺平台保留实际缺口，不以 skip 冒充通过）。

## 8. 测试方法与最小覆盖数 + 独立 Oracle（对齐说明书 §7 七组与 §7.2 D2 覆盖组）

**D2 才冻结实际测试文件名/符号/计数**；本节冻结方法族与最小覆盖数（合计 44 个测试方法——超出
P&V 默认预算 35 的理由：D1R 六项修正各自新增行为面（输出校验前置、复用核验、hash 物理键隔离、
限额计额与配置冲突、六字段绑定、回执/读结果分型）需要对应反例；按行为覆盖收敛，未删减任何
安全断言，不靠重复方法刷计数；D2 冻结时各组最小数不得降低）。探针/本表 PASS 均不构成产品
实现证据。

| 组（说明书 §7/D2 覆盖组） | 方法族 | 最小数 | 必含反例 |
|---|---|---|---|
| 隐私 | 真实 storage policy 净化；磁盘/DB/错误信息中无 raw Secret（含 SQLite 全文扫描）；缺 key/policy、净化失败、UNSUPPORTED_REDACTED_FORM 时零内容写入（目录快照对比）；**错 tenant 注入 → SanitizedPayload.tenant_id 不符 → S2b 拒绝零落盘（R66-01）；manifest 携错误 policy_digest → S2c 拒绝零落盘** | 6 | FingerprintRecord 形态拒绝且零落盘；绑定/策略反例经真实净化输出 |
| 真实闭环 | 同进程 stage→seal（回执）→get（读结果）；**新进程**重开 root/SQLite（同 root+同可信租户+policy）读回同字节；独立 digest 复算；envelope/blob_ref/reference 三方绑定校验；**回执无 content 字段 / 读结果 content=已验证字节（含合法空日志 b"" 唯一语义）** | 5 | 字节级全等断言（非仅 digest 相等） |
| 权限与输入 | 错租户（== NOT_FOUND 不可区分）；**六字段 ref 逐项校验（合法格式但错误 repository_snapshot_digest/content_digest → ARTIFACT_NOT_FOUND，R66-06②）**；错 type/version；非空 lineage/supersedes（stage 与 envelope helper 双入口）；未封送 id；缺失/损坏 blob 拒绝；**外来 root/tenant handle 拒绝（STAGING_STATE_INVALID）**；拒绝不泄露他租户 | 7 | 伪造 ref / 篡改 wire digest / 合法格式错误 digest |
| 不可变与重试 | 同 handle 重复 seal 幂等（**含跨进程重开 handle、P2 后崩溃重试**）；**幂等成功仍核验实物：SEALED 后实物损坏 → 重复 seal 稳定失败非假幂等（R66-02）**；**同长度坏旧 blob + 合法新 staging → 复用前核验拒绝（零覆盖、零新增 SEALED、原字节不动）**；**竞态分支核验（目标在核验与发布间出现）**；并发 seal（线程/进程）单胜者且不覆盖已存在有效对象；同字节不同 staging → 不同 artifact_id 同 blob；METADATA_CONFLICT 不覆盖 | 7 | 并发窗口内无双重提交；坏复用零副作用 |
| 故障与恢复 | 真子进程 kill 于 S3 后/P1 前/P1 后/P2 前/P2 后五点（两平台）；重启诊断分类正确；**P2 中 kill → DELETE hot journal 回滚两态**；部分/缺失内容不作为成功返回；**close 不破坏重试（close 后重开+原 handle 幂等）** | 6 | 无假 SEALED 断言 |
| 资源与路径 | 0-byte、Unicode 字节边界（单 emoji/多字节）、输入超限、**净化输出超限（膨胀反例 262,119 B 输入→365,378 B 输出 → SEALED_BUDGET_EXCEEDED、零内容写入、staging 目录为空、稳定失败无降级，R66-04）**、**更严格 policy 交集收紧（注入更严 policy 触发失败）**、**限额计额（重复同内容/空内容仍消耗逻辑额度；失败/崩溃残留计额；两真实进程争最后一个额度不超限；同 root limits 不一致 → STORE_CONFIG_CONFLICT；辅助文件预算；inspect 扫描有界）**、**两平台租户键（Windows `Tenant-A`/`tenant-a`、`tenant-end`/`tenant-end.` 独立物理目录互不混叠；合法标识含冒号/保留名租户正常封存；Linux 不同逻辑租户同内容独立存放；逻辑层 SQL/Reference/ACL 仍区分大小写与尾点，R66-03）**、路径穿越/symlink/junction/reparse 拒绝、满盘/权限（模拟注入） | 9 | 空对象不绕对象数；失败不变空成功 |
| 持久化边界 | SQLite 无日志正文/凭据（全库扫描）；metadata/ref 有界（行 9）；store 不可用无 inline/旧 report_json 降级；contracts/privacy 既有测试回归 + #60 面零触碰 | 4 | 契约兼容（import 面/wire 面） |

**独立 Oracle 要求**（D2 交付，禁止复用被测实现路径）：
1. digest 复算：`hashlib.sha256(sealed_bytes).hexdigest()` 直接计算，不经 `lima` codec；
2. 绑定校验：独立 JSON 遍历 envelope wire dict，验证 `content_digest==blob_ref.content_digest`、
   size、media type、schema 身份（不经 `decode_envelope`）；
3. 重启复读：独立子进程读文件字节做全等比较（不经 `get_log`）；
4. kill 时序：父进程独立观测标记文件（不在子进程内自证）；
5. **限额独立盘点（R66-05）**：独立文件系统遍历 + SQLite 只读查询重算对象数/字节数，与账本行
   比对（不经 store 计数接口）；
6. **物理键独立性（R66-03）**：独立计算 `SHA256(tenant_id)` 键并断言目录互不混叠（不经 store）。

## 9. Traceability

### 9.1 #66 requirement ID 逐行映射（18 ID；**无一条 SATISFIED**——D1R 零产品证据；状态语义：
PARTIAL=本片冻结其中本机 SQLite/日志子集行为、余下归后续片与 D2+ 证据；DESIGN-ONLY=本片仅设计
层冻结、实现证据归后续；NOT-COVERED=本片不做；**分布与 v1.0 不变：PARTIAL 14 / NOT-COVERED 2 /
DESIGN-ONLY 2 / SATISFIED 0——首片边界未扩大**）

| ID | 状态 | 本片贡献与理由 | 下一 Owner |
|---|---|---|---|
| FR-01 | PARTIAL | stage 仅建 attempt-scoped handle（净化已完成、输出校验先于任何写入、staging 只含净化内容）；seal 在类型/绑定/schema/digest/预算全过后返回 immutable ref 回执 | 后续片扩展非日志类型 |
| FR-02 | PARTIAL | 状态机实现 STAGING→SEALED 子集（QUARANTINED/EXPIRED/DELETING 不出现、corruption 不改状态）；SEALED 内容/身份绑定无任何覆盖路径（P1 三分支核验+临界区发布不覆盖既有有效对象，R66-02） | 后续片补 QUARANTINED/EXPIRED 转移与 ACL 面 |
| FR-03 | PARTIAL | 提交点协议（§4.2）明确 crash points；`inspect` 输出 staging/orphan/metadata-only/corrupt 四类；不静默伪造内容 | 后续片补 expired-with-reference 分类与自动 reconcile |
| FR-04 | PARTIAL | get 六字段绑定（G1–G6，R66-06②）；租户不符不可区分拒绝；本片无 lineage 查询（空 lineage only，非空双入口拒绝） | 后续片补 list_lineage/DAG/自环跨租户边 |
| FR-05 | NOT-COVERED | 本片仅版本化幂等建表（PRAGMA user_version+单事务 IF NOT EXISTS），非 migration registry；#67/#65 入口不存在 | 后续片（migration registry slice） |
| FR-06 | NOT-COVERED | 无 retention/pin/删除接口（首片无公共 delete/update）；容量满拒绝新写而非清理 | 后续片（retention slice） |
| NFR-01 | PARTIAL | 0-byte 到上限可验证（探针 P4.2a 实测 0-byte 路径）；**输入与净化输出双预算均在任何内容写入之前判定（S0/S2；膨胀反例 262,119→365,378 已纳入 §8，R66-04）**；路径/symlink/junction/reparse 防护（§7.2）；**hash 物理键消除大小写/尾点目录混叠（P6 win32 实测；Linux D2）** | 后续片补满盘演练平台面 |
| NFR-02 | PARTIAL | Blob IO 与 SQLite metadata 分离、业务仅 ref/字节/错误；本片仅本地 backend、不写 S3 SDK/配置框架；S3-compatible Port 语义由行为契约保证 | 后续片（S3 adapter） |
| AC-01/T-01 | PARTIAL | §4.3 矩阵 + §8 故障组（五 kill 点、两平台、真子进程、DELETE hot journal 两态）；无假 SEALED 断言 | D2+ 实证 |
| AC-02/T-02 | PARTIAL | 同 handle 幂等（含重开/崩溃重试且核验实物）、并发 seal 单胜者不覆盖、租户隔离（逻辑精确比较+hash 物理键双层）、无 ACL 放宽面（§4.4）；同字节≠同身份 | D2+ 实证 |
| AC-03/T-03 | PARTIAL | corrupt/missing blob、路径逃逸 fail closed 且 metadata 不丢（§6.1）；**坏旧 blob 复用在 seal 侧拒绝（R66-02，非仅 get 兜底）**；lineage 自环由契约层拒绝（源码复核：common.py `LINEAGE_SELF_REFERENCE`）、跨租户由契约层拒绝（探针 P3-B）+ 本片空 lineage only；Redis 不在链路 | D2+ 实证 |
| V5-FR-01 | PARTIAL | 新增 artifact 路径只存 metadata+blob ref（envelope_wire 无正文，§7.3）；**历史 report_json 迁移不在本片**（#66 仍是唯一迁移 Owner） | 后续片（迁移 slice） |
| V5-FR-02 | DESIGN-ONLY | seal 前强制 #94 policy 冻结于协议 S1（前置任何持久化；探针 P1 实测真实调用面；**policy 必填显式注入冻结于 §5.3 签名，R66-06①**）；实现证据归 D2+/IMPL | IMPL |
| V5-FR-03 | PARTIAL | digest verification 冻结为 G5 必检（探针 P3-A 证明不可省略）+ **六字段逐项绑定（G3）**；retention class 校验接受面；lineage query/tombstone 未实现（明确拒绝非空 lineage） | 后续片 |
| V5-FR-04 | DESIGN-ONLY | 无 inline 降级路径冻结于错误语义（CAPACITY_EXCEEDED/IO_ERROR 均拒绝，绝不回退 inline 巨型 JSON/旧 report_json）；实现证据归后续 | IMPL |
| V5-AC-01/V5-T-01 | PARTIAL | DB 只存 metadata/blob ref + seal 前强制 #94 + 不内联（§4.2/§7.3/§8 持久化边界组） | D2+ 实证 |
| V5-AC-02/V5-T-02 | PARTIAL | digest verify、跨 tenant/type mismatch 按契约工作（§6.1）；retention/tombstone/lineage query 未覆盖 | 后续片 |
| V5-AC-03/V5-T-03 | PARTIAL | blob/store 中断、partial write、重复 seal 可恢复且不返回未封存 Artifact（§4.3 矩阵 + §8） | D2+ 实证 |

分布统计：PARTIAL 14；NOT-COVERED 2（FR-05/06）；DESIGN-ONLY 2（V5-FR-02/04）；SATISFIED 0。

### 9.2 Assignment §7 条款 1–20 覆盖索引（D1 二十条；R66 改变者已更新落点）

| 条款 | 冻结位置 | 条款 | 冻结位置 |
|---|---|---|---|
| 1（类型身份） | §4.1 表 | 11（不持久化敏感物） | §6.1 错误面 + §7.3 |
| 2（复用契约） | §4.1 wire 行 | 12（stage/seal/get+入口） | §4.2、§5.3、`demo.py` |
| 3（digest 来源） | §4.1 digest 行（探针 P2） | 13（信任边界） | §4.5、§6.2 |
| 4（真实上下文） | §4.1 上下文行 + §5.3 字段表 | 14（身份/幂等/并发） | §4.4 |
| 5（lineage 空集） | §4.1 lineage 行 + §5.1 schema.py（探针 P3-C） | 15（提交点协议+处置） | §4.2（DR-PACKET-1） |
| 6（classification 相容） | §4.1 接受面行（探针 P1/P5） | 16（故障点矩阵） | §4.3 |
| 7（真实净化调用） | §4.2 S1（探针 P1/P5） | 17（资源上限） | §7.1 统一限额表 |
| 8（失败零落盘） | §4.2 S2、§6.1 | 18（路径与键） | §7.2 |
| 9（str-only 接受面） | §4.1/§6.1（探针 P1/P5） | 19（SQLite schema） | §7.3 |
| 10（双预算） | §7.1 + §4.2 S0/S2（探针 P4/P7） | 20（崩溃/重启验证） | §7.4 |

## 10. 平台命令骨架（实际命令面 D2 冻结；此处冻结骨架与平台义务）

**基线（合并前基线健康，两平台同）**

```bash
git fetch origin && git rev-parse origin/main        # 基线 SHA 声明
python -m compileall -q lima tests
python -m unittest discover -s tests -v              # 既有套件全绿（contracts/privacy/audit/#60 面零回归）
```

**slice（本片验收面）**

```bash
python -m unittest discover -s tests/artifacts -v   # D2 冻结的测试集
python -m ruff check lima/artifacts tests/artifacts
python -m bandit -q lima/artifacts
```

**integration（真实闭环示例）**

```bash
python -m lima.artifacts.demo --root "$TMP/ip0044-demo"   # 进程内闭环 + 子进程重开 + 独立 digest 复算
```

**boundary（文件边界 gate）**

```bash
git diff --name-only <base>..HEAD                    # 只允许 lima/artifacts/** 与 tests/artifacts/**（实现期）
git diff --check
```

**compatibility（契约兼容）**

```bash
python -m unittest discover -s tests -v              # 含既有 contracts/privacy 测试
python - <<'PY'
import lima.contracts.common, lima.evidence_privacy.port  # import 面未变
PY
```

**kill/重启（真子进程；两平台各自运行，缺平台记实际缺口）**

```text
Windows（PowerShell/Git Bash）：
  python -m tests.artifacts.crash_harness --point post_publish --root <tmp>
    （父进程：subprocess.Popen(...); 观测标记文件; child.kill()/taskkill /PID <pid> /T /F;
      新进程重开 root/SQLite 断言 §4.3 矩阵；P2 点含 DELETE hot journal 两态断言）
Linux：同 harness，父进程 os.kill(pid, SIGKILL)；其余一致
```

**post-merge（合并后在最新 main）**

```bash
python -m unittest discover -s tests/artifacts -v && python -m unittest discover -s tests -v
python -m lima.artifacts.demo --root <fresh tmp>
```

### 10.1 D2 收敛义务（v2.0：仅保留仍真实的义务；SF-05/SF-08 已核销）

**已核销登记**：

- **SF-05（abort 载体 D2 二选一）：核销**——R66-06④ 裁定删除 `STAGING_STATE_INVALID` 的「已
  abort」触发条件（本片无公共 abort 入口、`close()` 不批量 abort，该状态不可达；Assignment
  §11.9）。触发面收窄见 §6.1。
- **SF-08（content 双语义判空提示）：核销**——R66-06⑤ 裁定分型（`SealedLogReceipt` 无 content
  字段 / `RetrievedLogArtifact.content` 恒为已验证字节，合法空日志 `b""` 语义唯一；Assignment
  §11.10）；旧 `SealedLogArtifact` 类型删除（§5.1/§5.2/§5.3）。

**仍保留的 D2 收敛义务**：

1. **SF-06（crash harness 命名统一）**：§10 kill 骨架的 `tests.artifacts.crash_harness` 模块名
   与 §5.1 测试命名面（`tests/artifacts/test_*.py`）须在 D2 冻结时统一（harness 可为测试辅助
   模块，但命名归属须单值）。
2. **SF-09（内部模块落点/表列组织）**：`SealedLogReceipt`/`RetrievedLogArtifact`/
   `StoreHealthReport` 的模块归属（local_store.py vs schema.py vs recovery.py）与 SQLite 列
   组织可在 §5.1 文件边界内由 D2/IMPL 收敛——公共签名、字段与语义本轮已冻结（§5.3），仅物理
   落点可调（R66-06 收尾要求）。

## 11. Decision Request 区（随 Packet 呈批）

1. **DR-PACKET-1（既有呈批项，v2.0 更新表述）**：提交点协议对 #66 原文「先写临时 blob→
   fsync/verify→事务写 SEALED metadata→原子 rename」的处置——**方向认可；证明补齐（既有 blob
   有效复用与并发发布前提，即 R66-02 的三分支核验+临界区）后随本修订 Packet 一并呈批；本轮
   不视为已获批**（Assignment §9.7）。本 Packet 采用保留全部元素、把原子 rename 前移到
   metadata 事务之前的等价重排，并给出读者无不完整可见窗口的证明与覆盖范围声明（§4.2）。
   请 Maintainer 在本 Packet 新 head 批准时一并裁定该处置。
2. 其余：无新增 DR。六类升 Maintainer 事项（跨租户共享/真实身份来源/删除合规/默认部署/公共
   Contract/Profile 来源身份）本轮均未触发；SQLite 内部表结构、文件组织、实现手段按 Assignment
   §11 由责任角色在批准范围内自决（R66-06 公共合同已本轮冻结，不留给 D2/Implementation）。

## 12. 完成定义（Packet 完成本身，非产品完成）

本 Packet 视为完成，当且仅当：
1. 12 节齐备、20 条冻结项全部落地为可验证契约（§9.2 索引无空洞）、18-ID 映射表无 SATISFIED 且
   分布不变（PARTIAL 14 / NOT-COVERED 2 / DESIGN-ONLY 2 / SATISFIED 0）；
2. 六项 R66 各有唯一合同与可复核依据（§1.2 对照表）、§1.3 十六行替换核销完成、关键接口无 TBD
   （open/stage/seal/get 签名、错误码表 23 码、handle 字段表、回执/读结果类型、统一限额表、
   journal 模式单值 DELETE）；冻结值均有源码复核或设计探针实测支撑并标注出处；
3. 设计探针 P1–P8 在 `.pv_tmp/issue66-local-log-2026-10-10/probes/` 留有输入/命令/输出/脚本，
   可复现；R66-02/R66-05 的多进程与 crash 兑现如实标注协议推导/设计（D2/产品验收）；
4. docs-only 新 commit 落在 `codex/issue66-local-log-packet` 的 `1e6a6874` 之上（保留
   `de7181b3`/`1e6a6874` 历史，不 amend/force），`git diff --name-only 1e6a6874..HEAD` 与
   `git diff --name-only fbbbd619..HEAD` 均仅本文一份 md，工作树 clean，`git diff --check`
   干净；
5. PR 呈审以新精确 head 为准（`Related to #66`、无任何自动关闭关键字），停在审批点。

产品完成定义不在本文：需 D2 冻结测试 + 有效 RED + IMPL + 独立验证 + post-merge，且 #66 整体关闭
仍需完整 Closure Audit 与明确授权（首片完成 ≠ #66 DONE）。
