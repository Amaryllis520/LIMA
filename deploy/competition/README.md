# 参赛部署 profile（性能调优部署）

本目录是 LIMA 智能体漏洞挖掘平台在**比赛/性能评分场景**下的部署指引。与默认
部署的差异只有一类：**房间大小**（快照限额、内存、CPU、tmpfs）与**预处理
深度**。沙箱五层锁不放宽；受信构建门禁按其自身的 fail-closed 探针清单开启，
不构成沙箱放宽。设计依据：`docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md`
§8（规模化）、`docs/CXX_MEMORY_ANALYSIS.md`（受信构建生成门禁）。

环境变量样例见同目录 `.env.competition.example`（每项有注释）。

## 1. 快照限额参数组（放开默认限额）

默认限额面向普通 Web 仓库；参赛场景是大型 C/C++ 仓库（如 OpenHarmony 子系统、
油气仓库），需按组调整。以下资源值均为**建议值，非性能保证**：

| 变量 | 默认 | 参赛建议 | 说明 |
|---|---:|---:|---|
| `LIMA_REPOSITORY_SCAN_MAX_FILES` | 5000 | 50000 | 快照普通文件上限 |
| `LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES` | 524288 | 4194304 (4MB) | 单文件字节上限（大型生成代码/数据表需要） |
| `LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES` | 20971520 | 2147483648 (2GB) | 快照总字节上限 |

配套必须同步放大的 Sidecar/分析侧限额（否则快照进得去、分析出不来）：

| 变量 | 默认 | 参赛建议 |
|---|---:|---:|
| `LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS` | 300 | 900 |
| `LIMA_CXX_MAX_RESPONSE_BYTES` | 2097152 | 16777216 |
| `LIMA_CXX_MAX_MEMORY_MB`（Sidecar 容器 `mem_limit`） | 2048 | 8192 |
| `LIMA_CXX_MAX_PROCESSES`（Sidecar 容器 `pids_limit`） | 128 | 512 |
| `LIMA_CXX_MAX_AST_JSON_BYTES`（单 TU `-ast-dump=json` 输出预算；libexpat `xmlparse.c` 实测约 78MB） | 16777216 | 134217728 (128MB) |
| `LIMA_CXX_STEP_TIMEOUT_SECONDS` / `LIMA_CXX_TOTAL_TIMEOUT_SECONDS`（受信构建步骤） | 120 / 300 | 600 / 1800 |

智能体侧的 app 有效预算为 `LIMA_CXX_AGENT_MAX_CALLS`、
`LIMA_CXX_AGENT_MAX_OUTPUT_BYTES`；pilot 的并行、轮数与时限使用 CLI 参数，见 §7。

## 2. tmpfs / 内存 / CPU 建议

- Sidecar（cxx-analyzer）容器：`mem_limit` ≥ 8GB、`pids_limit` ≥ 512；CPU
  按并行度给满（每个并行目标一个 clang/ASan 编译运行）。
- WORK_ROOT / scratch/build 目录保持 **ephemeral tmpfs**（compose 已有
  `tmpfs` 挂载）；容量按最大单次实验（编译产物 + PoC 运行）估算，建议 ≥ 4GB。
- 仓库缓存（`LIMA_REPOSITORY_CACHE_ROOT` 所在卷）≥ 3× 最大仓库裸大小，
  `LIMA_REPOSITORY_CACHE_QUOTA_BYTES` 相应放大（默认 2GB，建议 10GB+），
  `LIMA_REPOSITORY_CACHE_MIN_FREE_BYTES` 保持 512MB 以上。
- 复现工作台的 ASan 运行是串行资源大头：pilot 的 `--parallelism`
  不应超过独立沙箱实例数，并需满足 CPU 核数与 Sidecar 内存预算。

## 3. 受信构建门禁开启步骤

默认部署**永不执行**仓库里的构建系统（`CMakeLists.txt` 可通过
`execute_process()` 产生任意副作用）。需要 compile_commands.json 的仓库走
受信构建生成门禁，开启步骤：

1. 部署环境先满足机器可探测探针（`cxx_analyzer/trust.py` 执行时 fail-closed
   探测，缺一即不执行）：Landlock ABI ≥ 3、seccomp 进程隔离可用、非 root
   uid、network namespace 仅 loopback、WORK_ROOT 所在挂载只读、snapshot 与
   import 目录只读挂载、无 Docker socket / host path / credential 挂载、
   scratch/build 为请求后销毁的 ephemeral tmpfs、CPU/memory/PID/输出/文件
   大小/绝对时间限额配置存在。
2. 设置管理员级总门禁 `LIMA_CXX_TRUSTED_BUILD_CONTEXT_GENERATION=true`
   （部署环境变量；分析请求、仓库内容与模型输出都无法设置或影响它）。
3. 如需自动选择 CMake adapter，设 `LIMA_CXX_AUTO_CMAKE=true`（仅是 adapter
   选择器，本身不构成执行授权）；否则用管理员显式 argv
   `LIMA_CXX_BUILD_STEPS_JSON` / `LIMA_CXX_TEST_STEPS_JSON`。
4. 验证：`/health` 的 `trusted_build_context_generation_available` 为 true
   才表示门禁可用；默认 Compose 部署不会全部通过探针，需要专门加固部署。

注意：总门禁只影响"为快照生成构建上下文"这一步，沙箱五层锁不变；模型生成
的 PoC 与仓库代码同狱。

## 4. 离线依赖预处理流程（沙箱不开外网）

沙箱内无网络是设计约束（设计 §10.1）。依赖一律在沙箱外预处理：

1. **沙箱外 clone**：在宿主/构建机完成 `git clone`（含子模块
   `--recurse-submodules`）。
2. **拉依赖**：包管理器（vcpkg/conan/tpf/hpm 等）在宿主解析并下载全部三方
   依赖到仓库内的 vendor/依赖目录；交叉编译工具链按目标架构就位。
3. **打包导入目录**：把"源码 + 依赖闭包"整理为一棵只读导入树，放到
   `LIMA_REPOSITORY_IMPORT_ROOT` 下；剔除与检测无关的巨型目录（见 §5 的
   OpenHarmony 注意事项）。
4. **固定指纹灌入**：扫描引用 `local-import` 源类型；快照身份由内容哈希
   派生（`snapshot_hash`），同一棵导入树灌入得到同一指纹——分诊、事实、
   实验、报告与结果缓存（Task 9 的 `ResultCache`）都锚定这一指纹，重复
   运行命中缓存即跳过已完成的智能体/实验工作。
5. 之后平台的所有下载类来源（github 等）保持关闭，
   `LIMA_REPOSITORY_SCAN_SOURCES=local-import`。

## 5. OpenHarmony 专用注意事项

- **`*.inl` 已在白名单**：`.inl/.ipp/.tpp` 内联实现头在
  `lima/workspace.py` 与 `cxx_analyzer/snapshot.py` 两处镜像的白名单里
  （缺失会让 OH 的 cvfObject.inl 这类 TU 准备失败），无需部署侧处理。
- **Qt 依赖目录剔除**：OH 图形栈周边常带 Qt/第三方 SDK 目录，体积大且不进
  编译闭包；导入前从导入树剔除（或移到快照配额外的目录），否则会吃掉
  `LIMA_REPOSITORY_SCAN_MAX_FILES/MAX_TOTAL_BYTES` 配额并给事实提取带来
  噪声。
- OH 仓库通常整仓无法构建：按设计走依赖闭包抽取，不承诺整仓构建；对参与
  检测的子系统目录保持相对完整的 compile_commands.json（或开启 §3 门禁）。

## 6. 规模化设施（平台内置）

- **并行**：`run_platform_review(parallelism=N)` 让独立目标在受控线程内并
  行实验；结果恒按确定性 Scout 序聚合（并行只影响墙钟，不改输出序）。
  当前 app 未接入 Settings 的并行参数；pilot 使用 `--parallelism`。
- **缓存**：`run_platform_review(cache=ResultCache(dir, ns))` 按快照指纹 +
  目标全字段 + 模式 + 对话轮数复用每目标完整结果；命中即零 LLM 调用、零
  沙箱实验。缓存损坏自愈（坏条目按未命中处理并删除）。
- **增量**：`lima.agent_scale.detect_changed_files` 提供两份
  `{path: sha256}` 清单的三方差异（新增/修改/删除），是"仅变更文件重跑"的
  数据基础；按文件粒度的自动增量重跑为接口预留（当前缓存键以整快照指纹为
  锚，任何文件变更都会换指纹全量重算——这是快照身份贯穿不变量的直接后果）。

OpenHarmony pilot 验证 CLI（`scripts/run_openharmony_validation.py`）的完整
运行手册见 `docs/competition/使用说明书.md` §10；快照限额必须与 Sidecar 同值。

## 7. 变量来源表与入口区别

下表逐项对应 `deploy/competition/.env.competition.example`。默认值来自实际
解析器/消费方；建议值即示例值，资源建议沿用上文，**建议值，非性能保证**。
“空”表示不填；占位目录须由部署者替换。共享变量在示例中只定义一次。

### 全局 app / Compose 插值

命令入口：`python -m lima`；挂载来源仅由 `docker compose --profile cxx up` 插值消费。

| 变量 | 实际解析/消费位置及用途 | 单位 | 默认 | 参赛建议/示例值 | 联动与适用范围 |
|---|---|---|---|---|---|
| `LIMA_REPOSITORY_IMPORT_ROOT` | lima/config.py Settings.from_env → lima/service.py RepositoryImportPolicy；宿主导入根 | 路径 | 空 | `./REPLACE_WITH_IMPORT_ROOT` | 填写只读导入树；pilot 必须另传 --repository-import-root |
| `LIMA_REPOSITORY_IMPORT_PATH` | docker-compose.yml volumes；宿主导入树挂载来源 | 路径 | ./repositories | `./REPLACE_WITH_IMPORT_PATH` | 仅 Compose 插值；容器 IMPORT_ROOT 固定为 /repositories |
| `LIMA_REPOSITORY_SCAN_SOURCES` | lima/config.py Settings.from_env → lima/service.py；扫描来源限制 | 枚举 | local-import | `local-import` | 只接受本地导入；pilot 不读此项 |
| `LIMA_REPOSITORY_SCAN_MAX_FILES` | lima/config.py / cxx_analyzer/config.py / scripts/run_openharmony_validation.py _resolve_limit；快照文件限额 | 文件数 | 5000 | `50000` | app、Sidecar、pilot 同值；CLI --max-files 优先 |
| `LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES` | lima/config.py / cxx_analyzer/config.py / scripts/run_openharmony_validation.py _resolve_limit；单文件限额 | 字节 | 524288 | `4194304` | 三入口同值；CLI --max-file-bytes 优先 |
| `LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES` | lima/config.py / cxx_analyzer/config.py / scripts/run_openharmony_validation.py _resolve_limit；总快照限额 | 字节 | 20971520 | `2147483648` | 三入口同值；CLI --max-total-bytes 优先 |
| `LIMA_REPOSITORY_CACHE_ROOT` | lima/config.py _repository_cache_root_from_env → lima/service.py RepositoryCache；缓存目录 | 路径 | output/repository-cache | 留空 | 留空沿用默认；自填 `<CACHE_ROOT>` 并配套磁盘配额；Compose 默认命名卷 |
| `LIMA_REPOSITORY_CACHE_QUOTA_BYTES` | lima/config.py Settings.from_env → lima/service.py RepositoryCache；缓存配额 | 字节 | 2147483648 | `10737418240` | 建议 10GiB 起；仅启用 GitHub 物化时使用 |
| `LIMA_REPOSITORY_CACHE_MIN_FREE_BYTES` | lima/config.py Settings.from_env → lima/service.py RepositoryCache；磁盘余量 | 字节 | 536870912 | `536870912` | 保持至少 512MiB；与缓存卷容量联动 |
| `LIMA_CXX_MEMORY_MODE` | lima/config.py Settings.from_env → lima/service.py；Sidecar 客户端开关 | 枚举 | off | `off` | 启用 app agent required 前需改为 auto/required |
| `LIMA_CXX_ANALYZER_URL` | lima/config.py → lima/service.py CxxMemoryAnalyzerClient；pilot main 也读取 | URL | app http://cxx-analyzer:8090；pilot http://127.0.0.1:8090 | `http://cxx-analyzer:8090` | Compose 内部地址；宿主 pilot 用 --cxx-analyzer-url `<SIDECAR_URL>` |
| `LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS` | lima/config.py → lima/service.py CxxMemoryAnalyzerClient；app 请求超时 | 秒 | 300 | `900` | pilot 不读；pilot 另传 --timeout；与 Sidecar 时限协调 |
| `LIMA_CXX_MAX_RESPONSE_BYTES` | lima/config.py → lima/service.py CxxMemoryAnalyzerClient；app 响应上限 | 字节 | 2097152 | `16777216` | pilot 不读且固定 8388608；不是 Sidecar AST 预算 |
| `LIMA_CXX_AGENT_MODE` | lima/config.py → lima/service.py RepositoryScanner；app agent 默认模式 | 枚举 | off | `off` | 无凭据保持 off；pilot 不读且不受此开关保护 |
| `LIMA_CXX_AGENT_MODEL` | lima/config.py → lima/service.py 模型覆盖；pilot main 模型选择 | 模型名 | 空 | 留空 | 留空回退；显式启用前填 `<MODEL_ID>` 或 LIMA_LLM_MODEL |
| `LIMA_CXX_AGENT_MAX_CALLS` | lima/config.py → lima/service.py CxxAgentBudget；app 调用预算 | 调用次数 | 40 | `40` | 仅 app；pilot budget_factory 固定 160 |
| `LIMA_CXX_AGENT_MAX_OUTPUT_BYTES` | lima/config.py → lima/service.py CxxAgentBudget；app 工具输出预算 | 字节 | 1048576 | `1048576` | 仅 app；pilot budget_factory 固定 16777216 |
| `LIMA_REPOSITORY_SCAN_LLM_MODE` | lima/config.py → lima/service.py _build_repository_semantic_triage；语义分诊 | 枚举 | off（根 .env.example 为 auto） | `off` | 保持 off；启用时须与模型凭据及预算联动 |
| `LIMA_REPOSITORY_INVESTIGATION_MODE` | lima/config.py → lima/service.py _build_repository_investigation；模型调查 | 枚举 | off | `off` | 保持 off；与语义分诊、agent 分开控制 |
| `LIMA_LLM_PROVIDER` | lima/config.py Settings.resolved_llm；pilot main provider 标签 | 枚举 | app local；pilot custom | `local` | 保持 local 且通用地址/密钥/模型全空；pilot 此值不是禁用门禁 |
| `LIMA_LLM_BASE_URL` | lima/config.py Settings.resolved_llm；pilot main provider 地址 | URL | 空 | 留空 | 留空；授权调用时填 `<PROVIDER_BASE_URL>`，同时填密钥和模型 |
| `LIMA_LLM_API_KEY` | lima/config.py Settings.resolved_llm；pilot main 唯一 API key 环境来源 | 字符串（无单位） | 空 | 留空 | 保持空；调用前在进程环境私下填写，勿提交 |
| `LIMA_LLM_MODEL` | lima/config.py Settings.resolved_llm；pilot main 模型回退 | 模型名 | 空 | 留空 | 留空；授权调用时填 `<MODEL_ID>` 并配套地址与密钥 |

### Sidecar

命令入口：`python -m cxx_analyzer.server`。

| 变量 | 实际解析/消费位置及用途 | 单位 | 默认 | 参赛建议/示例值 | 联动与适用范围 |
|---|---|---|---|---|---|
| `LIMA_CXX_AUTO_CMAKE` | cxx_analyzer/config.py AnalyzerSettings.from_env；构建 adapter 选择 | 布尔 | 解析器 false；Compose true | `false` | 保持 false；不等于受信构建执行授权 |
| `LIMA_CXX_TRUSTED_BUILD_CONTEXT_GENERATION` | cxx_analyzer/config.py AnalyzerSettings.from_env；受信构建总门禁 | 布尔 | false | `false` | 保持 false；Compose 不透传，开启需先满足 §3 全部探针 |
| `LIMA_CXX_MAX_MEMORY_MB` | cxx_analyzer/config.py；docker-compose.yml mem_limit；内存预算 | MiB | 2048 | `8192` | 与容器限额和独立沙箱数协调 |
| `LIMA_CXX_MAX_PROCESSES` | cxx_analyzer/config.py；docker-compose.yml pids_limit；PID 预算 | 进程数 | 128 | `512` | 与容器限额及并行度协调 |
| `LIMA_CXX_MAX_AST_JSON_BYTES` | cxx_analyzer/config.py → cxx_analyzer/server.py；单 TU AST 输出预算 | 字节 | 16777216 | `134217728` | 与单 TU 规模及内存预算协调 |
| `LIMA_CXX_STEP_TIMEOUT_SECONDS` | cxx_analyzer/config.py → cxx_analyzer/build_scan.py / server.py；步骤时限 | 秒 | 120 | `600` | Compose 不透传；直接注入 Sidecar 进程；总时限不得小于步骤时限 |
| `LIMA_CXX_TOTAL_TIMEOUT_SECONDS` | cxx_analyzer/config.py → cxx_analyzer/server.py AnalysisDeadline；分析总时限 | 秒 | 300 | `1800` | Compose 不透传；直接注入 Sidecar 进程；客户端等待需另行协调 |

### pilot CLI 专用

命令入口：`python scripts/run_openharmony_validation.py`。

| 变量 | 实际解析/消费位置及用途 | 单位 | 默认 | 参赛建议/示例值 | 联动与适用范围 |
|---|---|---|---|---|---|
| `LIMA_CXX_AGENT_REQUEST_PARAMS_JSON` | scripts/run_openharmony_validation.py main；provider 附加请求参数 | JSON 对象（无单位） | 未设置 | `{}` | 仅 pilot；按 provider 要求填写，例 thinking disabled；app 不读取 |

### 必须区分的配置边界

- pilot 地址优先级：`--provider-url` > `LIMA_LLM_BASE_URL`；模型优先级：
  `--model` > `LIMA_CXX_AGENT_MODEL` > `LIMA_LLM_MODEL`。密钥只取
  `LIMA_LLM_API_KEY`，不会自动使用 `LIMA_DEEPSEEK_API_KEY` 或
  `LIMA_OPENROUTER_API_KEY`。`LIMA_LLM_PROVIDER=local` 与
  `LIMA_CXX_AGENT_MODE=off` 均不是 pilot 的远程调用门禁；安全示例让通用
  地址、密钥和两个模型字段全部留空，未配置地址/模型的 pilot 会退出配置错误。
- app 的 `resolved_llm()` 在 provider 为 local 但通用地址/密钥/模型任一非空时
  会转入 custom 解析；所以占位地址/模型写在注释中，不写成有效值。
  app 模型覆盖为空时保留 provider 解析后的模型；通用模型由 provider 规则回退。
- `LIMA_CXX_AGENT_PARALLELISM`、`LIMA_CXX_AGENT_DIALOGUE_ROUNDS`、
  `LIMA_CXX_AGENT_TIMEOUT_SECONDS` 虽由 `lima/config.py` 读取和校验，
  当前 app 没有执行消费方，因此不放入可用示例。pilot 分别显式传
  `--parallelism`（默认 1）、`--dialogue-rounds`（默认 1）、
  `--timeout`（默认 60 秒）；`--deadline-seconds` 默认 1800 秒。
  导入目录必须传 `--repository-import-root`；不回退到 app 的导入根。
- pilot 的 `CxxMemoryAnalyzerClient` 响应限额固定 8388608 字节；
  `budget_factory` 固定 max_calls=160、max_output_bytes=16777216。
  app 的同类预算环境变量不会改变这些值。
- `LIMA_CXX_AGENT_REQUEST_PARAMS_JSON` 仅 pilot 读取；默认 `{}`，按 provider
  文档选择，例如 `{"thinking":{"type":"disabled"}}`；不将其当作 app 通用参数。
- Compose 的插值输入与容器环境是两层：`--env-file` 只供插值，
  不会把文件里所有变量都注入服务。app 的 `env_file` 指向根 `.env`，
  Sidecar 没有 `env_file`，只获得其 `environment` 明列的变量。
  当前 Compose 不透传 Sidecar 的两个步骤时限和受信构建总门禁；
  不能宣称修改示例就已应用这些值。app 导入根被 Compose 固定为 `/repositories`。
  本任务不改变 Compose 权限、CPU/tmpfs、检测规则或受信构建策略。

## 8. 安全使用步骤（PowerShell）

1. 在仓库根执行。若已有根 `.env` 或 `lima/.env`，先备份；命令仅复制到
   新建的临时测试目录，任何合并都不写回原文件：

   ```powershell
   $competitionReviewDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
   New-Item -ItemType Directory -Path $competitionReviewDir | Out-Null
   if (Test-Path -LiteralPath .env) {
       Copy-Item -LiteralPath .env -Destination (Join-Path $competitionReviewDir 'root.env.backup')
       Copy-Item -LiteralPath .env -Destination (Join-Path $competitionReviewDir 'merged.env.test')
   } else {
       New-Item -ItemType File -Path (Join-Path $competitionReviewDir 'merged.env.test') | Out-Null
   }
   if (Test-Path -LiteralPath lima/.env) {
       Copy-Item -LiteralPath lima/.env -Destination (Join-Path $competitionReviewDir 'package.env.backup')
   }
   Copy-Item -LiteralPath deploy/competition/.env.competition.example -Destination (Join-Path $competitionReviewDir 'competition.env.test')
   ```

2. 对照 §7，只在 `merged.env.test` 测试副本中逐项人工合并所需入口的值，
   同名 key 替换而非追加；不把文件当 shell 脚本执行。地址/目录占位符自行填写。
   旧配置可能已有付费凭据：无模型冒烟须在副本清空通用及 provider 专用密钥、
   地址和模型，并保持三个模型模式 off、受信构建 false。备份可能含密钥，
   不要提交、共享或贴入日志。清理进程环境中遗留的同名及 `EVOAGENT_*` 旧变量；
   app 的 dotenv 使用 setdefault，进程环境优先于文件，根 `.env` 优先于 `lima/.env`。
3. **该示例不会被 Compose 自动加载**，也不会被 app 自动发现。
   如后续明确选择 Compose，`--env-file <测试副本路径>` 仅参与插值，
   仍须核对固定 `environment` 与根 `.env` 的服务注入；示例不含 Compose 必需的
   数据库/登录秘密，不能直接作为完整生产配置启动。遵循既有部署流程，
   本文不提供覆盖用户 `.env` 或放宽 Sidecar 安全配置的命令。
4. 先在宿主机 Python 3.13 运行静态检查（不依赖 Docker，不加载 `.env`，不访问模型）：

   ```powershell
   python -m unittest tests.test_competition_env_example -v
   git diff --check
   ```

5. 确认副本差异、安全缺省和入口映射后，再按部署流程人工验收应用。
   真正运行 pilot 需独立准备 case、只读导入树、Sidecar、全新 output 路径，
   并明确授权模型调用后再配置凭据及命令参数。静态检查不证明资源建议的性能，
   也不代替 10-18～19 干净部署冒烟与 10-20 冻结门禁。
