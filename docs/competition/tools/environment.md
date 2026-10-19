# Competition 环境身份清单（#313）

## 计划与测试流程（先于实现冻结）

基线：main `8c77ea10286ce2146909b16b5d44889dd05128c2`。
分支：`codex/issue-313-environment`。仅新增本 issue 指定的四个文件。
2026-10-19 通过 GitHub API 核对 main；Git 直连 fetch 失败，但本地已含同一 SHA。
当时未合并的 #317 属于 #312，不是本工具的依赖。

1. 先写 `tests/test_competition_environment.py`，在 Docker 中证明未实现时失败。
2. 新增标准库实现和独立 CLI；不导入设置初始化、服务或模型客户端。
3. 在 Docker 内执行专项 unittest 和实际 CLI；全部自动验收用合成数据/Mock。
4. 临时 Git 仓验证 clean → untracked dirty → clean；不扫描真实目标仓库。
5. 无 Docker/无密钥演示；验证输出冲突、隐私和异常退出码。
6. 检查新增文件白名单、输入只读性、测试结果和未验证项。

专项命令：

```text
python -m unittest tests.test_competition_environment -v
```

覆盖 Git 缺失、clean/dirty/未跟踪、异常身份、工具缺失/超时/输出超限、Docker
缺失/权限不足、精确容器选择、字段投影、恶意标签、敏感异常、冲突输出、
声明模型身份、配置不读取，以及真实入口脚本。

## CLI 合同

```text
python scripts/export_competition_environment.py --repository <checkout-root> --run-label <label> --output <new-file.json> [--container <exact-id-or-name>] [--model-label <operator-label>]
```

Python 3.11+，仅使用标准库。既有 `lima/__init__.py` 只有版本声明；工具不导入
settings、服务或第三方初始化，也不修改依赖、Dockerfile 或部署。

`--repository` 必须是选定工作树的根目录。Git 可用时核对 `--show-toplevel`，
避免把普通子目录误认成其父仓库。支持普通工作树及 Git worktree；不采集远端 URL。
输出父目录必须已存在、文件必须不存在，且必须位于选定仓库外部，避免导出操作
污染正在采集的 dirty 状态。即使文件在采集期间被别人创建，也不会覆盖。
不创建目录，不向已有 bundle 写入，不修改输入。

run/model/container 标签均为 1–128 字符的 ASCII 标识：首字符字母或数字，
其余只允许字母、数字、点、下划线、连字符。拒绝路径、URL、查询参数、控制字符、
代理参数及明显凭证标记。不要把任何凭证当标签；任意不透明字符串是否为凭证无法
自动证明。镜像引用采用独立的 registry/repository:tag@sha256 语法校验，拒绝 URL
userinfo、参数、控制字符和明显凭证标记；异常内容不会原文写回。

成功时 stdout/stderr 为空；读取新 JSON 即可查看清单。失败诊断只包含固定原因码。
`--help` 展示用法并返回 0。不接受任意工具命令、环境变量清单或预算参数。

| 退出码 | 含义 |
| --- | --- |
| 0 | 已生成清单；可选信息可能为 null/unknown，并附原因 |
| 2 | 仓库目录不可读、不存在、不是工作树根，或必需的根身份无法核实 |
| 3 | 用法、标签、输出冲突、输出权限或其他导出错误 |

Git 执行文件缺失或无法启动时，源码 commit/dirty 均为 null + 原因，仍可退出 0；
不会把“没有 Git”当作 clean。Git 能启动却拒绝必需的工作树身份查询则退出 2。
根目录已确认后，HEAD/status 超时等错误分别保留为 unknown，不伪造身份或 clean。
没有 commit 的新 Git 仓可以输出 commit=null；dirty 仍按实际 status 记录。

## 字段与采集边界

| 字段 | 来源与含义 |
| --- | --- |
| `schema_version`, `run_label`, `generated_at_utc` | 固定版本 1、操作者标签、UTC ISO 时间（Z） |
| `host.os_type`, `host.os_version`, `host.architecture` | 运行导出器的环境的 OS、release 和架构；不记录 hostname |
| `host.logical_cpu_count`, `host.python_version` | 逻辑 CPU 数和当前 Python 数字版本 |
| `host.memory_total_bytes`, `host.memory_reason` | 固定 null + 未额外安装依赖采集的说明 |
| `host.unknown_reasons` | 缺失/异常的宿主字段原因；空架构记 null，异常不回显 |
| `source.commit`, `source.dirty`, `source.unknown_reasons` | 完整 commit、含未跟踪文件的 dirty、每项未知原因 |
| `host_tools` | 固定 Git、clang、clang-14、CMake 的数字版本；每项明确 `source=host` |
| `container.image_id`, `container.image_reference` | 显式指定容器的镜像内容 ID 和镜像引用 |
| `container.limits` | NanoCPUs、CPU period/quota/cpuset、memory/swap bytes、PID 限额原始配置 |
| `container.tool_versions` | 始终 `unknown`，原因 `not_collected`；不冒称 Sidecar clang 已采集 |
| `model` | 可选操作者标签，`source=operator-declared`，后端版本 `unknown` |
| `limitations` | 明确非依赖锁、非健康检查，模型后端与容器内工具版本未验证 |

`host` 指导出器所在的执行环境；在容器内运行导出器时，它指该执行容器，不能
据此推断 Docker 物理宿主或另一个 Sidecar 的工具版本。CPU 数也不等于容器 CPU
配额。Docker 限额是 daemon 记录的原始配置，0/-1/null 保留其原始语义，不能
解释为实测用量或已验证的隔离效果。

所有版本命令固定为 `[tool, "--version"]`，不运行用户传来的命令。
每条命令 `shell=False`、stdin/stderr 为 DEVNULL、最多 5 秒、stdout 最多保留
16 KiB（超限读取一个哨兵字节即终止子进程）。仅匹配首行已知前缀后的数字版本，
丢弃编译路径、供应商附注、用户名、额外行和原始异常。工具缺失、权限错误、
超时、非零退出、超限、无法识别分别记录固定原因。

Git status 使用 `--untracked-files=all` 和 `--no-optional-locks`，关闭 fsmonitor
和 untracked cache；只保留“输出是否为空”，不记录文件名或 diff。工具不枚举
`os.environ`，不转储 sys.path、完整命令行、用户名、机器名、工作目录，也不读取
`.env`、config.toml 或凭证。Git 本身正常读取其仓库元数据和忽略规则。

未传 `--container` 时 Docker 调用数为零，连 `docker --version` 也不会调用。
传入后只有一次 `docker inspect --type=container --format <fixed-projection> -- <exact-id>`，
模板只访问 `.Image`、`.Config.Image` 和特定 `.HostConfig` 限额字段。
不取完整 inspect，不访问 Env/Mounts，不 exec、拉取、构建、启动、重启或遍历容器。
Docker 不可用或响应异常时保留 null + 原因，仍可生成宿主清单。

## 可复制的无密钥、无 Docker 演示

在仓库根目录运行 PowerShell；每次使用新的 demo 目录：

```powershell
$demo = Join-Path $PWD 'output/environment-313-demo'
New-Item -ItemType Directory -Path $demo | Out-Null
git -c init.templateDir= init -q "$demo/repository"
git -C "$demo/repository" -c user.name=Synthetic -c user.email=synthetic@example.invalid -c commit.gpgsign=false -c core.hooksPath=__no_hooks__ commit --allow-empty -qm synthetic
python scripts/export_competition_environment.py --repository "$demo/repository" --run-label clean --output "$demo/clean.json"
Set-Content -LiteralPath "$demo/repository/untracked.txt" -Value synthetic
python scripts/export_competition_environment.py --repository "$demo/repository" --run-label dirty --output "$demo/dirty.json" --model-label operator-model-v1
Remove-Item -LiteralPath "$demo/repository/untracked.txt"
python scripts/export_competition_environment.py --repository "$demo/repository" --run-label restored --output "$demo/restored.json"
```

三个 JSON 的 `source.dirty` 依次为 false、true、false；第二个模型身份仍为
`operator-declared` / `unknown`。这组命令不调用 Docker，也不调用模型供应商。
没有 Git 时可以选择一个已存在目录演示 unknown 回退；不要把它误称为源码已验证。

## Docker 专项流程

复用本机已有、含 Python 和 Git 的测试镜像 `lima:issue312-test-git`，不安装库、
不拉取镜像、不构建部署。其他环境可以使用其已有同等测试镜像；不声称此本地 tag
是公开可拉取的镜像。创建只包含此次新增代码的测试上下文，避免挂载本机配置：

```powershell
$stage = Join-Path $PWD 'output/environment-313-test-context'
New-Item -ItemType Directory -Path $stage | Out-Null
New-Item -ItemType Directory -Path "$stage/lima","$stage/tests","$stage/scripts" | Out-Null
[IO.File]::WriteAllText("$stage/lima/__init__.py", '')
[IO.File]::WriteAllText("$stage/tests/__init__.py", '')
Copy-Item lima/competition_environment.py "$stage/lima/"
Copy-Item tests/test_competition_environment.py "$stage/tests/"
Copy-Item scripts/export_competition_environment.py "$stage/scripts/"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 2 --pids-limit 128 --tmpfs /tmp:rw,size=128m --mount "type=bind,source=$stage,target=/work,readonly" --workdir /work lima:issue312-test-git python -m unittest tests.test_competition_environment -v
```

专项测试自行创建临时合成 Git 仓、埋入隐私哨兵，并校验文件哈希；不执行目标代码。
Docker inspect 的失败与隐私场景使用 Mock，无需挂载 Docker socket。

## 实际验证记录（2026-10-19）

- 初始 21 项测试先写：Docker 中因模块未实现产生 ImportError，留存 RED 日志。
- 首版实现后 21 项通过。Windows 补测修正一处 CRLF 测试断言，并增加真实 Git、
  非零退出、资源类型、输出竞争测试；并非宣称初始测试文件字节永久不变。
- 实际 CLI 揭示父仓库向上发现问题，先补 3 项失败测试，再增加根身份核验和
  缺失宿主字段的 unknown 原因。最终专项共 28 项。
- Docker/Linux Python 3.11.16 和 Windows 本机 Python 3.9.13 均通过全部 28 项。
  本机 3.9 只是额外兼容性观察，项目支持基线仍是 3.11+。
- Docker 相关回归共 77 项：75 通过，2 项既有 Windows Job Object 测试在 Linux
  跳过；无失败。包括本工具、competition performance、competition coverage、CI 合同。
- 实际入口 CLI 在 Docker 和 Windows 各完成 16 个合成场景，退出码符合预期；
  每次输入仓库文件哈希不变，JSON/stdout/stderr 未含所埋隐私哨兵或绝对输入路径。
- Windows 真实 inspect 对象是专为验收创建但未启动的合成容器，带合成 Env 哨兵；
  最小投影得到 1 CPU、201326592 memory bytes、PID 32，Env/Mounts 未进入输出。
  测试基础设施创建并删除夹具容器，导出器自身仅 inspect。
- 无 Git/无工具场景使用空 PATH；Windows 驱动仅保留 Python 启动所需 SystemRoot，
  不携带密钥。无 Docker 镜像内的实际选择容器场景记录 `not_found`，未伪造工具版本。
- Bandit 的命令执行专项检查报告 1 项 LOW/HIGH-confidence B603：通用 Popen
  包装器。已逐一核对调用点：固定 argv 工具名/参数，只有受限容器标识可来自 CLI，
  `shell=False`；未通过忽略规则隐去该提示。
- 未执行全项目测试、真实模型、真实漏洞 PoC、真实 OH 扫描、服务部署或健康检查。
  没有安装新依赖或修改共享文件。独立人工审阅和合并后 CI 尚未执行。

相关回归命令：

```text
python -m unittest tests.test_competition_environment tests.test_competition_performance tests.test_competition_coverage tests.test_ci_contract -v
```

实际 Linux 无工具输出的关键字段：

```json
{
  "source": {
    "commit": null,
    "dirty": null,
    "unknown_reasons": {"commit": "not_found", "dirty": "not_found"}
  },
  "container": {"image_id": null, "reason": "not_selected", "tool_versions": "unknown"},
  "model": {"label": null, "source": "operator-declared", "backend_version": "unknown"}
}
```

以上是实际输出的字段节选，不是完整清单。原始日志、CLI 生成的完整 JSON、
合成验收驱动和逐场景结果留在本地忽略目录 `output/competition-environment-313/`，
未纳入交付源码；日志中的本机路径不应发布。
