# 双仓库验证记录（Competition Validation）

本文档记录智能体漏洞挖掘平台（内存包）在真实仓库上的论文侧验证状态与
配对基准结果，是 `docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md`
§11 评测条款与设计 §9.4/§9.10 诚实纪律的落地台账。核心规则
（沿承 `2026-09-02-cxx-llm-agent-detection-design.md` 验收条款）：

> 环境未提供 Docker、真实模型或真实执行时，对应验证层必须写"未验证"，
> 不得以 Fake 结果推断通过；任何演示性放宽必须逐条标注。

- 记录基线：worktree `D:\Projects\LIMA\.worktrees\cxx-llm-agent-detection`，
  HEAD `7a45bbd`（Task 10 落地时实测，见下文数字）。
- 更新约定：每完成一层验证，把状态表的"未验证"改为"已验证"并附证据
  路径与日期；不删除历史记录，只追加。

## 1. 分类验证状态表（诚实纪律对齐）

| 验证层 | 验证方式 | 状态 | 证据 |
|---|---|---|---|
| 平台管线闭环（Scout→假设→实验→修正→裁决） | `tests/test_platform_evaluation.py`（26 测试，零网络 Fake） | 已验证（Fake，2026-09-11） | 本仓库 unittest；`scripts/run_platform_evaluation.py --fake-llm` 全绿 |
| 配对基准指标（检测率/误报率/非安全过滤/实验收敛/PoC 稳定性） | `scripts/run_platform_evaluation.py` 全 6 案例 Fake 跑批 | 已验证（Fake，按构造确定性） | 报告 `detection_rate=1.0`、`false_positive_rate=0.0`、`non_security_filter_rate=1.0`、`experiment_convergence=1.0`、`poc_stability=1.0`（脚本是哈希判定，稳定性指标仅真实工作台下有信息量） |
| 真实模型分类（Specialist/Critic/Scout 走真实 provider） | `scripts/run_platform_evaluation.py`（不带 `--fake-llm`，glm-5.3 本地网关） | 已验证（glm-5.3，2026-10-11；语义检测 2/4、误报 1/8、非安全过滤 0/1，runtime 类指标受哈希工作台结构性封顶） | `evaluation_data/reports/platform_eval_real_glm53_2026-10-11.json`（§5 补充） |
| 真实容器 ASan 实证（`runtime-confirmed` 的 D3 证据） | Docker clang-14/ASan 沙箱真实执行 PoC | 未验证（走真实环境验收，独立记录） | — |
| 真实仓库全链检测 | ResInsight 限定子集（UAF v2 全链） | 已验证（诚实 abstain，2026-09-12，见 §2） | `.superpowers/tmp/uaf-demo-outcome.json` |

## 2. ResInsight（油气仓库，已完成的运行记录）

### 2.1 UAF v2 全链真实检测（2026-09-12）

- 对象：ResInsight 限定小范围真实路径（用户授权）。
- 结果：5 个 TU（cvfDebugTimer / Timer / Assert / RenderQueue /
  ModelBasicTree）提取出 **11 条事实（8 allocation + 3 alias）**，
  另有 **10 类 coverage gap**；候选生成 **0 条**——ResInsight 的内存管理
  形态（ctor 分配/dtor 释放、智能指针、循环拆卸）全部在第一阶段支持
  范围之外，管线**诚实 abstain、零编造**。
- 结果工件：`.superpowers/tmp/uaf-demo-outcome.json`。
- 附带战果（真实产品问题，均已修复或入 backlog）：
  1. sidecar/主进程清单白名单漏 `.inl/.ipp/.tpp`（cvfObject.inl 缺失导致
     隔离快照内全部 TU 编译失败）——已修 `0ca7d13`（含指纹第 5 次刷新）；
  2. `_expectation_for` 多 TU 各持合法不同 context hash 时置空崩溃——
     已修 `756c985`（`FactBundleExpectation.allowed_context_hashes`
     集合语义）；
  3. AST 规模边界：真实头文件重的 C++ 单 TU `-ast-dump=json` 达
     100–407 MiB（产品上限 16 MiB），需按函数过滤的提取策略——backlog。
- **演示性放宽 2 处（逐条标注）**：提取脚本去掉 preprocessing-record
  旗标；AST 上限放宽至 512 MiB。其余全部生产代码（隔离快照/指纹核验/
  沙箱 clang/resolver/extractor/adapt/generate/prove/orchestrator）。

### 2.2 纯 Agent 真实仓库实战（2026-09-08，前序记录）

- 战斗集 v1：11 文件（390 KB）；v2：129 文件（1.86 MB，C-API 轴
  21/5063 天花板 + FileInterface 解析器轴 108）。
- v2 窗口化单步分析 40 个最高风险锚点函数：**40/40 零失败零发现**；
  **阳性对照通过**（同格式正确检出合成 UAF CWE-416，conf=1.0），
  证明"零发现"裁定真实。
- 人工复核唯一实质发现：`cvfString.cpp:1268` replaceArgs 无界内层扫描
  （CWE-125 隐患，尾段吞噬不变量当前保护）——建议上游加固。
- 盲区记录：跨函数传播（调用图增强）与 v1 检索 C-API 种子覆盖率为产品
  backlog，不冒充已验证能力。

## 3. 油气仓库 OPM 系（占位——待执行）

OPM 系仓库（如 opm-common / opm-simulators）的论文侧运行尚未执行。
执行清单（每步完成后在本节追加数据与证据路径）：

1. **导入**：仓库快照导入与清单核验（复用 `lima/repository_import.py`
   边界，记录导入清单 SHA-256）；
2. **指纹**：快照指纹（snapshot_hash）与 Build Context 解析状态记录；
3. **分诊**：静态分诊产出线索数、种子分布、coverage gap 清单；
4. **平台跑**：`run_platform_review` 全链（真实 provider 或 Fake 分档
   记录），记录每目标状态机终态、实验台账、预算与降级；
5. **档案**：eRST 式报告 + CVE 离线匹配 + git 影响挖掘
   （`lima/agent_report.py`），结果归档并回填本节表格：

| 步骤 | 状态 | 关键数字 | 证据路径 |
|---|---|---|---|
| 导入 | 未执行 | — | — |
| 指纹 | 未执行 | — | — |
| 分诊 | 未执行 | — | — |
| 平台跑 | 未执行 | — | — |
| 档案 | 未执行 | — | — |

## 4. OpenHarmony 实战扫描记录（2026-10-07 ~ 10-09）

与 §3 的双版本验证模式互补，本节为 master 快照实战扫描模式（真实 Sidecar +
真实 glm-5.3 全链，检测脚本 `.zcode/tmp/detect.py`，工作区
`D:\OpenHarmonyPilot\`）。接入差异（仓库导入/离线依赖/快照限额参数组）见
`deploy/competition/README.md` §4/§5。

| 战役 | 目标（语言） | 耗时/调用 | 产出 | 人工核验终局 |
|---|---|---|---|---|
| 首战 cJSON | third_party_cJSON master（C） | 72 s | 0 finding 0 误报 | 干净空手（facts 441 条、0 候选→发现回退→Scout 全否决） |
| 第二战 dsoftbus | communication_dsoftbus master（C） | 6180 s / 16 实验 | 2 semantic-supported + 1 弃权 | CWE-416@693 锁生命周期竞态：代码级成立、本容器运行时归因未达 D3，按奖励计划表单口径本地留档；CWE-125@853 人工判疑似误报关闭 |
| 第三战 avrcp | communication_bluetooth_service avrcp_ct_profile.cpp（C++，两轮） | 2602 s / 27 实验 | 1 semantic-supported | **运行时证据闭合**：CWE-476+CWE-416 复合（TOCTOU 空解引用 + 临时 shared_ptr 所有权剥离 UAF）；朴素判空补丁不可修（10 连发双对照），所有权修复 10/10 存活。证据 `.zcode/reports/bt-avrcp-cwe476-verification/`（含 VERIFICATION.md 与 4 份 ASan 日志）；报告草稿留档待处置 |
| 第四战 l2cap | l2cap_le.c C 栈（C，验收战四轮） | 1454 s / 13 实验 | 1 semantic-supported + 3 弃权 | CWE-416@1540：险模式真（回调-仍挂链-后释放）、当下不可达（唯一回调方 EATT 不重入）——潜伏型 API 契约脆弱性 |

战果驱动的平台修复（提交见 PR #266）：C++ 限定名行定位（`0cd5008`）、
专家契约字段上限预告（`749b980`）、桩链接策略与 Critic 所有权规则
（`233a841`）、master→Release/LTS 对齐复核工具（`dc27258`）。

诚实边界：master 扫描不等于受支持 Release/LTS 版本（对齐复核用
`scripts/check_finding_on_branches.py`）；"专家自主使用桩闭包"目前仅间接
证据（对比旧战役驱动全灭于编译关 vs 本轮 13/27 实验全部执行）；C++ TU 的
确定性 facts 层为 0（全靠 LLM 发现回退）。

## 5. 配对基准（`evaluation_data/platform_cases/`）

- 案例：6 组源码级 vulnerable/fixed 对（SHA-256 钉死于
  `tests/fixtures/platform_cases/`，换行归一口径）：
  `uaf-direct`、`null-deref-direct`、`overflow-direct`（direct）、
  `rebind-revisable`（两轮实验闭环）、`clean-function`（误报纪律）、
  `non-security-filter`（赛题备注 3 机制化）。
- 评测器：`scripts/run_platform_evaluation.py`（无标签：管线输入只有
  workspace + 事实 wire + 分诊线索，标签只在评测侧）。
- 指标（全部可由内嵌 records 重算，零分母输出 null + diagnostic）：
  检测率、误报率、非安全过滤率、实验收敛（≤2 轮）、PoC 稳定性
  （同 PoC 重复 3 次全触发）、LLM 调用/时延。
- 当前状态：**Fake 全绿**（2026-09-11，6 案例 12 revision）：
  检测率 1.0、误报率 0.0、非安全过滤 1.0、实验收敛 1.0、PoC 稳定性 1.0
  （脚本工作台哈希判定下按构造稳定，真实工作台下该指标才有信息量）。
- 有效性边界（评测报告内逐条携带）：合成与钉死对不等价于生产检测能力；
  真实 Clang 提取与真实容器 ASan 为独立验收；null 指标≠满分。


## 3. OpenHarmony pilot 双版本真实运行（2026-10-07）

**首条真实双版本闭环记录。** 案例为上游 libexpat CVE-2022-43680（CWE-416；OH
third_party_expat 同源，见 `evaluation_data/openharmony/README.md` 的 OH 构建不受
影响边界）。

- **基线**：LIMA commit `e81f6c09`（分支 `feat/openharmony-pilot-validation`，
  Task 1-6 全部落地后的工作树）。脆弱 `5ac714074d2639e0b8bb82aa73ef51c4f7498d29`
  / 修复 `56967f83d68d5fc750f9e66a9a76756c94c7c173`，快照
  `D:\OpenHarmonyPilot\expat-up-{vuln,fixed}`（完整克隆、LF 工作区、
  `_overlay/expat_config.h` 与根 compdb 钉扎）。
- **环境**：真实 Sidecar（`lima-cxx-analyzer:local`，AST 预算 128 MiB、扫描限额
  5000/512KiB/20MiB 宿主容器同值）；真实 provider glm-5.3（本地网关，
  `thinking:disabled`）。
- **命令**：`scripts/run_openharmony_validation.py --case
  evaluation_data/openharmony/pilot_case.json --repository-import-root
  <import root> --output output/openharmony/pilot --cxx-analyzer-url
  http://cxx-analyzer:8090 --timeout 300 --deadline-seconds 5400
  --parallelism 1 --dialogue-rounds 2`（容器内执行，退出码 2）。
- **结果**：整体 `failed`（检测侧）。vulnerable 全链 1087.6 s / 85 LLM 调用 /
  310,967 reply bytes：6 窗口发现 14 条线索、多个 semantic-supported 发现
  （CWE-125@3240、CWE-190@7309），无 runtime-confirmed 的 CWE-416 目标命中——
  按合同判 `vulnerable-no-matching-finding`，不修饰。fixed 全链 145.7 s / 9 调用 /
  178,623 bytes：0 finding（该侧 passed）。双侧快照覆盖 100%。
- **证据**：bundle `output/openharmony/pilot/`（10 文件，`SHA256SUMS.json` 宿主侧
  逐文件重算全通过；AEP 双侧、VEP×2、patch.diff、中文报告含 3+3 矩阵与真实性边界）。
- **状态表更新**：真实模型分类一行——Scout/Specialist/Critic/Discovery 全部在真实
  provider 上运行并保持诚实降级语义，记**已验证（glm-5.3，2026-10-07）**；真实容器
  ASan 实证一行——实验编译/运行真实发生于沙箱（多次 clang++-14+ASan 编译与执行），
  但自动链路未产出 runtime-confirmed 命中，记**已验证（运行）/runtime-confirmed
  待达成**；另记同环境手工触发驱动实证（脆弱版目标绑定 heap-use-after-free@
  xmlparse.c:7148、修复版干净退出，2026-10-04 探针）作为 D3 侧旁证。
- **已知边界**：发现层当前稳定产出"正确文件 + 正确 CWE 族 + 正确邻域"的
  semantic-supported（4603 一带多次独立命中），分配失败注入手法已由智能体从通用
  指引自学（v4-v5 实测），自动 runtime-confirmed 的最后一跃待模型迭代（claude
  限流冷却中，glm 持续可用）。


### 全量项目门禁记录（`scripts/lima.ps1 test`，2026-10-07）

容器面 2890 测试：2 失败 + 6 错误 + 37 跳过。**全部 8 个失败/错误均在
origin/main（`3045910`）同一容器的基线复跑中同样出现**，为既有测试镜像
（`lima-cxx-analyzer:test`，构建于旧提交）缺依赖所致，非本分支回归：

| 精确 test id | 既有原因 |
|---|---|
| `tests.test_cxx_analyzer.AnalyzerComposeSecurityTests.test_compose_passes_only_admin_configuration_and_shared_snapshot_limits` | 镜像缺 `yaml` |
| `tests.test_cxx_analyzer.AnalyzerComposeSecurityTests.test_cxx_analyzer_is_an_internal_non_root_read_only_sidecar` | 镜像缺 `yaml` |
| `tests.test_cxx_analyzer.SourceRuleTests.test_rules_tie_three_distinct_oob_shapes_to_known_object_bounds` | 镜像缺 `yaml` |
| `tests.test_cxx_analyzer.SourceRuleTests.test_release_rules_exclude_same_pointer_rebinding_controls` | 镜像缺 `yaml` |
| `unittest.loader._FailedTest.test_build_recipe` | 镜像缺 `yaml`（模块导入失败） |
| `unittest.loader._FailedTest.test_cxx_memory_evaluation` | 镜像缺 `yaml`（模块导入失败） |
| `tests.test_cxx_analyzer.SourceScanContainerTests.test_fixture_manifest_is_complete_and_semgrep_marks_only_candidates` | 镜像 semgrep fixture 既有失败 |

另两处运行期现象已定位并处置：`test_v4_baseline_manifest` 双数据集指纹失配为
Windows 工作区 CRLF 检出伪影（提交内容与 main 逐字节一致；LF 重检出后指纹全部
吻合，非代码回归）；`ReproContainerTests` 偶发 `asan-runtime-segv-retried` 为
`cxx_analyzer/repro.py` 文档声明的受限容器 ASan 渲染器噪声类（重试机制消化）。
本分支新增的 18 个 git 夹具测试在容器内因镜像无 git 干净跳过（宿主全绿）。

### §5 补充：真模型评测首跑（glm-5.3，2026-10-11）

状态表第 3 行落地。报告 `evaluation_data/reports/platform_eval_real_glm53_2026-10-11.json`
（已做密钥扫描，零泄漏）。**结构性口径**：脚本工作台按 canned 驱动精确哈希判
PoC，真模型在构造上不可达 runtime 状态——检测率/收敛/PoC 稳定性三项在本
评测器下对真模型结构性封顶（真容器 ASan 由独立验收线覆盖）。**有效测得**：

| 指标 | 真模型实测 | 解读 |
|---|---|---|
| 语义层检测 | 2/4（uaf/null-deref 各 1 finding；overflow 漏报；rebind 因模型伪造 target_id 被 fail-closed 拒绝） | 顶层 detection_rate=0.0 系期望状态锚定 runtime 所致，语义层才是本评测器下真实能力读数 |
| 误报率 | 1/8（clean 案例 4/4 全零 ✓；FP=非安全案例 fixed 侧） | 误报纪律 7/8 |
| 非安全过滤 | 0/1 | **真实缺口**：FP 为 CWE-190（词表内）——词表封闭性挡不住算术代码上的溢出假设，过滤需内存安全影响证明（backlog） |
| 总耗时 | 180 s / 12 revision | — |

### §5 补充 2：检测率指标的真模型口径（backlog）

`run_platform_evaluation.py` 的 detection_rate 以案例期望终态（runtime 锚定）
为分母，真模型模式下结构性为 0。已立项：增加语义层级补充指标
（vulnerable 侧产出任意正向状态 finding 的比例），Fake/真模型两模式同口径可算。

### §5 补充 3：误报与非安全过滤判据（V03 冻结，2026-10-14）

真模型评测 FP 1/8、非安全过滤 0/1（§5 补充）之后的判据正式化；统计接线
归 C01（Issue #294），本节只冻结专业判定规则。

1. **误报判定（FP）**：非正期望修订（fixed/clean/非安全侧）产出任意
   Finding（`finding_count > 0`，与 C01 J1 同锚）计 1 例；分母 = 非正期望
   counted 修订数（当前冻结集 8）。**语义层与 runtime 层分开统计**：语义层
   在偏净代码上产出假设是已知特征（r3/r4 fixed 侧 1/3 个
   semantic-supported，pilot 合同按目标 cwe+path 判定故不误判）；只有
   **runtime-confirmed 出现在非正期望侧才是硬误报**（当前 0）。
2. **非安全案例期望**：全修订零 Finding。现行机制 = 假设合同的封闭内存
   安全 CWE 词表。实测缺口：唯一 FP 是 CWE-190（词表内）——词表封闭性
   挡不住纯算术代码上的溢出假设。
3. **CWE-190 立案边界（冻结）**：非安全案例上的整数溢出假设必须附带
   **内存安全影响证明**才可立案——溢出值可证明地进入内存操作（分配大小、
   数组索引、拷贝长度等）且攻击者可控输入可达；仅"溢出存在"不立案。
   操作化三分类：
   - 危险：溢出结果直接用作上述内存操作参数，可控输入可达；
   - 安全近邻：溢出仅进入算术/计数/日志用途，不触内存操作；
   - 不确定：路径存在但可控性/可达性未证明 → 按**安全**处理（不立案），
     计入"未定例"诊断计数，不入任何率。
   立案判定权在维护者；模型侧只允许按此规则过滤，不得自行放宽。
4. **指标口径**：`false_positive_rate` / `non_security_filter_rate` 维持
   既有定义与空分母 null 规则（C01 J4）；"未定例"为新增诊断计数，仅记录。

### §3 补充：runtime-confirmed 冲刺四连（2026-10-11，加固后平台重跑）

Task 7 之后平台经四轮实战加固（行定位×2、字段上限契约、桩链接策略、所有权
规则），以同一 expat 案例重冲 runtime-confirmed 自动命中：

| 轮 | 参数 | 终局 | 关键事实 |
|---|---|---|---|
| r2 | rounds=2 | inconclusive | Scout 引用不存在的 lead id（模型幻觉引用，fail-closed 正确拒绝） |
| r3 | rounds=2 | failed（no-matching） | 1494 s / 100 调用 / 16 线索，scout 轮数耗尽（预算剩 60）；3 个 semantic-supported 全落正确函数（doProlog:4603×2=CVE-2022-43680 本体、storeEntityValue:6073） |
| r4 | rounds=3 | failed（no-matching） | 1022 s / 71 调用；3 个 semantic-supported（doProlog:4603、2738、6806） |
| r5 | rounds=3，配方 v1 首战 | inconclusive（required-review 未满足） | 1141 s / 76 调用；3 finding 全钉 4603（CWE-416×2 + CWE-415）×8 轮 = 24 实验全清洁（driver sha 全在、零编译错）。当日重建 analyzer 丢失 AST 128 MB 预算 → ast-output-limit → xmlparse.c 必需审阅跳过 → fixed-not-run |
| r6 | rounds=3，AST 预算已修 | inconclusive（required-review 未满足） | 1928 s / 146 调用；8 finding（4603×4 + 2738/3240/5769/6806，全 CWE-416）×8 轮 = 64 实验全清洁。驱动已采用配方（`XML_ParserCreate_MM` + 计数分配器 + 单驱动内扫 N 0–400 + 内部子集 + 外部解析器创建 + 父解析器释放），但缺官方触发组合的三个要件：无外部 SYSTEM 子集与参数实体解析配置（handler 不触发）、编码名传 NULL（失败未定位到 parserInit 编码名复制）、失败后未复用父解析器。注：context==NULL 本身是共享父 DTD 的合法必经语义（2026-10-14 复核纠正，见 §3 补充 2 之 6），此前"空 context 脱离真实路径"的判读有误。配方 v2（PR #302，含纠错与机制探针） |
| r7 | rounds=3，配方 v2 首战 | inconclusive（required-review 未满足） | 903 s / 51 调用；**零 finding**——16 线索在 scout 评审层全部未升级（配方只进 Specialist 提示词、不影响 scout，判定为模型随机波动而非配方副作用；网关重启后抽查应答正常）。环境注记：发射前网关进程退出致一轮中止（`pilot-r7-aborted-env-down`，六窗拒连→AC5 provider-down=inconclusive 合同真实触发），网关恢复后重跑 |
| r8 | rounds=3 | inconclusive（fixed 侧线索封顶墙） | 2271 s / 58 调用；**vulnerable 侧首次达成正式判定 failed(no-matching)**（15 线索未触封顶、必需审阅完成——评审加固合同后首次）；3 semantic-supported（1249/3240/6806，**无一在 4603**）×8 轮 = 24 实验全清洁；fixed 侧 16 线索→封顶→unreviewed→inconclusive（案例级判定被 fixed 侧挡下）；一个发现窗遇上游 502/504 瞬断并被如实记录 |
| r9 | rounds=3 | inconclusive（provider 瞬断） | 642 s / 34 调用；上游 502/504 瞬断击中必需 LLM 的平台评审段 → `vulnerable-review-failed`（AC5 类合同正确触发）；网关两次掉线（进程退出）分别致 r7 前一轮与 r9 首发中止，后者复跑为本轮 |
| r10 | rounds=3，配额缩放工作树（`c6d01a5`=PR #303） | inconclusive | 1216 s / 76 调用；**3 finding 含 4603（配方 v2 时代首次锁定 CVE 本体位）**；18 线索留存（新配额生效）但模型发现 ≥19 仍触顶→unreviewed→fixed-not-run；8 轮实验全部 **compile 阶段失败**（8 个不同驱动 hash=盲改循环，`error_type=null` 未分类编译失败）。**手动抽验（决定性）**：最终 4603 驱动含完整 v2 组合（SYSTEM 子集+ALWAYS+handler 内 NULL context+"UTF-8"+失败后父解析器操作），仅一处签名笔误 `void inject_realloc`（应为 `void *`）；**修此一字即触发 heap-use-after-free（`XML_ParserFree → dtdDestroy → hashTableIterInit@xmlparse.c:7148`，与官方机制探针同归因）**，日志存维护者本地 |
| r11 | rounds=3，编译反馈环工作树（`5c252ce`=PR #304） | inconclusive（fixed 侧 discovery 窗 502/504 瞬断） | 1386 s / 42 调用；**反馈环生效实锤**：2 finding×8 轮全部 `error_type=compile-failed` 且 diagnostic（编译器 stderr）入台账并回喂 critic；模型**机械修复能力实证**（第 1 轮 `_MS` 拼写错→第 2 轮修掉→`_MM` 参数个数→再修掉）。**新墙=链接闭包**：平台仅链目标 TU，expat 的 xmltok/xmlrole 缺席（undefined reference to XmlGetUtf8InternalEncoding）；模型闭包思路两次正确、路径两次皆错（`source/expat/lib/xmltok.c`、`expat/lib/xmltok.c`——驱动在 build/ 编译，-I 只有 `-I_overlay -Iexpat/lib`，正确写法是裸名 `#include "xmltok.c"`）；第 7–8 轮又失 XMLCALL 调用约定。配方 v3（裸名兄弟源 + XMLCALL）已写为 PR #305 |
| r12 | rounds=3，叠栈工作树（#304+#305） | inconclusive（provider 瞬断） | 539 s / 31 调用；上游 502/504 瞬断再次击中必需评审段（当日第 4 次上游瞬断：r8 一窗、r9 整轮、r11 fixed 侧一窗、r12 整轮）；5 次稳定性抽查均 200 后立即重试 |
| r13 | rounds=3，同 r12 工作树 | inconclusive（案例级，见状态 5） | 873 s / 58 调用；**vulnerable 侧 4 finding 全部 runtime-confirmed——V02 自动闭环首次达成**。每个 finding 同构：第 1 轮编译失败（机械错，如未声明标识符）→ stderr 回喂 → **第 2 轮编译通过并直接触发 `heap-use-after-free`@`xmlparse.c:7148`（hashTableIterInit，与官方机制探针、r10 手动修复同归因点）**。终版驱动逐项落地配方：MM 计数套件 + ALWAYS + 外部实体 handler + UTF-8 + ParserReset + **裸名 `#include "xmltok.c"`/`"xmlrole.c"`（v3 一字不差）** + XMLCALL。案例级仍 inconclusive：18 线索留存仍触 ≥19 顶 → unreviewed → fixed-not-run（fixed 侧 3+3 干净对照未跑）。**报告口径（PR #302 审阅冻结）：对已知案例调优后的自动复现**——配方向量含该 CVE 触发条件，不得声称无偏检测能力 |
| r14 | rounds=3，配额二轮工作树（`41bef83`=PR #306） | inconclusive（fixed 侧被上游 502/504 瞬断击中评审段） | 1495 s / 61 调用；**r13 结果完整复现：vulnerable 侧 4/4 runtime-confirmed（连续第二轮，闭环稳定）**；配额 24 生效——vuln 18 线索完成审阅（unreviewed=[]），fixed 侧首次真正开跑且零 finding，但其评审段被当日第 5 次上游瞬断杀掉；另见 `ambiguous-matching-finding`——**多命中触发旧歧义守卫**（合同要求恰好一个匹配 finding），催生 PR #307 |
| r15 | rounds=3，叠栈工作树（#306+#307 `dc9665f`） | **failed（首个完整正式判定）** | 1532 s；**案例全流程首次跑完并落正式判定**：vuln 侧 **5/5 runtime-confirmed（连续第三轮）**；`multiple-matching-findings: 5 matches; replay uses the first` 新合同如设计生效；vulnerable 3+3 回放 **3/3 命中**（heap-use-after-free）；判 failed 于 **`fixed-matching-finding`**——同一宽扫描驱动（N 0..300）在 fixed 侧评审实验中也崩（扫描踩中修复版上与 CVE 无关的 OOM 路径），案例正确拒绝不具判别性的 PoC。诊断：官方测试用**固定 count=3**（钉单一分配序数），我们的配方教"扫 N"（探索用）；**判别性 PoC 需钉序数**（组合探针已验证序数 3≡第 4 次分配）——配方 v4 方向明确 |

**结论（诚实定级）**：runtime-confirmed 自动命中保持开放，但瓶颈已收窄定位——
**检测层瞄死靶心**（正确函数+正确 CWE，四轮一致），**实验层驱动转换是唯一
未闭合环节**（expat 该 UAF 的触发需要"计数分配器+外部实体+正确分配序号"的
多步组合，历史上手动战役 v5 的 21 个实验也只到 semantic-supported）。
附带信号：r3/r4 的 fixed 侧各产出 1/3 个 semantic-supported 假设（pilot 合同
按目标 cwe+path 判定故 passed）——与配对基准真模型 FP 1/8 的语义层信号一致，
语义层在偏净代码上会产假设是已知特征，runtime 层是收敛关键。
r3 排查顺带修复发现层两处盲区（顶行首裸名/宏别名，`1d65100`）。
bundle：容器 `/app/output/openharmony/pilot-r{2,3,4}`。

### §3 补充 2：配方战役 r5/r6（2026-10-14，CWE 键控配方层首战）

配方层（PR #301，`_SPECIALIST_CWE_RECIPES`）随 r5/r6 首战。诚实判读：

1. **检测层更强了**：r6 产 8 个 semantic-supported，其中 4 个钉 CVE 本体位
   4603；配方未让检测跑偏。
2. **实验层仍未闭合，但缺口已定位到组合步（2026-10-14 复核纠错版）**：
   r6 驱动执行了配方 90%（MM 套件/计数分配器/扫 N/内部子集/子解析器/
   父释放），漏的是官方回归测试
   （test_alloc_reset_after_external_entity_parser_create_fail）的三个要件：
   **外部 SYSTEM 子集 + `XML_PARAM_ENTITY_PARSING_ALWAYS`**（handler 才会
   触发）、**非空编码名 "UTF-8"**（把分配失败定位到 parserInit 的编码名
   复制）、**失败后 `XML_ParserReset` 复用父解析器**。勘误：早前判读
   "空 context 脱离真实路径"有误——`context==NULL` 恰是 `if (! context)
   newDtd = oldDtd;` 共享父 DTD 的合法必经语义，官方 handler 拒绝的是
   非 NULL context。配方 v2（PR #302，含纠错）与机制探针双对照已按正确
   组合落地（见第 6 条）；r7 待其合并后打。
3. **案例判定层出现新结构性墙**：r4 之后合入的评审第 5 轮 P2 加固规定
   线索封顶时被裁线索的 TU 记 unreviewed → 必需审阅（target_paths 全集）
   未满足 → 整局 inconclusive + fixed-not-run。glm-5.3 在 xmlparse.c
   （236 KB 单 TU）稳定发现 >16 线索，故本案例在此模型下恒 inconclusive。
   该合同是诚实记账（覆盖缺口不得读作干净），不是缺陷；但 PASSED 判定
   需要线索量下降或按 TU 尺寸调窗/线索配额——决策留维护者，本轮不改。
4. **环境教训（复跑必读）**：analyzer 容器重建必须带
   `LIMA_REPOSITORY_IMPORT_PATH=D:\OpenHarmonyPilot` 与
   `LIMA_CXX_MAX_AST_JSON_BYTES=134217728`（compose 默认 16 MB 会被
   xmlparse.c 的 78 MB AST 打穿）；LLM 网关已从 .env 的 8045（已停）迁到
   8046（zcode-proxy，glm-5.3 可用，均耗 ~15 s/调用，首轮偶发 3–6 分钟）；
   r5v1 曾被误判挂起而终止（urllib 长读 + 大提示词），后续轮用
   faulthandler 看门狗判活。
5. **V02 状态（r15：案例全流程贯通，判别性 PoC 是最后一环）**：
   r13–r15 **连续三轮 4–5 个 runtime-confirmed**（自动闭环稳定可复现）；
   r15 首次跑完案例全流程并落**正式判定 failed**（非 inconclusive）——
   多匹配确定性选首合同（PR #307）生效，vulnerable 3+3 回放 3/3 命中，
   案例正确拒绝在 fixed 侧也崩溃的宽扫描驱动。**下一环（配方 v4）**：
   教判别性 PoC 钉单一分配序数（官方 count=3 形态；组合探针已验证
   序数 3 ≡ 创建起第 4 次分配，fixed 全清洁），扫描仅用于探索。
   bundle：容器 `/app/output/openharmony/pilot-r{5..15}`。
   **报告口径（PR #302 审阅冻结）**：配方 v2 已写入已知 CVE 的触发
   条件，故 r7 及后续命中一律报告为**对已知案例调优后的自动复现**，
   不得声称无偏检测能力；配方向量含该 CVE 触发条件这一点必须在任何
   对外材料中保持可见；既有"不从单案例外推检测率"的纪律不变。
6. **组合机理探针双对照（2026-10-14，PR #302 附带）**：按官方用例
   复刻的探针（`tests/fixtures/expat_composition_probe/`，扫描序数替代
   固定 count=3），同驱动同配置在冻结对上运行（chain-probe，clang-14
   +ASan，XML_DTD=1 overlay 两侧逐字节一致）：**vulnerable `5ac71407`
   heap-use-after-free（触发序数 3，勘误见下）**，栈
   `XML_ParserReset → dtdReset → hashTableIterInit（xmlparse.c:7148）`，
   与 2026-10-04 手动实证同归因点；**fixed `56967f83` 全部 64 序数
   清洁**。此为探针机制验证（正负对照），不是平台 runtime-confirmed，
   也不是模型战役结果。勘误（2026-10-14 二轮复核）：触发序数为 **3**（日志实锄：序数
   1/2 创建失败但父重置存活，序数 3 触发；探针与官方 duff 分配器同为
   "允许 N 次后下一次失败"语义，故序数 3 ≡ 官方 allocation_count=3，
   失败点为创建起第 4 次分配=parserInit 编码名复制；此前"序数 2/第 3 次
   分配"的记录有误）。原始日志已随夹具入库供交叉核对。

### §3 补充 3：V06 avrcp 补丁双对照复跑（2026-10-14）

平台定级 semantic-supported → 不满足 #287 自动闭环前提，走手工双对照
（记录：`.zcode/reports/2026-10-14-v06-avrcp-patch-regression.md`，工件
`v06-rerun-2026-10-14/`）。全量重建三变体后同 PoC 同锤击：**原版 9/10
TU 归因崩溃；判空补丁 8/10 崩溃且 8/8 全为 heap-use-after-free**（帧钉
GetEventId ← ProcessVendorNotificationTimeout(patched:1499)，朴素补丁
不可修复更硬）；**所有权修复 0/10 崩溃 + 完整 soak 94 s rc=0
（checked=117812 全存活）**。与 10-07 基线同向。未验证项：正常业务功能
面回归、真机/模拟器（与报告草稿 §9 同口径）。
