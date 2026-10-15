# expat composition probe（CVE-2022-43680 谱系机制探针）

复刻官方上游回归测试 `test_alloc_reset_after_external_entity_parser_create_fail`
（随修复 `56967f83` 入库），把固定的 `allocation_count = 3` 改为**分配序数扫描**，
用于验证 CVE-2022-43680 谱系配方（`_SPECIALIST_CWE_RECIPES["CWE-416"]` 谱系 A
的组合步）描述的触发机理。

## 组合关系（与官方用例逐条对应）

| 要素 | 官方用例 | 探针 |
|---|---|---|
| 外部子集 | `<!DOCTYPE doc SYSTEM 'foo'><doc/>` | 同 |
| 参数实体解析 | `XML_SetParamEntityParsing(..., XML_PARAM_ENTITY_PARSING_ALWAYS)` | 同 |
| context 语义 | handler 拒绝非 NULL context（外部子集触发时 context == NULL） | 同；NULL context 即 `if (! context) newDtd = oldDtd;` 的共享父 DTD 路径 |
| 失败定位 | 非 NULL 编码名 `"UTF-8"`（注释 "needs something non-NULL"），`allocation_count=3` 允许 3 次分配后第 4 次——parserInit 的编码名复制——失败 | 同；扫描序数 N 的语义一致（允许 N 次后下一次失败），实测序数 3 触发（≡官方 count=3），序数 1/2 创建失败但父重置存活 |
| 失败后父操作 | `XML_ParserReset(g_parser, NULL)` | 同 |

**不要**把 NULL context 解读为"脱离真实路径"：NULL 恰是该案例共享 DTD 的合法
必经语义；脱离真实路径的是在 handler 流程之外调用子解析器创建。

## 运行（双对照）

```bash
# chain-probe 容器内（/repositories 有 expat-up-vuln / expat-up-fixed）：
bash /src/tests/fixtures/expat_composition_probe/run_dual_control.sh
```

预期：vulnerable（`5ac71407`）在某序数 ASan heap-use-after-free
（`XML_ParserReset → dtdReset → hashTableIterInit`）；fixed（`56967f83`）
全序数清洁。2026-10-14 实测结果见 `evidence-2026-10-14.json`。

判定不认"出现任意 ASan 报告"：`classify_probe_log.py` 要求 vulnerable 侧
报告**同时**满足 heap-use-after-free、归因到 `xmlparse.c` 帧、且在父解析器
重置路径（`XML_ParserReset` + `dtdReset`/`hashTableIterInit`）；fixed 侧
必须完整收尾且无任何 AddressSanitizer/LeakSanitizer 报告。无关 ASan 故障
（驱动内 SEGV、泄露报告、解析路径上的 UAF、无 xmlparse 归因的 UAF）一律
判 UNEXPECTED，脚本非零退出（`DUAL_CONTROL_FAILED`）。

普通 CI **不**运行本探针（需要 expat checkout 与 clang 容器）；单测只断言
探针组合与证据记录结构（见 `tests/test_expat_composition_probe.py`）。
