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
| 失败定位 | 非 NULL 编码名 `"UTF-8"`（注释 "needs something non-NULL"），`allocation_count=3` 打在 parserInit 的编码名复制 | 同，`"UTF-8"` + 扫描序数（ordinal 2 ≡ 官方第 3 次分配） |
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

普通 CI **不**运行本探针（需要 expat checkout 与 clang 容器）；单测只断言
探针组合与证据记录结构（见 `tests/test_expat_composition_probe.py`）。
