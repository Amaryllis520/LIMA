"""Static contract for the competition example; never import app configuration."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "deploy/competition/.env.competition.example"
README = ROOT / "deploy/competition/README.md"

# Explicit inventory: suffix -> unit. No environment loading or repository scan.
REQUIRED = {
    "REPOSITORY_IMPORT_ROOT": "路径",
    "REPOSITORY_IMPORT_PATH": "路径",
    "REPOSITORY_SCAN_SOURCES": "枚举",
    "REPOSITORY_SCAN_MAX_FILES": "文件数",
    "REPOSITORY_SCAN_MAX_FILE_BYTES": "字节",
    "REPOSITORY_SCAN_MAX_TOTAL_BYTES": "字节",
    "REPOSITORY_CACHE_ROOT": "路径",
    "REPOSITORY_CACHE_QUOTA_BYTES": "字节",
    "REPOSITORY_CACHE_MIN_FREE_BYTES": "字节",
    "CXX_MEMORY_MODE": "枚举",
    "CXX_ANALYZER_URL": "URL",
    "CXX_ANALYSIS_TIMEOUT_SECONDS": "秒",
    "CXX_MAX_RESPONSE_BYTES": "字节",
    "CXX_AGENT_MODE": "枚举",
    "CXX_AGENT_MODEL": "模型名",
    "CXX_AGENT_MAX_CALLS": "调用次数",
    "CXX_AGENT_MAX_OUTPUT_BYTES": "字节",
    "REPOSITORY_SCAN_LLM_MODE": "枚举",
    "REPOSITORY_INVESTIGATION_MODE": "枚举",
    "LLM_PROVIDER": "枚举",
    "LLM_BASE_URL": "URL",
    "LLM_API_KEY": "字符串（无单位）",
    "LLM_MODEL": "模型名",
    "CXX_AUTO_CMAKE": "布尔",
    "CXX_TRUSTED_BUILD_CONTEXT_GENERATION": "布尔",
    "CXX_MAX_MEMORY_MB": "MiB",
    "CXX_MAX_PROCESSES": "进程数",
    "CXX_MAX_AST_JSON_BYTES": "字节",
    "CXX_STEP_TIMEOUT_SECONDS": "秒",
    "CXX_TOTAL_TIMEOUT_SECONDS": "秒",
    "CXX_AGENT_REQUEST_PARAMS_JSON": "JSON 对象（无单位）",
}


class CompetitionEnvExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = EXAMPLE.read_text(encoding="utf-8").splitlines()
        cls.entries = []
        cls.comments = {}
        for index, raw in enumerate(cls.lines):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or not key.startswith("LIMA_"):
                raise AssertionError(f"Invalid example assignment at line {index + 1}")
            cls.entries.append((key, value))
            cls.comments[key] = cls.lines[index - 1] if index else ""
        cls.values = dict(cls.entries)

    def test_no_duplicate_keys(self):
        keys = [key for key, _ in self.entries]
        self.assertEqual(len(keys), len(set(keys)), "Duplicate environment key")

    def test_required_keys_have_unit_command_and_linkage_comments(self):
        self.assertEqual(set(self.values), {"LIMA_" + key for key in REQUIRED})
        for suffix, unit in REQUIRED.items():
            key = "LIMA_" + suffix
            with self.subTest(key=key):
                comment = self.comments[key]
                self.assertTrue(comment.startswith("# "))
                self.assertIn("单位：" + unit, comment)
                self.assertTrue(
                    any(command in comment for command in (
                        "命令：python ", "命令：docker compose ",
                    )),
                    comment,
                )
                self.assertIn("联动：", comment)

    def test_safe_defaults(self):
        safe = {
            "LIMA_LLM_PROVIDER": "local",
            "LIMA_LLM_API_KEY": "",
            "LIMA_LLM_BASE_URL": "",
            "LIMA_LLM_MODEL": "",
            "LIMA_CXX_AGENT_MODEL": "",
            "LIMA_CXX_AGENT_MODE": "off",
            "LIMA_CXX_MEMORY_MODE": "off",
            "LIMA_REPOSITORY_SCAN_LLM_MODE": "off",
            "LIMA_REPOSITORY_INVESTIGATION_MODE": "off",
            "LIMA_CXX_AUTO_CMAKE": "false",
            "LIMA_CXX_TRUSTED_BUILD_CONTEXT_GENERATION": "false",
        }
        for key, value in safe.items():
            with self.subTest(key=key):
                self.assertEqual(self.values[key], value)
        for key, value in self.entries:
            if key.endswith(("_API_KEY", "_PASSWORD", "_SECRET", "_TOKEN")):
                with self.subTest(secret=key):
                    self.assertEqual(value, "")

    def test_readme_example_references_exist(self):
        text = README.read_text(encoding="utf-8")
        references = {
            ".env.competition.example": EXAMPLE,
            "deploy/competition/.env.competition.example": EXAMPLE,
        }
        for reference, path in references.items():
            with self.subTest(reference=reference):
                self.assertIn(reference, text)
                self.assertTrue(path.is_file(), str(path))


if __name__ == "__main__":
    unittest.main()
