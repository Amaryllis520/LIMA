"""Expat composition probe consistency tests (CVE-2022-43680 lineage).

Review correction (PR #302): the recipe previously claimed a child parser
created with an empty context sits outside the real path.  The fixed
upstream source says the opposite -- ``if (! context) newDtd = oldDtd;``
is exactly the shared-DTD path, and the official regression handler
REJECTS a non-NULL context while passing a non-NULL encoding name.  These
tests pin the committed probe to that official relationship, and pin the
recorded dual-control evidence, so the mechanism description cannot drift
again.  They do NOT run the container build (no expat checkout or clang
assumption in CI); the mechanism run itself is recorded in the evidence
file and was executed on 2026-10-14 in the chain-probe container.
"""

import json
import unittest
from pathlib import Path

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "expat_composition_probe"


class ProbeCompositionTests(unittest.TestCase):
    """The probe source mirrors the official regression test exactly."""

    def setUp(self):
        self.probe = (_FIXTURE / "probe.c").read_text(encoding="utf-8")

    def test_external_subset_doc_and_param_entity_config(self):
        # Official: "<!DOCTYPE doc SYSTEM 'foo'><doc/>" +
        # XML_PARAM_ENTITY_PARSING_ALWAYS so the external subset loads.
        self.assertIn("<!DOCTYPE doc SYSTEM 'foo'><doc/>", self.probe)
        self.assertIn("XML_SetParamEntityParsing", self.probe)
        self.assertIn("XML_PARAM_ENTITY_PARSING_ALWAYS", self.probe)

    def test_null_context_is_the_shared_dtd_semantics(self):
        # Official handler rejects non-NULL context; NULL context is the
        # legal shared-DTD path (xmlparse.c: if (! context) newDtd =
        # oldDtd).  The probe must never claim otherwise.
        self.assertIn("context != NULL", self.probe)
        self.assertIn("unexpected non-NULL context", self.probe)
        self.assertIn("XML_ExternalEntityParserCreate(parser, context,",
                      self.probe)
        # No re-introduction of the wrong claim in the probe's comments.
        self.assertNotIn("empty context", self.probe)

    def test_non_null_encoding_name_steers_the_failing_allocation(self):
        # Official comment: "needs something non-NULL" so the failure
        # lands on the encoding-name copy in parserInit.
        self.assertIn('"UTF-8"', self.probe)
        self.assertIn("encoding_name", self.probe)

    def test_parent_reuse_after_failed_create(self):
        # Official: XML_ParserReset(g_parser, NULL) after the create
        # failure -- the step that touches the freed shared DTD.
        self.assertIn("XML_ParserReset(parser, NULL)", self.probe)

    def test_failure_is_swept_not_fixed(self):
        # The one deliberate divergence from the official test: the
        # failing ordinal is swept instead of pinned at 3.
        self.assertIn("g_sweep_ordinal", self.probe)
        self.assertIn("for (long n = 1; n <= max_ordinal; n++)", self.probe)


class EvidenceRecordTests(unittest.TestCase):
    """The dual-control evidence record is structured and honest."""

    def setUp(self):
        self.evidence = json.loads(
            (_FIXTURE / "evidence-2026-10-14.json").read_text(encoding="utf-8")
        )

    def test_dual_control_outcomes_recorded(self):
        vulnerable = self.evidence["vulnerable"]
        fixed = self.evidence["fixed"]
        self.assertIn("heap-use-after-free", vulnerable["result"])
        self.assertIn("hashTableIterInit", vulnerable["crash_site"])
        self.assertIn("XML_ParserReset", vulnerable["crash_site"])
        self.assertEqual(3, vulnerable["trigger_ordinal"])
        self.assertIn("5ac71407", vulnerable["commit"])
        self.assertIn("clean", fixed["result"])
        self.assertIn("56967f83", fixed["commit"])

    def test_ordinal_convention_matches_the_official_allocator(self):
        # Both conventions allow N allocations then fail the next one:
        # the official duff allocator with allocation_count=3 lets three
        # through and fails the fourth (the encoding-name copy in
        # parserInit, the site its comment names).  The probe's ordinal
        # must therefore equal the official count at the same site.
        convention = self.evidence["vulnerable"]["ordinal_convention"]
        self.assertIn("allows the first N allocations", convention)
        self.assertIn("allocation_count=3", convention)
        self.assertIn("FOURTH", convention)

    def test_evidence_logs_are_committed(self):
        for record in (self.evidence["vulnerable"], self.evidence["fixed"]):
            committed = Path(record["log"].split(" (committed;")[0])
            self.assertTrue(
                committed.is_file(),
                f"committed log missing: {committed}",
            )

    def test_official_reference_pins_the_corrected_semantics(self):
        reference = self.evidence["official_reference"]
        self.assertIn("rejects non-NULL context", reference["test"])
        self.assertIn("UTF-8", reference["test"])
        self.assertIn(
            "a NULL context is the shared-DTD semantics",
            reference["shared_dtd_path"],
        )

    def test_claim_scope_is_honest(self):
        # The evidence must not read as a platform runtime-confirmed
        # finding or a model-campaign outcome.
        self.assertIn("not a platform runtime-confirmed", self.evidence["what"])
        self.assertIn("does NOT re-run the container build",
                      self.evidence["honesty"])


class LogCrossCheckTests(unittest.TestCase):
    """The evidence numbers must match the actual saved run output.

    Review correction: an earlier record said ordinal 2 triggered the
    UAF; the log shows ordinals 1 and 2 surviving the reset and ordinal
    3 firing.  These tests re-derive the trigger ordinal from the
    committed log so the JSON can never drift from the raw evidence.
    """

    def setUp(self):
        self.evidence = json.loads(
            (_FIXTURE / "evidence-2026-10-14.json").read_text(encoding="utf-8")
        )
        self.vuln_log = (_FIXTURE / "evidence-2026-10-14.vuln.log").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        self.fixed_log = (_FIXTURE / "evidence-2026-10-14.fixed.log").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()

    def test_trigger_ordinal_derived_from_the_log(self):
        asan_lines = [
            i for i, line in enumerate(self.vuln_log)
            if "ERROR: AddressSanitizer" in line
        ]
        self.assertTrue(asan_lines, "vulnerable log has no ASan report")
        sweeps_before = [
            line for line in self.vuln_log[: asan_lines[0]]
            if line.startswith("sweep ordinal ")
        ]
        derived = int(sweeps_before[-1].rsplit(" ", 1)[1])
        self.assertEqual(
            self.evidence["vulnerable"]["trigger_ordinal"], derived,
            "evidence trigger_ordinal disagrees with the committed log",
        )

    def test_earlier_ordinals_survived_the_reset(self):
        trigger = self.evidence["vulnerable"]["trigger_ordinal"]
        survived = {
            int(line.split()[1])
            for line in self.vuln_log
            if line.endswith("survived reset+free")
        }
        self.assertEqual(set(range(1, trigger)), survived)

    def test_crash_signature_matches_the_record(self):
        joined = "\n".join(self.vuln_log)
        self.assertIn("heap-use-after-free", joined)
        self.assertIn("hashTableIterInit", joined)
        self.assertIn("xmlparse.c:7148", joined)
        self.assertIn("XML_ParserReset", joined)
        self.assertIn("dtdReset", joined)

    def test_fixed_log_is_clean_and_complete(self):
        joined = "\n".join(self.fixed_log)
        self.assertNotIn("AddressSanitizer", joined)
        self.assertIn("sweep done: 64 ordinals, no crash", joined)


class RunnerContractTests(unittest.TestCase):
    """The dual-control runner must fail closed on unexpected results."""

    def test_runner_exits_nonzero_when_the_control_does_not_hold(self):
        script = (_FIXTURE / "run_dual_control.sh").read_text(encoding="utf-8")
        self.assertIn("set -e", script)
        self.assertIn("DUAL_CONTROL_FAILED", script)
        self.assertIn('!= "asan-crash"', script)
        self.assertIn('!= "clean"', script)
        self.assertIn("exit 1", script)
        self.assertIn("exit 2", script)


class RecipeProbeConsistencyTests(unittest.TestCase):
    """The recipe text and the probe must tell the same story."""

    def test_recipe_matches_probe_composition(self):
        from lima.agent_orchestrator import _SPECIALIST_CWE_RECIPES

        recipe = _SPECIALIST_CWE_RECIPES["CWE-416"]
        probe = (_FIXTURE / "probe.c").read_text(encoding="utf-8")
        shared_pins = (
            "XML_PARAM_ENTITY_PARSING_ALWAYS",
            "XML_ExternalEntityParserCreate",
        )
        for pin in shared_pins:
            self.assertIn(pin, recipe)
            self.assertIn(pin, probe)
        # The corrected NULL-context semantics appear in both.
        self.assertIn("never dismiss a NULL context", recipe)
        self.assertIn("non-NULL context", probe)
        # The expat specifics stay scoped, not universal.
        self.assertIn("not universal necessary conditions", recipe)


if __name__ == "__main__":
    unittest.main()
