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
        self.assertEqual(2, vulnerable["trigger_ordinal"])
        self.assertIn("5ac71407", vulnerable["commit"])
        self.assertIn("clean", fixed["result"])
        self.assertIn("56967f83", fixed["commit"])

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
