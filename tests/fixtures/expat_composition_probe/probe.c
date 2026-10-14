/*
 * expat composition probe (CVE-2022-43680 lineage).
 *
 * Replicates the official upstream regression test
 * `test_alloc_reset_after_external_entity_parser_create_fail`
 * (expat/tests/runtests.c, committed with fix 56967f83) with one change:
 * instead of the test's fixed `allocation_count = 3`, the failing
 * ordinal is swept so the whole creation path is probed.
 *
 * Composition (each element mirrors the official test):
 *   1. DOCTYPE with an external SYSTEM subset: "<!DOCTYPE doc SYSTEM 'foo'><doc/>"
 *   2. XML_SetParamEntityParsing(XML_PARAM_ENTITY_PARSING_ALWAYS) so the
 *      external subset is fetched and the handler fires.
 *   3. The external-entity handler fires with context == NULL -- the legal
 *      shared-DTD semantics: with XML_DTD builds, a NULL context is exactly
 *      what makes the child share the parent DTD (xmlparse.c:
 *      `if (! context) newDtd = oldDtd;`).  A non-NULL context is rejected,
 *      exactly like the official handler.
 *   4. A NON-NULL encoding name ("UTF-8") steers the failing allocation to
 *      the encoding-name copy in parserInit, which runs after the DTD share
 *      is set.
 *   5. When the swept ordinal makes XML_ExternalEntityParserCreate fail
 *      partway, the half-built child frees the shared DTD (pre-fix).
 *   6. The parent is then REUSED: XML_ParserReset(g_parser, NULL), touching
 *      the freed DTD -- the heap-use-after-free the fix removes.
 *
 * Positive/negative dual control: compile the SAME driver with the SAME
 * config against the vulnerable (5ac71407) and fixed (56967f83) checkouts.
 * Expected: vulnerable crashes with an ASan report attributed to xmlparse
 * at some swept ordinal; fixed stays clean for every ordinal.
 * An ordinal where the creation succeeds simply means the failure landed
 * past the creation path; the sweep continues.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "expat.h"

static long g_target = -1;      /* swept ordinal; -1 = never fail */
static long g_allocs = 0;
static long g_sweep_ordinal = -1;

static void *probe_malloc(size_t n) {
  if (g_target >= 0 && ++g_allocs > g_target) return NULL;
  return malloc(n);
}

static void *probe_realloc(void *p, size_t n) {
  if (g_target >= 0 && ++g_allocs > g_target) return NULL;
  return realloc(p, n);
}

static void probe_free(void *p) { free(p); }

static int XMLCALL probe_ext_handler(XML_Parser parser,
                                     const XML_Char *context,
                                     const XML_Char *base,
                                     const XML_Char *systemId,
                                     const XML_Char *publicId) {
  (void)base; (void)systemId; (void)publicId;
  if (context != NULL) {
    /* Mirrors the official handler: "Unexpected non-NULL context". */
    fprintf(stderr, "unexpected non-NULL context\n");
    exit(90);
  }
  /* Non-NULL encoding name: the official test comments "needs something
   * non-NULL" so the failing allocation lands on
   * parser->m_protocolEncodingName = copyString(encodingName, ...) in
   * parserInit, after the shared-DTD assignment. */
  const XML_Char *const encoding_name = "UTF-8";
  g_allocs = 0;
  g_target = g_sweep_ordinal;
  const XML_Parser ext =
      XML_ExternalEntityParserCreate(parser, context, encoding_name);
  if (ext != NULL) {
    fprintf(stderr, "ordinal %ld: create succeeded (failure past path)\n",
            g_sweep_ordinal);
    XML_ParserFree(ext);
    g_target = -1;
    return XML_STATUS_ERROR;
  }
  fprintf(stderr, "ordinal %ld: create failed as designed\n",
          g_sweep_ordinal);
  g_target = -1;
  return XML_STATUS_ERROR;
}

int main(void) {
  const char *const doc = "<!DOCTYPE doc SYSTEM 'foo'><doc/>";
  const long max_ordinal = 64;

  for (long n = 1; n <= max_ordinal; n++) {
    fprintf(stderr, "sweep ordinal %ld\n", n);
    XML_Memory_Handling_Suite suite = {probe_malloc, probe_realloc, probe_free};
    XML_Parser parser = XML_ParserCreate_MM(NULL, &suite, NULL);
    if (parser == NULL) {
      fprintf(stderr, "parent create failed\n");
      return 92;
    }
    g_sweep_ordinal = n;
    g_target = -1; /* the parent parse itself must not fail */
    g_allocs = 0;

    XML_SetExternalEntityRefHandler(parser, probe_ext_handler);
    XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_ALWAYS);

    if (XML_Parse(parser, doc, (int)strlen(doc), XML_TRUE)
        != XML_STATUS_ERROR) {
      fprintf(stderr, "parse unexpectedly succeeded at ordinal %ld\n", n);
      return 93;
    }
    /* The parent reuse step: pre-fix this touches the freed shared DTD. */
    XML_ParserReset(parser, NULL);
    XML_ParserFree(parser);
    fprintf(stderr, "ordinal %ld survived reset+free\n", n);
  }
  printf("sweep done: %ld ordinals, no crash\n", max_ordinal);
  return 0;
}
