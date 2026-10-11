

"""PI-DR2/PI-DR6 REFERENCE IMPLEMENTATION -- temporary verification branch
pv/ip-0023-d2-freeze-pidr6 only. NOT the product implementation and never
to be merged; exists so the frozen IP-0023 acceptance suite can run green
on a Linux CI runner (precedent: pv/ip-0022-freeze-pidr6 run 34826215469).

PI-DR2 scratch reference implementation of the IP-0023 frozen contract.

Isolated scratch area (run-unique path, never committed). Implements the
Packet v5.1 frozen rules faithfully enough to prove the acceptance tests are
satisfiable (reference GREEN) and known-wrong outputs are rejected.

Reference-harness notes (no repository file is modified):
- W-1 (workspace admitted_files/metadata_files) is emulated via a
  RepositoryWorkspace subclass (isinstance checks keep passing).
- W-2 (_manifest_candidates union filtering) is emulated by wrapping the
  inventory module attribute in THIS process only; unrestricted workspaces
  keep the byte-identical old behaviour.
"""

from __future__ import annotations

import ast
import json
import math
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from lima.audit import inventory as _inventory_module
from lima.audit.inventory import (
    ProfileBudgets,
    ProfileBuildResult,
    ProfileInventoryOptions,
    build_repository_profile,
    is_secret_shaped_path,
)
from lima.audit.ram import (
    RamBudgets,
    RamFactsBuildResult,
    build_python_ram_facts,
    ram_facts_digest,
)
from lima.audit.ram_schema import ProfileCoverageGap, ram_wire_payload
from lima.audit.semantic_prioritizer import (
    SemanticOptions,
    SemanticTopNResult,
    build_semantic_top_n,
)
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.workspace import RepositoryWorkspace, WorkspaceInventory

COMPONENT_GRAPH_SCHEMA_VERSION = "2.0"
COMPONENT_GRAPH_SCHEMA_NAME = "lima.component-graph"
COMPONENT_GRAPH_SCHEMA_FILE = Path("schemas") / "v4" / "lima.component-graph.json"
COMPONENT_GRAPH_PROVENANCE_ANCHOR = "component-graph"
COMPONENT_EDGE_STATUS_RESOLVED = "resolved"
COMPONENT_EDGE_STATUS_AMBIGUOUS = "ambiguous"
COMPONENT_EDGE_STATUS_UNRESOLVED = "unresolved"
COMPONENT_EDGE_STATUSES = frozenset({"resolved", "ambiguous", "unresolved"})
COMPONENT_MANIFEST_KIND_PYPROJECT = "pyproject"
COMPONENT_MANIFEST_KIND_SETUP_PY = "setup_py"
COMPONENT_MANIFEST_KIND_SETUP_CFG = "setup_cfg"
COMPONENT_MANIFEST_KIND_REQUIREMENTS = "requirements"
COMPONENT_MANIFEST_KIND_ENVIRONMENT_YML = "environment_yml"
COMPONENT_MANIFEST_KIND_PACKAGE_JSON = "package_json"
COMPONENT_MANIFEST_KIND_GO_MOD = "go_mod"
COMPONENT_MANIFEST_KIND_CARGO_TOML = "cargo_toml"
COMPONENT_MANIFEST_KIND_POM_XML = "pom_xml"
UNBUILT_REASON_CAP_DIVERGENCE = "cap-divergence"
UNBUILT_REASON_VIEW_UNFORMABLE = "view-unformable"
UNBUILT_REASON_ADMISSION_REFUSED = "admission-refused"
UNBUILT_REASONS = frozenset(
    {"cap-divergence", "view-unformable", "admission-refused"}
)
COMPONENT_MANIFEST_SOURCE_INVENTORY = "source-inventory"
COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL = "metadata-channel"
COMPONENT_MANIFEST_SOURCES = frozenset({"source-inventory", "metadata-channel"})
MANIFEST_POLICY_METADATA_CHANNEL = "metadata-channel"
MANIFEST_POLICY_ADMITTED_ONLY = "admitted-only"
MANIFEST_POLICIES = frozenset({"metadata-channel", "admitted-only"})

_MANIFEST_EXACT_NAMES = {
    "Cargo.toml": COMPONENT_MANIFEST_KIND_CARGO_TOML,
    "environment.yml": COMPONENT_MANIFEST_KIND_ENVIRONMENT_YML,
    "go.mod": COMPONENT_MANIFEST_KIND_GO_MOD,
    "package.json": COMPONENT_MANIFEST_KIND_PACKAGE_JSON,
    "pom.xml": COMPONENT_MANIFEST_KIND_POM_XML,
    "pyproject.toml": COMPONENT_MANIFEST_KIND_PYPROJECT,
    "setup.cfg": COMPONENT_MANIFEST_KIND_SETUP_CFG,
    "setup.py": COMPONENT_MANIFEST_KIND_SETUP_PY,
}
_REQUIREMENTS_RE = re.compile(r"^requirements[^/]*\.txt$")
_T6_KEYS = (
    "file-limit",
    "total-size-limit",
    "file-size-limit",
    "binary",
    "non-utf8",
    "unreadable",
)
_T8_LOSS_KEYS = (
    "metadata-manifest-limit",
    "metadata-byte-limit",
    "unreadable",
    "non-utf8",
)
_STDLIB_TOP_LEVEL = frozenset(
    """
    abc argparse array ast asyncio atexit base64 binascii bisect builtins
    calendar cmath codecs collections concurrent configparser contextlib
    contextvars copy copyreg csv ctypes dataclasses datetime decimal difflib
    dis doctest email enum errno faulthandler fileinput fnmatch fractions
    ftplib functools gc getpass gettext glob gzip hashlib heapq hmac html
    http importlib inspect io ipaddress itertools json keyword linecache
    locale logging lzma marshal math mimetypes mmap multiprocessing numbers
    operator os pathlib pdb pickle platform plistlib poplib posixpath pprint
    profile pstats pty pwd py_compile pyclbr pydoc queue quopri random re
    readline reprlib resource runpy sched secrets select selectors shelve
    shlex shutil signal site smtplib socket sqlite3 ssl stat statistics
    string stringprep struct subprocess symtable sys sysconfig tarfile
    tempfile termios textwrap threading time timeit token tokenize traceback
    tracemalloc tty types typing unicodedata unittest urllib uuid venv
    warnings wave weakref webbrowser wsgiref xml xmlrpc zipfile zlib zonepath
    """.split()
)
_DEP_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+")
_SENTINEL = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------------------
# W-1 / W-2 equivalents (reference harness only)
# ---------------------------------------------------------------------------


class _RestrictedWorkspace(RepositoryWorkspace):
    """RepositoryWorkspace with the W-1 double-list restricted view."""

    def __init__(
        self,
        root: Any,
        *,
        max_files: int = 5_000,
        max_file_bytes: int = 512 * 1024,
        max_total_bytes: int = 20 * 1024 * 1024,
        extensions: Any = None,
        ignored_directories: Any = None,
        admitted_files: Any = None,
        metadata_files: Any = None,
    ) -> None:
        super().__init__(
            root,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            extensions=extensions,
            ignored_directories=ignored_directories,
        )
        self._admitted_files = (
            None if admitted_files is None else frozenset(admitted_files)
        )
        self._metadata_files = (
            None if metadata_files is None else frozenset(metadata_files)
        )

    @property
    def admitted_files(self) -> frozenset[str] | None:
        return self._admitted_files

    @property
    def metadata_files(self) -> frozenset[str] | None:
        return self._metadata_files

    def _read_set(self) -> frozenset[str] | None:
        union: set[str] = set()
        for value in (self._admitted_files, self._metadata_files):
            if value is not None:
                union |= value
        return frozenset(union) if union else None

    def inventory(self) -> WorkspaceInventory:
        unrestricted = super().inventory()
        if self._admitted_files is None:
            return unrestricted
        kept = [
            item for item in unrestricted.files if item.path in self._admitted_files
        ]
        result = WorkspaceInventory(root=unrestricted.root)
        result.files = kept
        result.discovered_files = len(kept)
        result.total_bytes = sum(item.size for item in kept)
        result.discovered_bytes = result.total_bytes
        return result

    def read_text(self, relative_path: Any) -> str:
        allowed = self._read_set()
        if (
            allowed is not None
            and str(relative_path).replace("\\", "/") not in allowed
        ):
            raise ValueError("workspace path escapes repository root")
        return super().read_text(relative_path)

    def absolute_file(self, relative_path: Any) -> Path:
        allowed = self._read_set()
        if (
            allowed is not None
            and str(relative_path).replace("\\", "/") not in allowed
        ):
            raise ValueError("workspace path escapes repository root")
        return super().absolute_file(relative_path)


_ORIGINAL_MANIFEST_CANDIDATES = _inventory_module._manifest_candidates


def _filtered_manifest_candidates(workspace: Any) -> list[str]:
    candidates = _ORIGINAL_MANIFEST_CANDIDATES(workspace)
    if not isinstance(workspace, _RestrictedWorkspace):
        return candidates
    allowed = workspace._read_set()  # noqa: SLF001 -- reference harness
    if allowed is None:
        return candidates
    return [item for item in candidates if item in allowed]


_inventory_module._manifest_candidates = _filtered_manifest_candidates


# ---------------------------------------------------------------------------
# Frozen dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ComponentManifestRef:
    path: str
    manifest_kind: str
    source: str


@dataclass(frozen=True)
class EdgeEvidence:
    path: str
    line: int
    imported_name: str


@dataclass(frozen=True)
class ComponentArtifactDigests:
    profile_content_digest: str
    ram_facts_digest: str
    semantic_result_digest: str


@dataclass(frozen=True)
class ComponentInfo:
    component_id: str
    root_dir: str
    manifests: tuple[ComponentManifestRef, ...]
    python_file_count: int
    is_empty: bool
    artifact_digests: ComponentArtifactDigests | None = None


@dataclass(frozen=True)
class ComponentScanSummary:
    component_id: str
    parse_error_file_count: int
    read_failure_file_count: int
    dynamic_import_site_count: int
    unknown_truncated_count: int
    manifest_parse_failure_count: int


@dataclass(frozen=True)
class UnknownImportRecord:
    source_component_id: str
    imported_name: str
    count: int


@dataclass(frozen=True)
class UnbuiltComponentRecord:
    component_id: str
    reason: str


@dataclass(frozen=True)
class ComponentEdge:
    source_component_id: str
    target_component_id: str | None
    status: str
    imported_name: str
    evidence: tuple[EdgeEvidence, ...]


@dataclass(frozen=True)
class ResourceMetering:
    main_inventory_read_attempts: int = 0
    component_rescan_read_attempts: int = 0
    profile_manifest_read_attempts: int = 0
    ast_read_attempts: int = 0
    metadata_channel_read_attempts: int = 0
    read_success_bytes: int = 0


@dataclass(frozen=True)
class ComponentGraph:
    components: tuple[ComponentInfo, ...]
    edges: tuple[ComponentEdge, ...]
    unassigned_files: tuple[str, ...]
    unassigned_file_count: int
    unknown_imports: tuple[UnknownImportRecord, ...]
    scan_summaries: tuple[ComponentScanSummary, ...]
    unbuilt_components: tuple[UnbuiltComponentRecord, ...]
    dependencies_complete: bool
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    manifests_discovered_count: int
    metadata_manifest_count: int
    collaboration_manifest_count: int
    overflow_manifest_count: int
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)


@dataclass(frozen=True)
class MonorepoBudgets:
    max_components: int = 16
    max_edges: int = 4_096
    max_edge_evidence: int = 64
    max_unassigned_files: int = 256
    max_total_model_calls: int = 8
    aggregate_max_prompt_tokens: int = 24_000
    aggregate_max_output_tokens: int = 4_096
    aggregate_max_total_tokens: int = 28_096
    max_metadata_manifests: int = 64
    max_metadata_total_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        domains = {
            "max_components": (1, 64),
            "max_edges": (1, 16_384),
            "max_edge_evidence": (1, 1_024),
            "max_unassigned_files": (1, 4_096),
            "max_total_model_calls": (1, 512),
            "aggregate_max_prompt_tokens": (1, 1_000_000),
            "aggregate_max_output_tokens": (1, 1_000_000),
            "aggregate_max_total_tokens": (1, 1_000_000),
            "max_metadata_manifests": (1, 1_024),
            "max_metadata_total_bytes": (1, 10**12),
        }
        for name, (low, high) in domains.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer in [{low}, {high}]")
        if (
            self.aggregate_max_total_tokens
            < self.aggregate_max_prompt_tokens + self.aggregate_max_output_tokens
        ):
            raise ValueError("aggregate total must be >= prompt + output")


@dataclass(frozen=True)
class ComponentDiscoveryResult:
    components: tuple[ComponentInfo, ...]
    unassigned_files: tuple[str, ...]
    unassigned_file_count: int
    metadata_manifest_count: int
    metadata_channel_skipped: Mapping[str, int]
    manifests_discovered_count: int
    collaboration_manifest_count: int
    overflow_manifest_count: int
    coverage_gaps: tuple[ProfileCoverageGap, ...]
    truncated: bool
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)


@dataclass(frozen=True)
class ComponentBuildResult:
    component: ComponentInfo
    profile_result: ProfileBuildResult
    ram_result: RamFactsBuildResult
    semantic_result: SemanticTopNResult
    ram_wire: Mapping[str, object]
    effective_profile_budgets: ProfileBudgets
    effective_ram_budgets: RamBudgets
    effective_semantic_options: SemanticOptions


@dataclass(frozen=True)
class MonorepoProfileBuildResult:
    discovery: ComponentDiscoveryResult
    per_component: tuple[ComponentBuildResult, ...]
    graph: ComponentGraph
    metering: ResourceMetering
    effective_budgets_payload: Mapping[str, int] = None  # type: ignore[assignment]
    provenance_anchor_ids: tuple[str, ...] = (COMPONENT_GRAPH_PROVENANCE_ANCHOR,)


__all__ = [
    "COMPONENT_EDGE_STATUSES",
    "COMPONENT_EDGE_STATUS_AMBIGUOUS",
    "COMPONENT_EDGE_STATUS_RESOLVED",
    "COMPONENT_EDGE_STATUS_UNRESOLVED",
    "COMPONENT_GRAPH_PROVENANCE_ANCHOR",
    "COMPONENT_GRAPH_SCHEMA_FILE",
    "COMPONENT_GRAPH_SCHEMA_NAME",
    "COMPONENT_GRAPH_SCHEMA_VERSION",
    "COMPONENT_MANIFEST_KIND_CARGO_TOML",
    "COMPONENT_MANIFEST_KIND_ENVIRONMENT_YML",
    "COMPONENT_MANIFEST_KIND_GO_MOD",
    "COMPONENT_MANIFEST_KIND_PACKAGE_JSON",
    "COMPONENT_MANIFEST_KIND_POM_XML",
    "COMPONENT_MANIFEST_KIND_PYPROJECT",
    "COMPONENT_MANIFEST_KIND_REQUIREMENTS",
    "COMPONENT_MANIFEST_KIND_SETUP_CFG",
    "COMPONENT_MANIFEST_KIND_SETUP_PY",
    "COMPONENT_MANIFEST_SOURCES",
    "COMPONENT_MANIFEST_SOURCE_INVENTORY",
    "COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL",
    "MANIFEST_POLICIES",
    "MANIFEST_POLICY_ADMITTED_ONLY",
    "MANIFEST_POLICY_METADATA_CHANNEL",
    "UNBUILT_REASONS",
    "UNBUILT_REASON_ADMISSION_REFUSED",
    "UNBUILT_REASON_CAP_DIVERGENCE",
    "UNBUILT_REASON_VIEW_UNFORMABLE",
    "ComponentArtifactDigests",
    "ComponentBuildResult",
    "ComponentDiscoveryResult",
    "ComponentEdge",
    "ComponentGraph",
    "ComponentInfo",
    "ComponentManifestRef",
    "ComponentScanSummary",
    "EdgeEvidence",
    "MonorepoBudgets",
    "MonorepoProfileBuildResult",
    "ResourceMetering",
    "UnbuiltComponentRecord",
    "UnknownImportRecord",
    "build_monorepo_profile",
    "component_graph_digest",
    "component_graph_payload",
    "detect_components",
    "load_component_graph_schema",
    "validate_component_graph_payload",
]


# ---------------------------------------------------------------------------
# Discovery internals
# ---------------------------------------------------------------------------


def _manifest_kind_for(name: str) -> str | None:
    if name in _MANIFEST_EXACT_NAMES:
        return _MANIFEST_EXACT_NAMES[name]
    if _REQUIREMENTS_RE.match(name):
        return COMPONENT_MANIFEST_KIND_REQUIREMENTS
    return None


def _iter_channel_candidates(workspace: RepositoryWorkspace) -> list[str]:
    """Sorted manifest-name matches visible to the S2 channel walk."""

    candidates: list[str] = []
    for current_root, directory_names, file_names in os.walk(
        workspace.root, topdown=True, followlinks=False
    ):
        kept: list[str] = []
        for name in sorted(directory_names):
            child = Path(current_root) / name
            rel_dir = child.relative_to(workspace.root).as_posix()
            if name in workspace.ignored_directories:
                continue
            if child.is_symlink():
                continue
            if is_secret_shaped_path(rel_dir) or is_secret_shaped_path(name):
                continue
            kept.append(name)
        directory_names[:] = kept
        for name in sorted(file_names):
            if _manifest_kind_for(name) is None:
                continue
            path = (Path(current_root) / name).relative_to(workspace.root).as_posix()
            if (Path(current_root) / name).is_symlink():
                continue
            if is_secret_shaped_path(path):
                continue
            candidates.append(path)
    return sorted(candidates)


def _channel_manifests(
    workspace: RepositoryWorkspace,
    budgets: MonorepoBudgets,
) -> tuple[dict[str, str], dict[str, int], dict[str, str], dict[str, int]]:
    """Enumerate + read the S2 channel; returns texts, skips, failures, prunes."""

    candidates = _iter_channel_candidates(workspace)
    texts: dict[str, str] = {}
    skipped: dict[str, int] = {}
    failures: dict[str, str] = {}
    prunes: dict[str, int] = {"ignored-directory": 0, "sensitive-filename": 0, "symlink": 0}
    for current_root, directory_names, _file_names in os.walk(
        workspace.root, topdown=True, followlinks=False
    ):
        for name in sorted(directory_names):
            child = Path(current_root) / name
            rel_dir = child.relative_to(workspace.root).as_posix()
            if name in workspace.ignored_directories:
                prunes["ignored-directory"] += 1
            elif child.is_symlink():
                prunes["symlink"] += 1
            elif is_secret_shaped_path(rel_dir) or is_secret_shaped_path(name):
                prunes["sensitive-filename"] += 1
    for path in candidates:
        if (Path(workspace.root) / path).is_symlink():
            prunes["symlink"] += 1
            continue
        if is_secret_shaped_path(path):
            prunes["sensitive-filename"] += 1
            continue
        if len(texts) >= budgets.max_metadata_manifests:
            skipped["metadata-manifest-limit"] = len(candidates) - len(texts) - sum(
                1 for item in failures
            )
            break
        try:
            text = workspace.read_text(path)
        except UnicodeDecodeError:
            failures[path] = "non-utf8"
            skipped["non-utf8"] = skipped.get("non-utf8", 0) + 1
            continue
        except (OSError, ValueError):
            failures[path] = "unreadable"
            skipped["unreadable"] = skipped.get("unreadable", 0) + 1
            continue
        size = len(text.encode("utf-8"))
        consumed = sum(len(value.encode("utf-8")) for value in texts.values())
        if consumed + size > budgets.max_metadata_total_bytes:
            overflow = consumed + size - budgets.max_metadata_total_bytes
            skipped["metadata-byte-limit"] = overflow
            break
        texts[path] = text
    skipped.update({key: value for key, value in prunes.items() if value})
    return texts, skipped, failures, prunes


def _is_collaboration_manifest(path: str, text: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return False
        uv = data.get("tool", {}).get("uv", {}).get("workspace", {})
        if isinstance(uv, dict) and uv.get("members"):
            return True
        if data.get("tool", {}).get("pdm", {}).get("workspace"):
            return True
        return "project" not in data
    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return False
        return bool(data.get("workspaces"))
    if name == "Cargo.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return False
        return "workspace" in data and "package" not in data
    return False


def _declared_dependency_names(path: str, text: str) -> set[str]:
    name = path.rsplit("/", 1)[-1]
    names: set[str] = set()
    if name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return names
        for item in data.get("project", {}).get("dependencies", []) or []:
            match = _DEP_NAME_RE.match(str(item))
            if match:
                names.add(match.group(0))
    elif _REQUIREMENTS_RE.match(name):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = _DEP_NAME_RE.match(line)
            if match:
                names.add(match.group(0))
    return names


def _anchor_of(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _component_id_for(anchor: str) -> str:
    return "component:." if anchor == "" else f"component:{anchor}"


def _internal_path(anchor: str, repo_path: str) -> str:
    if anchor == "":
        return repo_path
    return (
        repo_path[len(anchor) + 1 :]
        if repo_path.startswith(anchor + "/")
        else repo_path
    )


def _owner_anchor(path: str, anchors: list[str]) -> str | None:
    best: str | None = None
    best_depth = -1
    for anchor in anchors:
        if anchor == "":
            depth = 0
        elif path.startswith(anchor + "/"):
            depth = anchor.count("/") + 1
        else:
            continue
        if depth > best_depth:
            best, best_depth = anchor, depth
    return best


def _in_subtree(path: str, anchor: str) -> bool:
    if anchor == "":
        return True
    return path == anchor or path.startswith(anchor + "/")


@dataclass
class _DiscoveryOutcome:
    components: tuple[ComponentInfo, ...]
    unassigned_files: tuple[str, ...]
    unassigned_file_count: int
    metadata_manifest_count: int
    metadata_channel_skipped: dict[str, int]
    manifests_discovered_count: int
    collaboration_manifest_count: int
    overflow_manifest_count: int
    gaps: list[tuple[str, str]]
    truncated: bool
    manifest_texts: dict[str, str]
    channel_paths: set[str]
    main_truncated: bool
    main_skipped: dict[str, int]
    owned_py: dict[str, list[str]]


def _detect(
    workspace: RepositoryWorkspace,
    budgets: MonorepoBudgets,
    manifest_policy: str,
) -> _DiscoveryOutcome:
    if not isinstance(workspace, RepositoryWorkspace):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if manifest_policy not in MANIFEST_POLICIES:
        raise ValueError(f"unknown manifest policy: {manifest_policy}")
    main = workspace.inventory()
    admitted = {item.path for item in main.files}
    s1_manifests = {
        path
        for path in admitted
        if _manifest_kind_for(path.rsplit("/", 1)[-1]) is not None
    }
    channel_texts: dict[str, str] = {}
    channel_skipped: dict[str, int] = {}
    channel_failures: dict[str, str] = {}
    if manifest_policy == MANIFEST_POLICY_METADATA_CHANNEL:
        channel_texts, channel_skipped, channel_failures, _prunes = _channel_manifests(
            workspace, budgets
        )
    channel_paths = set(channel_texts) | set(channel_failures)
    discovered = sorted(s1_manifests | channel_paths)
    manifest_texts: dict[str, str] = dict(channel_texts)
    for path in discovered:
        if path in channel_failures:
            manifest_texts[path] = ""
        elif path not in manifest_texts:
            try:
                manifest_texts[path] = workspace.read_text(path)
            except (OSError, ValueError, UnicodeDecodeError):
                manifest_texts[path] = ""

    collaboration = 0
    admitted_anchors: list[str] = []
    per_anchor: dict[str, list[str]] = {}
    rejected_anchor_count = 0
    for path in discovered:
        anchor = _anchor_of(path)
        if _is_collaboration_manifest(path, manifest_texts.get(path, "")):
            collaboration += 1
            continue
        if anchor not in per_anchor:
            basename = path.rsplit("/", 1)[-1]
            probe = f"{anchor}/{basename}" if anchor else basename
            if is_secret_shaped_path(probe):
                rejected_anchor_count += 1
                continue
            admitted_anchors.append(anchor)
            per_anchor[anchor] = []
        per_anchor[anchor].append(path)

    anchors_sorted = sorted(admitted_anchors, key=_component_id_for)
    truncated = len(anchors_sorted) > budgets.max_components
    overflow_manifests: list[str] = []
    kept_anchors = anchors_sorted
    if truncated:
        for anchor in anchors_sorted[budgets.max_components :]:
            overflow_manifests.extend(per_anchor[anchor])
        kept_anchors = anchors_sorted[: budgets.max_components]

    components: list[ComponentInfo] = []
    for anchor in kept_anchors:
        refs = tuple(
            ComponentManifestRef(
                path=path,
                manifest_kind=str(_manifest_kind_for(path.rsplit("/", 1)[-1])),
                source=(
                    COMPONENT_MANIFEST_SOURCE_INVENTORY
                    if path in s1_manifests
                    else COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL
                ),
            )
            for path in sorted(per_anchor[anchor])
        )
        components.append(
            ComponentInfo(
                component_id=_component_id_for(anchor),
                root_dir=anchor,
                manifests=refs,
                python_file_count=0,
                is_empty=True,
            )
        )
    anchors = [component.root_dir for component in components]
    owned_py: dict[str, list[str]] = {component.root_dir: [] for component in components}
    unassigned: list[str] = []
    for path in sorted(admitted):
        if not path.endswith(".py"):
            continue
        owner = _owner_anchor(path, anchors)
        if owner is None:
            unassigned.append(path)
        else:
            owned_py[owner].append(path)
    unassigned_count = len(unassigned)
    unassigned_list = [
        path for path in unassigned if not is_secret_shaped_path(path)
    ]
    for component in components:
        count = len(owned_py[component.root_dir])
        object.__setattr__(component, "python_file_count", count)
        object.__setattr__(component, "is_empty", count == 0)

    gaps: list[tuple[str, str]] = []
    if rejected_anchor_count:
        gaps.append(
            (
                "INVENTORY_SKIPPED",
                "channel=source-inventory; reason=sensitive-filename; "
                f"count={rejected_anchor_count}",
            )
        )
    for key in _T6_KEYS:
        count = main.skipped.get(key, 0)
        if count:
            gaps.append(
                (
                    "INVENTORY_SKIPPED",
                    f"channel=source-inventory; reason={key}; count={count}",
                )
            )
    for key in _T8_LOSS_KEYS:
        count = channel_skipped.get(key, 0)
        if count:
            code = (
                "BUDGET_EXHAUSTED"
                if key in ("metadata-manifest-limit", "metadata-byte-limit")
                else "INVENTORY_SKIPPED"
            )
            gaps.append(
                (code, f"channel=metadata-channel; reason={key}; count={count}")
            )
    if truncated:
        gaps.append(
            (
                "BUDGET_EXHAUSTED",
                "reason=component-limit; "
                f"count={len(anchors_sorted) - budgets.max_components}",
            )
        )
    return _DiscoveryOutcome(
        components=tuple(components),
        unassigned_files=tuple(unassigned_list),
        unassigned_file_count=unassigned_count,
        metadata_manifest_count=len(channel_paths),
        metadata_channel_skipped=dict(sorted(channel_skipped.items())),
        manifests_discovered_count=len(discovered),
        collaboration_manifest_count=collaboration,
        overflow_manifest_count=len(overflow_manifests),
        gaps=gaps,
        truncated=truncated,
        manifest_texts=manifest_texts,
        channel_paths=channel_paths,
        main_truncated=main.truncated,
        main_skipped=dict(main.skipped),
        owned_py=owned_py,
    )


def _make_gap(code: str, detail: str) -> ProfileCoverageGap:
    return ProfileCoverageGap(gap_code=code, detail=detail)


def detect_components(
    workspace: RepositoryWorkspace,
    *,
    budgets: MonorepoBudgets | None = None,
    manifest_policy: str = MANIFEST_POLICY_METADATA_CHANNEL,
) -> ComponentDiscoveryResult:
    if not isinstance(workspace, RepositoryWorkspace):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if budgets is not None and not isinstance(budgets, MonorepoBudgets):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if manifest_policy not in MANIFEST_POLICIES:
        raise ValueError(f"unknown manifest policy: {manifest_policy}")
    outcome = _detect(
        workspace,
        budgets if budgets is not None else MonorepoBudgets(),
        manifest_policy,
    )
    return ComponentDiscoveryResult(
        components=outcome.components,
        unassigned_files=outcome.unassigned_files,
        unassigned_file_count=outcome.unassigned_file_count,
        metadata_manifest_count=outcome.metadata_manifest_count,
        metadata_channel_skipped=outcome.metadata_channel_skipped,
        manifests_discovered_count=outcome.manifests_discovered_count,
        collaboration_manifest_count=outcome.collaboration_manifest_count,
        overflow_manifest_count=outcome.overflow_manifest_count,
        coverage_gaps=tuple(_make_gap(*pair) for pair in sorted(set(outcome.gaps))),
        truncated=outcome.truncated,
    )


# ---------------------------------------------------------------------------
# Module roots / name table / edge resolution
# ---------------------------------------------------------------------------


def _module_roots(
    component: ComponentInfo,
    all_repo_files: set[str],
    manifest_texts: dict[str, str],
) -> list[str]:
    anchor = component.root_dir
    roots = [anchor]
    for ref in component.manifests:
        if not ref.path.endswith("pyproject.toml"):
            continue
        try:
            data = tomllib.loads(manifest_texts.get(ref.path, ""))
        except tomllib.TOMLDecodeError:
            continue
        setuptools = data.get("tool", {}).get("setuptools", {})
        values: list[str] = []
        where = setuptools.get("packages", {}).get("find", {}).get("where", [])
        values.extend([where] if isinstance(where, str) else where)
        for value in setuptools.get("package-dir", {}).values():
            values.extend([value] if isinstance(value, str) else value)
        for value in values:
            internal = str(value).strip("/")
            candidate = f"{anchor}/{internal}" if anchor else internal
            if candidate and candidate not in roots:
                roots.append(candidate)
    src = f"{anchor}/src" if anchor else "src"
    direct_py = any(
        path.startswith(src + "/")
        and path.endswith(".py")
        and path.count("/") == src.count("/") + 1
        for path in all_repo_files
    )
    direct_pkg = any(
        path.startswith(src + "/")
        and path.endswith("__init__.py")
        and path.count("/") == src.count("/") + 2
        for path in all_repo_files
    )
    if (direct_py or direct_pkg) and src not in roots:
        roots.append(src)
    return roots


def _build_name_table(
    components: tuple[ComponentInfo, ...],
    all_repo_files: set[str],
    manifest_texts: dict[str, str],
) -> dict[str, set[str]]:
    directories: set[str] = set()
    for path in all_repo_files:
        parts = path.split("/")
        for index in range(1, len(parts)):
            directories.add("/".join(parts[:index]))
    table: dict[str, set[str]] = {}
    for component in components:
        names: set[str] = set()
        for root in _module_roots(component, all_repo_files, manifest_texts):
            prefix = root + "/" if root else ""
            for path in all_repo_files:
                if not path.startswith(prefix):
                    continue
                rest = path[len(prefix) :]
                if "/" in rest:
                    continue
                if path.endswith(".py") and not path.endswith("__init__.py"):
                    names.add(rest[: -len(".py")])
            for directory in directories:
                if not directory.startswith(prefix):
                    continue
                rest = directory[len(prefix) :]
                if rest == "" or "/" in rest:
                    continue
                names.add(rest)
        table[component.component_id] = names
    return table


def _absolute(
    cid: str,
    top: str,
    line: int,
    path: str,
    own_names: set[str],
    name_table: dict[str, set[str]],
    declared: set[str],
    edges: dict[tuple[str, str, str, str], dict[str, Any]],
    unknowns: dict[tuple[str, str], dict[str, Any]],
) -> None:
    if top in own_names:
        return
    definers = {
        component_id for component_id, names in name_table.items() if top in names
    }
    if len(definers) == 1:
        key = (cid, "resolved", next(iter(definers)), top)
        edges.setdefault(
            key,
            {
                "source_component_id": cid,
                "target_component_id": next(iter(definers)),
                "status": "resolved",
                "imported_name": top,
                "evidence": [],
            },
        )["evidence"].append((path, line, top))
        return
    if len(definers) >= 2:
        key = (cid, "ambiguous", "", top)
        edges.setdefault(
            key,
            {
                "source_component_id": cid,
                "target_component_id": None,
                "status": "ambiguous",
                "imported_name": top,
                "evidence": [],
            },
        )["evidence"].append((path, line, top))
        return
    if top in _STDLIB_TOP_LEVEL or top in declared:
        return
    key = (cid, top)
    unknowns.setdefault(
        key, {"source_component_id": cid, "imported_name": top, "count": 0}
    )["count"] += 1


def _relative(
    cid: str,
    anchor: str,
    path: str,
    node: ast.ImportFrom,
    dotted: str,
    all_repo_files: set[str],
    components: tuple[ComponentInfo, ...],
    edges: dict[tuple[str, str, str, str], dict[str, Any]],
) -> None:
    def emit(target: str | None, status: str) -> None:
        key = (cid, status, target or "", dotted)
        edges.setdefault(
            key,
            {
                "source_component_id": cid,
                "target_component_id": target,
                "status": status,
                "imported_name": dotted,
                "evidence": [],
            },
        )["evidence"].append((path, node.lineno, dotted))

    file_dir = path.rsplit("/", 1)[0] if "/" in path else ""
    base_parts = file_dir.split("/") if file_dir else []
    up = node.level - 1
    if up > len(base_parts):
        emit(None, "unresolved")
        return
    module_parts = (node.module or "").split(".") if node.module else []
    target = "/".join(base_parts[: len(base_parts) - up] + module_parts)
    exists = (
        f"{target}.py" in all_repo_files or f"{target}/__init__.py" in all_repo_files
    )
    if not exists:
        emit(None, "unresolved")
        return
    if _in_subtree(target, anchor):
        return
    best: str | None = None
    for component in components:
        other = component.root_dir
        if other == anchor:
            continue
        if _in_subtree(target, other) and (
            best is None or other.count("/") > best.count("/")
        ):
            best = other
    if best is not None:
        target_id = _component_id_for(best)
        emit(target_id, "resolved")
        return
    if any(component.root_dir == "" for component in components):
        return
    emit(None, "unresolved")


def _scan_and_resolve(
    workspace: RepositoryWorkspace,
    owned_py: dict[str, list[str]],
    components: tuple[ComponentInfo, ...],
    name_table: dict[str, set[str]],
    manifest_texts: dict[str, str],
    all_repo_files: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, int]], int]:
    edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    unknowns: dict[tuple[str, str], dict[str, Any]] = {}
    summaries: dict[str, dict[str, int]] = {
        component.component_id: {
            "parse_error_file_count": 0,
            "read_failure_file_count": 0,
            "dynamic_import_site_count": 0,
            "unknown_truncated_count": 0,
            "manifest_parse_failure_count": 0,
        }
        for component in components
    }
    ast_reads = 0
    for component in sorted(components, key=lambda item: item.component_id):
        cid = component.component_id
        declared: set[str] = set()
        for ref in component.manifests:
            declared |= _declared_dependency_names(
                ref.path, manifest_texts.get(ref.path, "")
            )
            if ref.path.endswith(".toml") and manifest_texts.get(ref.path, ""):
                try:
                    tomllib.loads(manifest_texts[ref.path])
                except tomllib.TOMLDecodeError:
                    summaries[cid]["manifest_parse_failure_count"] += 1
        own_names = name_table.get(cid, set())
        for path in sorted(owned_py.get(component.root_dir, [])):
            ast_reads += 1
            try:
                text = workspace.read_text(path)
            except (OSError, ValueError, UnicodeDecodeError):
                summaries[cid]["read_failure_file_count"] += 1
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                summaries[cid]["parse_error_file_count"] += 1
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    callee = (
                        func.id
                        if isinstance(func, ast.Name)
                        else func.attr
                        if isinstance(func, ast.Attribute)
                        else ""
                    )
                    if callee in ("import_module", "__import__"):
                        summaries[cid]["dynamic_import_site_count"] += 1
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        _absolute(
                            cid,
                            alias.name.split(".")[0],
                            node.lineno,
                            path,
                            own_names,
                            name_table,
                            declared,
                            edges,
                            unknowns,
                        )
                elif isinstance(node, ast.ImportFrom):
                    dotted = "." * node.level + (node.module or "")
                    if node.level == 0 and node.module:
                        _absolute(
                            cid,
                            node.module.split(".")[0],
                            node.lineno,
                            path,
                            own_names,
                            name_table,
                            declared,
                            edges,
                            unknowns,
                        )
                    else:
                        _relative(
                            cid,
                            component.root_dir,
                            path,
                            node,
                            dotted,
                            all_repo_files,
                            components,
                            edges,
                        )
    edge_list = [
        edges[key]
        for key in sorted(edges, key=lambda key: (key[0], key[1], key[2], key[3]))
    ]
    unknown_list = [
        unknowns[key] for key in sorted(unknowns, key=lambda key: (key[0], key[1]))
    ]
    return edge_list, unknown_list, summaries, ast_reads


class _PoolBlocked(Exception):
    pass


class _PoolGuardClient:
    def __init__(self, inner: Any, pools: list[int]) -> None:
        self.inner = inner
        self.pools = pools
        self.calls = 0
        self.blocked = False

    def complete(self, prompt: str, *, timeout_seconds: int) -> str:
        prompt_est = math.ceil(len(prompt) / 4)
        output_est = 256
        if (
            self.pools[0] < prompt_est
            or self.pools[1] < output_est
            or self.pools[2] < prompt_est + output_est
        ):
            self.blocked = True
            raise _PoolBlocked()
        self.calls += 1
        self.pools[0] -= prompt_est
        self.pools[1] -= output_est
        self.pools[2] -= prompt_est + output_est
        return self.inner.complete(prompt, timeout_seconds=timeout_seconds)


# ---------------------------------------------------------------------------
# build_monorepo_profile
# ---------------------------------------------------------------------------


def build_monorepo_profile(
    workspace: RepositoryWorkspace,
    *,
    tenant_id: str,
    task_id: str,
    workflow_id: str,
    stage_attempt_id: str,
    artifact_id: str,
    repository_snapshot_digest: str,
    policy_digest: str = _SENTINEL,
    toolchain_digest: str = _SENTINEL,
    profile_options: ProfileInventoryOptions | None = None,
    ram_budgets: RamBudgets | None = None,
    semantic_options: SemanticOptions | None = None,
    monorepo_budgets: MonorepoBudgets | None = None,
    manifest_policy: str = MANIFEST_POLICY_METADATA_CHANNEL,
    model_client: Any = None,
) -> MonorepoProfileBuildResult:
    if not isinstance(workspace, RepositoryWorkspace):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    for identifier in (
        tenant_id,
        task_id,
        workflow_id,
        stage_attempt_id,
        artifact_id,
    ):
        if not isinstance(identifier, str):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if (
        not isinstance(repository_snapshot_digest, str)
        or not repository_snapshot_digest
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE)
    if monorepo_budgets is not None and not isinstance(
        monorepo_budgets, MonorepoBudgets
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)

    budgets = monorepo_budgets if monorepo_budgets is not None else MonorepoBudgets()
    outcome = _detect(workspace, budgets, manifest_policy)
    main = workspace.inventory()
    admitted = {item.path for item in main.files}
    anchors = [component.root_dir for component in outcome.components]
    owned_all: dict[str, list[str]] = {
        component.root_dir: [] for component in outcome.components
    }
    for path in sorted(admitted):
        owner = _owner_anchor(path, anchors)
        if owner is not None:
            owned_all[owner].append(path)
    all_repo_files = set(admitted) | set(outcome.channel_paths)
    name_table = _build_name_table(
        outcome.components, all_repo_files, outcome.manifest_texts
    )
    edge_records, unknown_records, summaries, ast_reads = _scan_and_resolve(
        workspace,
        outcome.owned_py,
        outcome.components,
        name_table,
        outcome.manifest_texts,
        all_repo_files,
    )

    gaps: list[tuple[str, str]] = list(outcome.gaps)
    for record in edge_records:
        evidence = sorted(set(record["evidence"]))
        if len(evidence) > budgets.max_edge_evidence:
            overflow = len(evidence) - budgets.max_edge_evidence
            gaps.append(
                ("BUDGET_EXHAUSTED", f"reason=edge-evidence-limit; count={overflow}")
            )
            evidence = evidence[: budgets.max_edge_evidence]
        record["evidence"] = evidence
    mixed = edge_records + unknown_records
    if len(mixed) > budgets.max_edges:
        kept = mixed[: budgets.max_edges]
        kept_edges = [item for item in kept if item in edge_records]
        kept_unknowns = [item for item in kept if item in unknown_records]
        dropped_edges = len(edge_records) - len(kept_edges)
        dropped_unknowns = [
            item for item in unknown_records if item not in kept_unknowns
        ]
        if dropped_edges:
            gaps.append(
                ("BUDGET_EXHAUSTED", f"reason=edge-limit; count={dropped_edges}")
            )
        if dropped_unknowns:
            gaps.append(
                (
                    "BUDGET_EXHAUSTED",
                    f"reason=unknown-import-limit; count={len(dropped_unknowns)}",
                )
            )
            for item in dropped_unknowns:
                summaries[item["source_component_id"]][
                    "unknown_truncated_count"
                ] += item["count"]
        edge_records, unknown_records = kept_edges, kept_unknowns
    unassigned_files = list(outcome.unassigned_files)
    unassigned_count = outcome.unassigned_file_count
    if len(unassigned_files) > budgets.max_unassigned_files:
        overflow = len(unassigned_files) - budgets.max_unassigned_files
        gaps.append(
            ("BUDGET_EXHAUSTED", f"reason=unassigned-file-limit; count={overflow}")
        )
        unassigned_files = unassigned_files[: budgets.max_unassigned_files]

    base_options = (
        semantic_options if semantic_options is not None else SemanticOptions()
    )
    caller_pools = [
        base_options.budgets.max_prompt_tokens_estimate,
        base_options.budgets.max_output_tokens_estimate,
        base_options.budgets.max_total_tokens_estimate,
    ]
    effective_pools = [
        min(value, caller_pools[index])
        for index, value in enumerate(
            (
                budgets.aggregate_max_prompt_tokens,
                budgets.aggregate_max_output_tokens,
                budgets.aggregate_max_total_tokens,
            )
        )
    ]
    model_active = model_client is not None and base_options.model_id != "unset"
    remaining_calls = budgets.max_total_model_calls
    call_degraded = 0
    pool_degraded = 0
    effective_profile = (
        profile_options.budgets if profile_options is not None else ProfileBudgets()
    )
    effective_ram = ram_budgets if ram_budgets is not None else RamBudgets()
    builds: list[ComponentBuildResult] = []
    unbuilt: list[UnbuiltComponentRecord] = []
    component_infos: list[ComponentInfo] = []
    rescan_attempts = 0
    manifest_read_attempts = 0
    for component in outcome.components:
        anchor = component.root_dir
        slice_internal = sorted(
            _internal_path(anchor, path) for path in owned_all[anchor]
        )
        metadata_internal = sorted(
            {_internal_path(anchor, ref.path) for ref in component.manifests}
        )
        try:
            component_ws = _RestrictedWorkspace(
                workspace.root if anchor == "" else workspace.root / anchor,
                max_files=workspace.max_files,
                max_file_bytes=workspace.max_file_bytes,
                max_total_bytes=workspace.max_total_bytes,
                extensions=workspace.extensions,
                ignored_directories=workspace.ignored_directories,
                admitted_files=slice_internal,
                metadata_files=metadata_internal,
            )
            precheck = component_ws.inventory()
            mapped = {
                f"{anchor}/{item.path}" if anchor else item.path
                for item in precheck.files
            }
            if mapped != set(owned_all[anchor]):
                unbuilt.append(
                    UnbuiltComponentRecord(
                        component_id=component.component_id,
                        reason=UNBUILT_REASON_CAP_DIVERGENCE,
                    )
                )
                component_infos.append(component)
                continue
        except (OSError, ValueError):
            unbuilt.append(
                UnbuiltComponentRecord(
                    component_id=component.component_id,
                    reason=UNBUILT_REASON_VIEW_UNFORMABLE,
                )
            )
            component_infos.append(component)
            continue
        rescan_attempts += 3 * len(slice_internal) + len(outcome.owned_py[anchor])
        manifest_read_attempts += len(metadata_internal)
        profile_result = build_repository_profile(
            component_ws,
            tenant_id=tenant_id,
            task_id=task_id,
            workflow_id=workflow_id,
            stage_attempt_id=stage_attempt_id,
            artifact_id=artifact_id,
            repository_snapshot_digest=repository_snapshot_digest,
            producer="lima.audit.component_graph",
            policy_digest=policy_digest,
            toolchain_digest=toolchain_digest,
            options=profile_options,
        )
        ram_result = build_python_ram_facts(component_ws, budgets=effective_ram)
        effective_options = base_options
        if model_active and remaining_calls > 0:
            stage_options = replace(
                base_options,
                budgets=replace(
                    base_options.budgets,
                    max_llm_calls=min(
                        base_options.budgets.max_llm_calls, remaining_calls
                    ),
                ),
            )
            guard = _PoolGuardClient(model_client, list(effective_pools))
            try:
                semantic_result = build_semantic_top_n(
                    ram_result.facts, options=stage_options, model_client=guard
                )
            except _PoolBlocked:
                semantic_result = build_semantic_top_n(
                    ram_result.facts, options=stage_options
                )
                pool_degraded += 1
            except Exception:
                semantic_result = build_semantic_top_n(
                    ram_result.facts, options=stage_options
                )
            remaining_calls -= guard.calls
            effective_options = stage_options
        elif model_active:
            semantic_result = build_semantic_top_n(
                ram_result.facts, options=base_options
            )
            call_degraded += 1
        else:
            semantic_result = build_semantic_top_n(
                ram_result.facts, options=base_options
            )
        ram_wire = ram_wire_payload(
            ram_result,
            semantic_result,
            profile_budgets=effective_profile,
            ram_budgets=effective_ram,
            semantic_options=effective_options,
        )
        digests = ComponentArtifactDigests(
            profile_content_digest=profile_result.envelope.content_digest,
            ram_facts_digest=ram_facts_digest(ram_result.facts),
            semantic_result_digest=semantic_result.result_digest,
        )
        built_info = replace(component, artifact_digests=digests)
        component_infos.append(built_info)
        builds.append(
            ComponentBuildResult(
                component=built_info,
                profile_result=profile_result,
                ram_result=ram_result,
                semantic_result=semantic_result,
                ram_wire=ram_wire,
                effective_profile_budgets=effective_profile,
                effective_ram_budgets=effective_ram,
                effective_semantic_options=effective_options,
            )
        )
    if call_degraded:
        gaps.append(
            (
                "BUDGET_EXHAUSTED",
                f"reason=aggregate-model-call-limit; count={call_degraded}",
            )
        )
    if pool_degraded:
        gaps.append(
            (
                "BUDGET_EXHAUSTED",
                f"reason=aggregate-token-pool-limit; count={pool_degraded}",
            )
        )

    t2 = any(
        gap.gap_code == "BUDGET_EXHAUSTED"
        and gap.detail.startswith("reason=python-file-limit")
        for build in builds
        for gap in build.ram_result.facts.coverage_gaps
    )
    t3 = any(
        code == "BUDGET_EXHAUSTED"
        and detail.startswith(
            ("reason=edge-limit", "reason=unknown-import-limit")
        )
        for code, detail in gaps
    )
    t4 = any(
        summary["parse_error_file_count"] > 0
        or summary["manifest_parse_failure_count"] > 0
        for summary in summaries.values()
    )
    t5 = any(
        summary["read_failure_file_count"] > 0 for summary in summaries.values()
    )
    t6 = outcome.main_truncated or any(
        outcome.main_skipped.get(key, 0) > 0 for key in _T6_KEYS
    )
    t7 = bool(unbuilt)
    t8 = any(
        outcome.metadata_channel_skipped.get(key, 0) > 0 for key in _T8_LOSS_KEYS
    )
    complete = not (outcome.truncated or t2 or t3 or t4 or t5 or t6 or t7 or t8)

    ordered_infos = sorted(component_infos, key=lambda item: item.component_id)
    scan_summaries = tuple(
        ComponentScanSummary(
            component_id=component.component_id,
            **{
                key: summaries[component.component_id][key]
                for key in (
                    "parse_error_file_count",
                    "read_failure_file_count",
                    "dynamic_import_site_count",
                    "unknown_truncated_count",
                    "manifest_parse_failure_count",
                )
            },
        )
        for component in ordered_infos
    )
    graph = ComponentGraph(
        components=tuple(ordered_infos),
        edges=tuple(
            ComponentEdge(
                source_component_id=record["source_component_id"],
                target_component_id=record["target_component_id"],
                status=record["status"],
                imported_name=record["imported_name"],
                evidence=tuple(
                    EdgeEvidence(path=item[0], line=item[1], imported_name=item[2])
                    for item in record["evidence"]
                ),
            )
            for record in edge_records
        ),
        unassigned_files=tuple(unassigned_files),
        unassigned_file_count=unassigned_count,
        unknown_imports=tuple(
            UnknownImportRecord(**record) for record in unknown_records
        ),
        scan_summaries=scan_summaries,
        unbuilt_components=tuple(unbuilt),
        dependencies_complete=complete,
        coverage_gaps=tuple(
            _make_gap(code, detail) for code, detail in sorted(set(gaps))
        ),
        manifests_discovered_count=outcome.manifests_discovered_count,
        metadata_manifest_count=outcome.metadata_manifest_count,
        collaboration_manifest_count=outcome.collaboration_manifest_count,
        overflow_manifest_count=outcome.overflow_manifest_count,
    )
    effective_budgets_payload: dict[str, int] = {
        "max_components": budgets.max_components,
        "max_edges": budgets.max_edges,
        "max_edge_evidence": budgets.max_edge_evidence,
        "max_unassigned_files": budgets.max_unassigned_files,
        "max_total_model_calls": budgets.max_total_model_calls,
        "aggregate_max_prompt_tokens": effective_pools[0],
        "aggregate_max_output_tokens": effective_pools[1],
        "aggregate_max_total_tokens": effective_pools[2],
        "max_metadata_manifests": budgets.max_metadata_manifests,
        "max_metadata_total_bytes": budgets.max_metadata_total_bytes,
    }
    discovery = ComponentDiscoveryResult(
        components=outcome.components,
        unassigned_files=tuple(unassigned_files),
        unassigned_file_count=unassigned_count,
        metadata_manifest_count=outcome.metadata_manifest_count,
        metadata_channel_skipped=outcome.metadata_channel_skipped,
        manifests_discovered_count=outcome.manifests_discovered_count,
        collaboration_manifest_count=outcome.collaboration_manifest_count,
        overflow_manifest_count=outcome.overflow_manifest_count,
        coverage_gaps=tuple(
            _make_gap(code, detail) for code, detail in sorted(set(outcome.gaps))
        ),
        truncated=outcome.truncated,
    )
    metering = ResourceMetering(
        main_inventory_read_attempts=main.discovered_files,
        component_rescan_read_attempts=rescan_attempts,
        profile_manifest_read_attempts=manifest_read_attempts,
        ast_read_attempts=ast_reads,
        metadata_channel_read_attempts=len(outcome.channel_paths),
        read_success_bytes=0,
    )
    return MonorepoProfileBuildResult(
        discovery=discovery,
        per_component=tuple(builds),
        graph=graph,
        metering=metering,
        effective_budgets_payload=effective_budgets_payload,
    )


# ---------------------------------------------------------------------------
# canonical projection / digest / payload
# ---------------------------------------------------------------------------


def canonical_dict_from_graph(graph: ComponentGraph) -> dict[str, Any]:
    return {
        "components": [
            {
                "component_id": item.component_id,
                "root_dir": item.root_dir,
                "manifests": [
                    {
                        "path": ref.path,
                        "kind": ref.manifest_kind,
                        "source": ref.source,
                    }
                    for ref in item.manifests
                ],
                "python_file_count": item.python_file_count,
                "is_empty": item.is_empty,
                "artifact_digests": (
                    None
                    if item.artifact_digests is None
                    else {
                        "profile_content_digest": item.artifact_digests.profile_content_digest,
                        "ram_facts_digest": item.artifact_digests.ram_facts_digest,
                        "semantic_result_digest": item.artifact_digests.semantic_result_digest,
                    }
                ),
            }
            for item in graph.components
        ],
        "edges": [
            {
                "source_component_id": edge.source_component_id,
                "target_component_id": edge.target_component_id,
                "status": edge.status,
                "imported_name": edge.imported_name,
                "evidence": [
                    {
                        "path": item.path,
                        "line": item.line,
                        "imported_name": item.imported_name,
                    }
                    for item in edge.evidence
                ],
            }
            for edge in graph.edges
        ],
        "unknown_imports": [
            {
                "source_component_id": item.source_component_id,
                "imported_name": item.imported_name,
                "count": item.count,
            }
            for item in graph.unknown_imports
        ],
        "scan_summaries": [
            {
                "component_id": item.component_id,
                "parse_error_file_count": item.parse_error_file_count,
                "read_failure_file_count": item.read_failure_file_count,
                "dynamic_import_site_count": item.dynamic_import_site_count,
                "unknown_truncated_count": item.unknown_truncated_count,
                "manifest_parse_failure_count": item.manifest_parse_failure_count,
            }
            for item in graph.scan_summaries
        ],
        "unbuilt_components": [
            {"component_id": item.component_id, "reason": item.reason}
            for item in graph.unbuilt_components
        ],
        "unassigned_files": list(graph.unassigned_files),
        "unassigned_file_count": graph.unassigned_file_count,
        "dependencies_complete": graph.dependencies_complete,
        "coverage_gaps": [
            {"gap_code": gap.gap_code, "detail": gap.detail}
            for gap in graph.coverage_gaps
        ],
        "manifests_discovered_count": graph.manifests_discovered_count,
        "metadata_manifest_count": graph.metadata_manifest_count,
        "collaboration_manifest_count": graph.collaboration_manifest_count,
        "overflow_manifest_count": graph.overflow_manifest_count,
    }


def component_graph_digest(graph: ComponentGraph) -> str:
    return compute_content_digest(canonical_dict_from_graph(graph))


def component_graph_payload(result: MonorepoProfileBuildResult) -> dict[str, Any]:
    graph = result.graph
    builds_by_id = {b.component.component_id: b for b in result.per_component}
    components = []
    for info in graph.components:
        build = builds_by_id.get(info.component_id)
        summary = next(
            item for item in graph.scan_summaries
            if item.component_id == info.component_id
        )
        components.append(
            {
                "component_id": info.component_id,
                "root_dir": info.root_dir,
                "manifests": [
                    {
                        "path": ref.path,
                        "manifest_kind": ref.manifest_kind,
                        "source": ref.source,
                    }
                    for ref in info.manifests
                ],
                "python_file_count": info.python_file_count,
                "is_empty": info.is_empty,
                "built": build is not None,
                "digests": (
                    None
                    if info.artifact_digests is None
                    else {
                        "profile_content_digest": info.artifact_digests.profile_content_digest,
                        "ram_facts_digest": info.artifact_digests.ram_facts_digest,
                        "semantic_result_digest": info.artifact_digests.semantic_result_digest,
                    }
                ),
                "scan_summary": {
                    "parse_error_file_count": summary.parse_error_file_count,
                    "read_failure_file_count": summary.read_failure_file_count,
                    "dynamic_import_site_count": summary.dynamic_import_site_count,
                    "unknown_truncated_count": summary.unknown_truncated_count,
                    "manifest_parse_failure_count": summary.manifest_parse_failure_count,
                },
                "semantic_topn": (
                    None
                    if build is None
                    else {
                        "model_id": build.effective_semantic_options.model_id,
                        "top_n": build.effective_semantic_options.top_n,
                        "ranked_candidate_ids": [
                            item.candidate_id
                            for item in build.semantic_result.ranked
                        ],
                    }
                ),
            }
        )
    return {
        "schema_version": COMPONENT_GRAPH_SCHEMA_VERSION,
        "model_kind": COMPONENT_GRAPH_SCHEMA_NAME,
        "components": components,
        "edges": [
            {
                "source_component_id": edge.source_component_id,
                "target_component_id": edge.target_component_id,
                "status": edge.status,
                "imported_name": edge.imported_name,
                "evidence": [
                    {
                        "path": item.path,
                        "line": item.line,
                        "imported_name": item.imported_name,
                    }
                    for item in edge.evidence
                ],
            }
            for edge in graph.edges
        ],
        "unknown_imports": [
            {
                "source_component_id": item.source_component_id,
                "imported_name": item.imported_name,
                "count": item.count,
            }
            for item in graph.unknown_imports
        ],
        "unassigned_files": list(graph.unassigned_files),
        "unassigned_file_count": graph.unassigned_file_count,
        "scan_summaries": [
            {
                "component_id": item.component_id,
                "parse_error_file_count": item.parse_error_file_count,
                "read_failure_file_count": item.read_failure_file_count,
                "dynamic_import_site_count": item.dynamic_import_site_count,
                "unknown_truncated_count": item.unknown_truncated_count,
                "manifest_parse_failure_count": item.manifest_parse_failure_count,
            }
            for item in graph.scan_summaries
        ],
        "unbuilt_components": [
            {"component_id": item.component_id, "reason": item.reason}
            for item in graph.unbuilt_components
        ],
        "dependencies_complete": graph.dependencies_complete,
        "coverage_gaps": [
            {"gap_code": gap.gap_code, "detail": gap.detail}
            for gap in graph.coverage_gaps
        ],
        "metadata_manifest_count": graph.metadata_manifest_count,
        "metadata_channel_skipped": dict(result.discovery.metadata_channel_skipped),
        "manifests_discovered_count": graph.manifests_discovered_count,
        "collaboration_manifest_count": graph.collaboration_manifest_count,
        "overflow_manifest_count": graph.overflow_manifest_count,
        "build": {
            "monorepo_budgets": dict(result.effective_budgets_payload)
        },
        "identity": {"component_graph_digest": component_graph_digest(graph)},
        "provenance": {
            "provenance_anchor_ids": [COMPONENT_GRAPH_PROVENANCE_ANCHOR]
        },
    }


def load_component_graph_schema() -> dict[str, Any]:
    schema_path = Path(__file__).resolve().parents[2] / COMPONENT_GRAPH_SCHEMA_FILE
    return json.loads(schema_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# validator (V1-V10)
# ---------------------------------------------------------------------------

_TOP_KEYS = {
    "schema_version",
    "model_kind",
    "components",
    "edges",
    "unknown_imports",
    "unassigned_files",
    "unassigned_file_count",
    "scan_summaries",
    "unbuilt_components",
    "dependencies_complete",
    "coverage_gaps",
    "metadata_manifest_count",
    "metadata_channel_skipped",
    "manifests_discovered_count",
    "collaboration_manifest_count",
    "overflow_manifest_count",
    "build",
    "identity",
    "provenance",
}
_ENTRY_KEYS = {
    "component_id",
    "root_dir",
    "manifests",
    "python_file_count",
    "is_empty",
    "built",
    "digests",
    "scan_summary",
    "semantic_topn",
}
_MANIFEST_KEYS = {"path", "manifest_kind", "source"}
_KINDS = frozenset(_MANIFEST_EXACT_NAMES.values()) | {
    COMPONENT_MANIFEST_KIND_REQUIREMENTS
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PATH_OK = re.compile(r"^[^/]+(/[^/]+)*$")
_SEGMENT_OK = re.compile(r"^[A-Za-z0-9._\-]+$")


def _fail(message: str) -> None:
    raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, message)


def _check_path(value: object, *, charset: bool = False) -> None:
    if not isinstance(value, str) or not value:
        _fail("path must be a non-empty string")
    if value == ".":
        return
    if "\x00" in value or value.startswith("/") or value.endswith("/"):
        _fail(f"invalid path shape: {value!r}")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail(f"invalid path segment: {value!r}")
    if charset:
        if value != "." and not all(
            _SEGMENT_OK.match(part) for part in value.split("/")
        ):
            _fail(f"charset violation: {value!r}")
    if is_secret_shaped_path(value):
        _fail(f"secret-shaped path on a public surface: {value!r}")


def validate_component_graph_payload(payload: Mapping[str, object]) -> None:
    if not isinstance(payload, Mapping):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    extra = set(payload) - _TOP_KEYS
    if extra:
        raise ContractError(ContractErrorCode.UNKNOWN_FIELD, f"$.{sorted(extra)[0]}")
    if payload.get("schema_version") != "2.0":
        _fail("schema_version")
    if payload.get("model_kind") != "lima.component-graph":
        _fail("model_kind")
    if payload.get("provenance") != {"provenance_anchor_ids": ["component-graph"]}:
        _fail("provenance")

    components = payload.get("components")
    if not isinstance(components, list):
        _fail("components")
    ids: list[str] = []
    published = 0
    published_meta = 0
    for entry in components:
        if not isinstance(entry, Mapping):
            _fail("component entry")
        extra = set(entry) - _ENTRY_KEYS
        if extra:
            raise ContractError(
                ContractErrorCode.UNKNOWN_FIELD, f"$.components.{sorted(extra)[0]}"
            )
        cid = entry.get("component_id")
        if not isinstance(cid, str) or not cid.startswith("component:"):
            _fail("component_id")
        segment = cid[len("component:") :]
        _check_path(segment if segment != "." else ".", charset=True)
        root_dir = entry.get("root_dir")
        if not isinstance(root_dir, str):
            _fail("root_dir")
        if root_dir:
            _check_path(root_dir, charset=True)
        ids.append(cid)
        count = entry.get("python_file_count")
        if type(count) is not int or count < 0:
            _fail("python_file_count")
        if entry.get("is_empty") is not (count == 0):
            _fail("is_empty mismatch")
        manifests = entry.get("manifests")
        if not isinstance(manifests, list):
            _fail("manifests")
        paths = [ref.get("path") for ref in manifests]
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            _fail("manifests order/duplicates")
        for ref in manifests:
            if set(ref) != _MANIFEST_KEYS:
                raise ContractError(ContractErrorCode.UNKNOWN_FIELD, "manifest keys")
            _check_path(ref["path"])
            if ref["manifest_kind"] not in _KINDS:
                _fail("manifest_kind")
            if ref["source"] not in COMPONENT_MANIFEST_SOURCES:
                _fail("manifest source")
            published += 1
            if ref["source"] == COMPONENT_MANIFEST_SOURCE_METADATA_CHANNEL:
                published_meta += 1
        built = entry.get("built")
        digests = entry.get("digests")
        if not isinstance(built, bool):
            _fail("built")
        if (digests is not None) != built:
            _fail("digests/built mismatch")
        if digests is not None:
            if set(digests) != {
                "profile_content_digest",
                "ram_facts_digest",
                "semantic_result_digest",
            }:
                _fail("digest keys")
            for value in digests.values():
                if not isinstance(value, str) or not _HEX64.match(value):
                    _fail("digest format")
        scan = entry.get("scan_summary")
        for key in (
            "parse_error_file_count",
            "read_failure_file_count",
            "dynamic_import_site_count",
            "unknown_truncated_count",
            "manifest_parse_failure_count",
        ):
            if type(scan.get(key)) is not int or scan[key] < 0:
                _fail(f"scan_summary.{key}")
        topn = entry.get("semantic_topn")
        if built and (not isinstance(topn, Mapping)):
            _fail("semantic_topn")
        if isinstance(topn, Mapping):
            if set(topn) != {"model_id", "top_n", "ranked_candidate_ids"}:
                _fail("semantic_topn keys")
            top_n = topn.get("top_n")
            if type(top_n) is not int or not 1 <= top_n <= 100:
                _fail("top_n")
            ranked = topn.get("ranked_candidate_ids")
            if not isinstance(ranked, list) or len(ranked) > top_n or len(ranked) > 100:
                _fail("ranked_candidate_ids")
            for item in ranked:
                if not isinstance(item, str):
                    _fail("candidate_id")
    if len(set(ids)) != len(ids):
        _fail("duplicate component_id")
    if ids != sorted(ids):
        _fail("components order")

    edges = payload.get("edges")
    if not isinstance(edges, list):
        _fail("edges")
    edge_keys: list[tuple] = []
    for edge in edges:
        if not isinstance(edge, Mapping):
            _fail("edge")
        if set(edge) != {
            "source_component_id",
            "target_component_id",
            "status",
            "imported_name",
            "evidence",
        }:
            _fail("edge keys")
        source = edge["source_component_id"]
        target = edge["target_component_id"]
        status = edge["status"]
        if status not in COMPONENT_EDGE_STATUSES:
            _fail("edge status")
        if source not in ids:
            _fail("edge source")
        if status == "resolved":
            if target not in ids or target == source:
                _fail("edge target")
        elif target is not None:
            _fail("edge target must be null")
        evidence = edge["evidence"]
        if not isinstance(evidence, list):
            _fail("evidence")
        tuples = []
        for item in evidence:
            if set(item) != {"path", "line", "imported_name"}:
                _fail("evidence keys")
            _check_path(item["path"])
            if type(item["line"]) is not int or item["line"] < 1:
                _fail("evidence line")
            tuples.append(
                (item["path"], item["line"], item["imported_name"])
            )
        if tuples != sorted(tuples):
            _fail("evidence order")
        edge_keys.append((source, status, target or "", edge["imported_name"]))
    if len(set(edge_keys)) != len(edge_keys) or edge_keys != sorted(edge_keys):
        _fail("edges order/duplicates")

    unknowns = payload.get("unknown_imports")
    if not isinstance(unknowns, list):
        _fail("unknown_imports")
    unknown_keys = []
    for item in unknowns:
        if set(item) != {"source_component_id", "imported_name", "count"}:
            _fail("unknown keys")
        if item["source_component_id"] not in ids:
            _fail("unknown source")
        if type(item["count"]) is not int or item["count"] < 1:
            _fail("unknown count")
        unknown_keys.append((item["source_component_id"], item["imported_name"]))
    if len(set(unknown_keys)) != len(unknown_keys) or unknown_keys != sorted(
        unknown_keys
    ):
        _fail("unknown order/duplicates")

    unassigned = payload.get("unassigned_files")
    if not isinstance(unassigned, list):
        _fail("unassigned_files")
    for item in unassigned:
        _check_path(item)
    if unassigned != sorted(unassigned):
        _fail("unassigned order")
    unassigned_count = payload.get("unassigned_file_count")
    if type(unassigned_count) is not int or unassigned_count < len(unassigned):
        _fail("unassigned_file_count")

    summaries = payload.get("scan_summaries")
    if not isinstance(summaries, list):
        _fail("scan_summaries")
    summary_ids = []
    for item in summaries:
        if set(item) != {
            "component_id",
            "parse_error_file_count",
            "read_failure_file_count",
            "dynamic_import_site_count",
            "unknown_truncated_count",
            "manifest_parse_failure_count",
        }:
            _fail("scan keys")
        if item["component_id"] not in ids:
            _fail("scan component_id")
        summary_ids.append(item["component_id"])
        for key in (
            "parse_error_file_count",
            "read_failure_file_count",
            "dynamic_import_site_count",
            "unknown_truncated_count",
            "manifest_parse_failure_count",
        ):
            if type(item[key]) is not int or item[key] < 0:
                _fail(f"scan {key}")
    if summary_ids != sorted(summary_ids) or len(set(summary_ids)) != len(summary_ids):
        _fail("scan order")
    if set(summary_ids) != set(ids):
        _fail("scan coverage")
    for entry in components:
        summary = next(
            item for item in summaries if item["component_id"] == entry["component_id"]
        )
        for key in (
            "parse_error_file_count",
            "read_failure_file_count",
            "dynamic_import_site_count",
            "unknown_truncated_count",
            "manifest_parse_failure_count",
        ):
            if summary[key] != entry["scan_summary"][key]:
                _fail("scan/entry mismatch")

    unbuilt = payload.get("unbuilt_components")
    if not isinstance(unbuilt, list):
        _fail("unbuilt")
    unbuilt_ids = []
    for item in unbuilt:
        if set(item) != {"component_id", "reason"}:
            _fail("unbuilt keys")
        if item["component_id"] not in ids:
            _fail("unbuilt component_id")
        if item["reason"] not in UNBUILT_REASONS:
            _fail("unbuilt reason")
        unbuilt_ids.append(item["component_id"])
    if unbuilt_ids != sorted(unbuilt_ids) or len(set(unbuilt_ids)) != len(
        unbuilt_ids
    ):
        _fail("unbuilt order")
    built_ids = {
        entry["component_id"] for entry in components if entry["built"]
    }
    if set(unbuilt_ids) != set(ids) - built_ids:
        _fail("unbuilt/built correspondence")
    if unbuilt and payload.get("dependencies_complete") is not False:
        _fail("unbuilt requires incomplete")
    if not isinstance(payload.get("dependencies_complete"), bool):
        _fail("dependencies_complete")

    gaps = payload.get("coverage_gaps")
    if not isinstance(gaps, list):
        _fail("coverage_gaps")
    gap_pairs = []
    for gap in gaps:
        if set(gap) != {"gap_code", "detail"}:
            _fail("gap keys")
        gap_pairs.append((gap["gap_code"], gap["detail"]))
    if gap_pairs != sorted(gap_pairs):
        _fail("gaps order")
    channel_meta: dict[str, int] = {}
    seen_triples: set[tuple] = set()
    unknown_limit_count = 0
    for code, detail in gap_pairs:
        channel = None
        if code == "INVENTORY_SKIPPED" or detail.startswith("channel="):
            parts = detail.split("; ")
            if len(parts) != 3 or not parts[0].startswith("channel="):
                _fail(f"channel detail format: {detail!r}")
            channel = parts[0][len("channel=") :]
            if channel not in COMPONENT_MANIFEST_SOURCES:
                _fail("channel domain")
            if not parts[1].startswith("reason=") or not parts[2].startswith(
                "count="
            ):
                _fail("channel detail order")
            count_value = parts[2][len("count=") :]
            if not count_value.isdigit() or int(count_value) < 1:
                _fail("channel count")
            reason = parts[1][len("reason=") :]
            triple = (code, channel, reason)
            if triple in seen_triples:
                _fail("duplicate channel triple")
            seen_triples.add(triple)
            if code == "BUDGET_EXHAUSTED" and reason not in (
                "metadata-manifest-limit",
                "metadata-byte-limit",
            ):
                _fail("budget family must not carry a channel")
            if channel == "metadata-channel":
                channel_meta[reason] = int(count_value)
            if reason == "unknown-import-limit":
                unknown_limit_count = int(count_value)
        else:
            parts = detail.split("; ")
            if len(parts) != 2 or not parts[0].startswith("reason="):
                _fail(f"budget detail format: {detail!r}")
            if not parts[1].startswith("count=") or not parts[1][
                len("count=") :
            ].isdigit():
                _fail("budget count")
            if int(parts[1][len("count=") :]) < 1:
                _fail("budget count value")
            if parts[0][len("reason=") :] == "unknown-import-limit":
                unknown_limit_count = int(parts[1][len("count=") :])
    skipped = payload.get("metadata_channel_skipped")
    if not isinstance(skipped, Mapping):
        _fail("metadata_channel_skipped")
    vocabulary = _T8_LOSS_KEYS + (
        "ignored-directory",
        "sensitive-filename",
        "symlink",
    )
    for key, value in skipped.items():
        if key not in vocabulary or type(value) is not int or value < 0:
            _fail("metadata_channel_skipped vocabulary")
    for reason, count in channel_meta.items():
        if skipped.get(reason) != count:
            _fail("channel/gap accounting")
    for key in ("metadata-manifest-limit", "metadata-byte-limit", "unreadable", "non-utf8"):
        if skipped.get(key, 0) > 0 and key not in channel_meta:
            _fail("missing metadata-domain gap record")
    truncated_total = sum(
        item["unknown_truncated_count"] for item in summaries
    )
    if truncated_total != unknown_limit_count:
        _fail("unknown truncation accounting")

    discovered = payload.get("manifests_discovered_count")
    collaboration = payload.get("collaboration_manifest_count")
    overflow = payload.get("overflow_manifest_count")
    metadata_manifest = payload.get("metadata_manifest_count")
    for name, value in (
        ("manifests_discovered_count", discovered),
        ("collaboration_manifest_count", collaboration),
        ("overflow_manifest_count", overflow),
        ("metadata_manifest_count", metadata_manifest),
    ):
        if type(value) is not int or value < 0:
            _fail(name)
    if discovered != published + collaboration + overflow:
        _fail("manifest conservation")
    if metadata_manifest > discovered:
        _fail("metadata over discovered")
    if published_meta > metadata_manifest:
        _fail("published metadata over channel count")

    build = payload.get("build")
    if not isinstance(build, Mapping) or set(build) != {"monorepo_budgets"}:
        _fail("build keys")
    budgets = build["monorepo_budgets"]
    if not isinstance(budgets, Mapping):
        _fail("monorepo_budgets")
    budget_keys = {
        "max_components",
        "max_edges",
        "max_edge_evidence",
        "max_unassigned_files",
        "max_total_model_calls",
        "aggregate_max_prompt_tokens",
        "aggregate_max_output_tokens",
        "aggregate_max_total_tokens",
        "max_metadata_manifests",
        "max_metadata_total_bytes",
    }
    if set(budgets) != budget_keys:
        _fail("monorepo_budgets keys")
    for value in budgets.values():
        if type(value) is not int or value < 1:
            _fail("budget value")
    if len(components) > budgets["max_components"]:
        _fail("components over budget")
    if len(edges) + len(unknowns) > budgets["max_edges"]:
        _fail("mixed edge/unknown over budget")
    for edge in edges:
        if len(edge["evidence"]) > budgets["max_edge_evidence"]:
            _fail("evidence over budget")
    if len(unassigned) > budgets["max_unassigned_files"]:
        _fail("unassigned over budget")
    if metadata_manifest > budgets["max_metadata_manifests"]:
        _fail("metadata manifests over budget")
    if len(components) > 64 or len(edges) > 16_384 or len(unknowns) > 16_384:
        _fail("hard caps")

    identity = payload.get("identity")
    if not isinstance(identity, Mapping) or set(identity) != {
        "component_graph_digest"
    }:
        _fail("identity keys")
    digest_value = identity["component_graph_digest"]
    if not isinstance(digest_value, str) or not _HEX64.match(digest_value):
        _fail("identity digest format")
    canonical = {
        "components": [
            {
                "component_id": entry["component_id"],
                "root_dir": entry["root_dir"],
                "manifests": [
                    {
                        "path": ref["path"],
                        "kind": ref["manifest_kind"],
                        "source": ref["source"],
                    }
                    for ref in entry["manifests"]
                ],
                "python_file_count": entry["python_file_count"],
                "is_empty": entry["is_empty"],
                "artifact_digests": (
                    None
                    if entry["digests"] is None
                    else dict(entry["digests"])
                ),
            }
            for entry in components
        ],
        "edges": [dict(edge) for edge in edges],
        "unknown_imports": [dict(item) for item in unknowns],
        "scan_summaries": [dict(item) for item in summaries],
        "unbuilt_components": [dict(item) for item in unbuilt],
        "unassigned_files": list(unassigned),
        "unassigned_file_count": unassigned_count,
        "dependencies_complete": payload["dependencies_complete"],
        "coverage_gaps": [dict(gap) for gap in gaps],
        "manifests_discovered_count": discovered,
        "metadata_manifest_count": metadata_manifest,
        "collaboration_manifest_count": collaboration,
        "overflow_manifest_count": overflow,
    }
    if compute_content_digest(canonical) != digest_value:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.identity")
