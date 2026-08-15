#!/usr/bin/env python3
"""The identifier registries, loaded from spec/registries.yaml.

The YAML is JSON-compatible, the same way security/abuse-cases.yaml is.
spec/registries.md is the human view of these tables. vot-codec holds the
Rust constants. This module is the one relation those two are checked
against, so a row that exists in only one of them is a failure.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "spec" / "registries.yaml"
GENERATED_PATH = ROOT / "crates" / "vot-codec" / "src" / "generated.rs"

FRAME_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_-]+)` "
    r"\| (?P<handling>critical|optional) \| (?P<status>draft|experimental) \|",
    re.MULTILINE,
)
SETTING_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_-]+)` \| "
    r"(?P<default>[^|]+?) \| (?P<range>[^|]+?) \| (?P<handling>critical|optional) \|",
    re.MULTILINE,
)
ERROR_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_]+)` \| (?P<class>[a-z/ ]+) \|",
    re.MULTILINE,
)
OPERATION_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_]+)` \| (?P<status>[a-z ]+) \|",
    re.MULTILINE,
)
LIMIT_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_]+)` \| "
    r"(?P<unit>[^|]+?) \| (?P<status>[a-z ]+) \|",
    re.MULTILINE,
)
TELEMETRY_ROW = re.compile(
    r"^\| `(?P<name>(?:vot|vcrc)\.[a-z0-9_.]+)` \| (?P<stability>[^|]+?) \| "
    r"(?P<redaction>[^|]+?) \|",
    re.MULTILINE,
)
EXTENSION_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_]+)` \| "
    r"(?P<status>[^|]+?) \| (?P<default>[^|]+?) \|",
    re.MULTILINE,
)
SUITE_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[a-z0-9-]+)` \| "
    r"(?P<root_length>[^|]+?) \| (?P<status>[^|]+?) \|",
    re.MULTILINE,
)
COMPRESSION_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[a-z0-9-]+)` \| (?P<status>[^|]+?) \|",
    re.MULTILINE,
)
PROFILE_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z_]+)` \| "
    r"`(?P<predecessor>[A-Z_]+)` \|",
    re.MULTILINE,
)
PROVIDER_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z_]+)` \| (?P<status>[^|]+?) \|",
    re.MULTILINE,
)
ASSURANCE_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z_]+)` \|",
    re.MULTILINE,
)
RECEIPT_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[A-Z0-9_]+)` \| "
    r"(?P<authenticator_length>[^|]+?) \| (?P<status>[^|]+?) \|",
    re.MULTILINE,
)
FORMAT_ROW = re.compile(
    r"^\| `(?P<value>0x[0-9a-f]+)` \| `(?P<name>[a-z0-9-]+)` \| (?P<status>[^|]+?) \|",
    re.MULTILINE,
)
FRAME_DECLARATION_ROW = re.compile(
    r"^\s*(?P<name>[A-Z0-9_]+) = (?P<value>0x[0-9a-f]+), "
    r"limit: (?P<limit>[0-9 *]+|HARD_MAX_FRAME_PAYLOAD), "
    r"auth: (?P<auth>exempt|required), "
    r"extension: (?P<extension>none|[A-Z0-9_]+);$",
    re.MULTILINE,
)
SPEC_LIMIT = re.compile(r"^(?P<amount>\d+)(?: (?P<unit>KiB|MiB))?$")
BEHAVIOR_ROW = re.compile(
    r"^\| `(?P<name>[A-Z0-9_]+)` \| (?P<maximum>\d+(?: KiB| MiB)?) "
    r"\|[^|]*\| (?P<auth>yes|no|depends on phase) \|",
    re.MULTILINE,
)
RUST_U64 = re.compile(
    r"^\s*pub const (?P<name>[A-Z0-9_]+): u64 = (?P<value>0x[0-9a-f]+);$",
    re.MULTILINE,
)
RUST_U16 = re.compile(
    r"^\s*pub const (?P<name>[A-Z0-9_]+): u16 = (?P<value>0x[0-9a-f]+);$",
    re.MULTILINE,
)
RETIRED_SETTINGS = re.compile(
    r"pub const RETIRED: \[u64; (?P<count>\d+)\] = \[(?P<body>[^\]]*)\];"
)

REQUIRED_TABLES = (
    "frames",
    "settings",
    "retired_settings",
    "extensions",
    "suites",
    "compression",
    "commit_profiles",
    "providers",
    "assurance",
    "errors",
    "telemetry",
    "receipt_schemes",
    "capability_formats",
    "operations",
    "limits",
)


def load_registries(path: Path = REGISTRY_PATH) -> dict:
    """The committed identifier tables."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "vot-registries-v1":
        raise ValueError(f"unsupported registry schema: {document.get('schema')!r}")
    missing = [key for key in REQUIRED_TABLES if key not in document]
    if missing:
        raise ValueError(f"registry table missing {missing}")
    if "grease_frames" not in document:
        raise ValueError("registry table missing grease_frames")
    return document


def parse_hex(value: str) -> int:
    return int(value, 16)


def name_values(rows: list[dict]) -> dict[str, int]:
    return {row["name"]: parse_hex(row["value"]) for row in rows}


def _const_block(rows: list[dict], ty: str) -> str:
    lines = [f"    pub const {row['name']}: {ty} = {row['value']};" for row in rows]
    return "\n".join(lines)


def render_identifiers(document: dict) -> str:
    """Rust identifier modules whose YAML rows are the complete set.

    Frame types stay in `frame_registry!` until payload, auth, and
    extension columns live in the YAML. Error codes stay handwritten
    because the codec names a subset of the registry.
    """
    settings = document["settings"]
    retired = document["retired_settings"]
    operations = document["operations"]
    limits = document["limits"]
    extensions = document["extensions"]
    retired_values = ", ".join(row["value"] for row in retired)
    setting_list = ",\n    ".join(f"setting_id::{row['name']}" for row in settings)
    operation_list = ",\n    ".join(f"operation::{row['name']}" for row in operations)
    limit_list = ",\n    ".join(f"resource_limit::{row['name']}" for row in limits)
    return (
        "// Generated from spec/registries.yaml by tools/generate_registries.py.\n"
        "// Do not edit.\n"
        "\n"
        "pub mod setting_id {\n"
        f"{_const_block(settings, 'u64')}\n"
        "\n"
        "    /// Identifiers the registry retired, kept so nothing reassigns them.\n"
        f"    pub const RETIRED: [u64; {len(retired)}] = [{retired_values}];\n"
        "}\n"
        "\n"
        "/// What a capability authorizes.\n"
        "pub mod operation {\n"
        f"{_const_block(operations, 'u64')}\n"
        "}\n"
        "\n"
        "/// What a capability may cap.\n"
        "pub mod resource_limit {\n"
        f"{_const_block(limits, 'u64')}\n"
        "}\n"
        "\n"
        "/// Extension identifiers.\n"
        "pub mod extension_id {\n"
        f"{_const_block(extensions, 'u64')}\n"
        "}\n"
        "\n"
        f"/// Every registered setting, in identifier order.\n"
        f"pub const REGISTERED_SETTINGS: [u64; {len(settings)}] = [\n"
        f"    {setting_list},\n"
        "];\n"
        "\n"
        f"/// Every registered operation, in identifier order.\n"
        f"pub const REGISTERED_OPERATIONS: [u64; {len(operations)}] = [\n"
        f"    {operation_list},\n"
        "];\n"
        "\n"
        f"/// Every registered resource limit, in identifier order.\n"
        f"pub const REGISTERED_LIMITS: [u64; {len(limits)}] = [\n"
        f"    {limit_list},\n"
        "];\n"
    )


def section(document: str, heading: str, next_heading: str) -> str:
    start = document.index(heading)
    end = document.index(next_heading, start)
    return document[start:end]


def numbered_section(document: str, heading: str) -> str:
    start = document.index(heading)
    body = document[start + len(heading) :]
    offset = body.find("\n## ")
    return heading + (body if offset < 0 else body[:offset])


def rust_module(source: str, name: str) -> str:
    marker = f"pub mod {name} {{"
    start = source.index(marker) + len(marker)
    end = source.index("\n}", start)
    return source[start:end]


def _table_lines(blob: str, prefix: str = "| `") -> int:
    return sum(1 for line in blob.splitlines() if line.startswith(prefix))


def _view_rows(pattern: re.Pattern[str], blob: str, prefix: str) -> list[dict]:
    rows = [match.groupdict() for match in pattern.finditer(blob)]
    for row in rows:
        for key, value in row.items():
            row[key] = value.strip()
    counted = _table_lines(blob, prefix)
    if len(rows) != counted:
        raise ValueError(f"parsed {len(rows)} of {counted} markdown rows")
    return rows


def markdown_tables(markdown: str) -> dict[str, list[dict]]:
    """The identifier tables as the human view writes them."""
    return {
        "frames": _view_rows(
            FRAME_ROW,
            section(markdown, "## 2. Frame types", "## 3. Settings"),
            "| `0x",
        ),
        "settings": _view_rows(
            SETTING_ROW,
            section(markdown, "## 3. Settings", "## 4. Extension identifiers"),
            "| `0x",
        ),
        "errors": _view_rows(
            ERROR_ROW,
            numbered_section(markdown, "## 8. Error codes"),
            "| `0x",
        ),
        "telemetry": _view_rows(
            TELEMETRY_ROW,
            section(
                markdown,
                "## 9. Telemetry event names",
                "## 10. Receipt authentication schemes",
            ),
            "| `",
        ),
        "extensions": _view_rows(
            EXTENSION_ROW,
            section(markdown, "## 4. Extension identifiers", "## 5. Verification suites"),
            "| `0x",
        ),
        "suites": _view_rows(
            SUITE_ROW,
            section(markdown, "## 5. Verification suites", "## 6. Compression suites"),
            "| `0x",
        ),
        "compression": _view_rows(
            COMPRESSION_ROW,
            section(markdown, "## 6. Compression suites", "## 7. Commit profiles"),
            "| `0x",
        ),
        "commit_profiles": _view_rows(
            PROFILE_ROW,
            section(markdown, "### 7.1 Commit profiles", "### 7.2 Provider identifiers"),
            "| `0x",
        ),
        "providers": _view_rows(
            PROVIDER_ROW,
            section(markdown, "### 7.2 Provider identifiers", "### 7.3 Assurance levels"),
            "| `0x",
        ),
        "assurance": _view_rows(
            ASSURANCE_ROW,
            section(markdown, "### 7.3 Assurance levels", "## 8. Error codes"),
            "| `0x",
        ),
        "receipt_schemes": _view_rows(
            RECEIPT_ROW,
            section(
                markdown,
                "## 10. Receipt authentication schemes",
                "## 11. Capability formats",
            ),
            "| `0x",
        ),
        "capability_formats": _view_rows(
            FORMAT_ROW,
            numbered_section(markdown, "## 11. Capability formats"),
            "| `0x",
        ),
        "operations": _view_rows(
            OPERATION_ROW,
            numbered_section(markdown, "## 12. Capability operations"),
            "| `0x",
        ),
        "limits": _view_rows(
            LIMIT_ROW,
            numbered_section(markdown, "## 13. Capability resource limits"),
            "| `0x",
        ),
    }


def _unique(rows: list[dict], label: str, failures: list[str]) -> None:
    values = [parse_hex(row["value"]) for row in rows]
    names = [row["name"] for row in rows]
    if len(values) != len(set(values)):
        failures.append(f"duplicate {label} value")
    if len(names) != len(set(names)):
        failures.append(f"duplicate {label} name")


def _handling_parity(rows: list[dict], label: str, failures: list[str]) -> None:
    for row in rows:
        value = parse_hex(row["value"])
        expected = "critical" if value & 1 else "optional"
        if row["handling"] != expected:
            failures.append(f"{label} {row['name']}: {row['handling']}, expected {expected}")


def _maps_equal(
    source: dict[str, int],
    other: dict[str, int],
    left: str,
    right: str,
    failures: list[str],
) -> None:
    if source == other:
        return
    failures.append(
        f"{left}/{right} mismatch: "
        f"{left}-only={source.keys() - other.keys()}, "
        f"{right}-only={other.keys() - source.keys()}"
    )
    mismatched = {
        name: (source[name], other[name])
        for name in source.keys() & other.keys()
        if source[name] != other[name]
    }
    if mismatched:
        failures.append(f"{left}/{right} value mismatch: {mismatched}")


def _listed_names(rust: str, const: str, prefix: str) -> list[str]:
    listed = re.search(
        rf"pub const {const}: \[u64; (?P<count>\d+)\] = \[(?P<body>[^\]]*)\];",
        rust,
    )
    if listed is None:
        raise ValueError(f"{const} not found")
    names = re.findall(rf"{prefix}::([A-Z0-9_]+)", listed["body"])
    if len(names) != int(listed["count"]):
        raise ValueError(
            f"{const} declares {listed['count']} entries but lists {len(names)}"
        )
    return names


def check_registries(
    document: dict,
    markdown: str,
    rust: str,
    wire: str,
    generated: str | None = None,
) -> list[str]:
    """Failures that mean the YAML, the Markdown view, or vot-codec drifted."""
    failures: list[str] = []
    if generated is not None:
        expected = render_identifiers(document)
        if generated != expected:
            failures.append(
                "crates/vot-codec/src/generated.rs is stale; "
                "run tools/generate_registries.py"
            )
        rust = generated + "\n" + rust

    frames = document["frames"]
    settings = document["settings"]
    operations = document["operations"]
    limits = document["limits"]
    errors = document["errors"]
    if not frames:
        failures.append("no frame registry rows")
    if not settings:
        failures.append("no settings registry rows")
    if not operations:
        failures.append("no capability operation rows")
    if not limits:
        failures.append("no capability limit rows")
    if not errors:
        failures.append("no error-code registry rows")

    _unique(frames, "frame", failures)
    _unique(settings, "setting", failures)
    _unique(operations, "capability operation", failures)
    _unique(limits, "capability limit", failures)
    _unique(errors, "error", failures)
    _handling_parity(frames, "frame", failures)
    _handling_parity(settings, "setting", failures)

    grease = document["grease_frames"]
    grease_first = parse_hex(grease["first"])
    grease_last = parse_hex(grease["last"])
    grease_step = int(grease["step"])
    grease_values = range(grease_first, grease_last + 1, grease_step)
    if any(value % 2 for value in grease_values):
        failures.append("grease frame values are not even")
    frame_values = {parse_hex(row["value"]) for row in frames}
    if frame_values & set(grease_values):
        failures.append("frame collides with the grease range")

    if 0 in name_values(operations).values():
        failures.append("0x0000 is reserved as an operation")
    if 0 in name_values(limits).values():
        failures.append("0x0000 is reserved as a limit")

    try:
        view = markdown_tables(markdown)
    except (ValueError, KeyError) as error:
        failures.append(f"markdown view: {error}")
        view = {}
    for key, rows in view.items():
        if rows != document[key]:
            failures.append(f"markdown {key} table does not match the registry source")

    try:
        declaration_start = rust.index("frame_registry! {")
        declaration_text = rust[declaration_start : rust.index("\n}", declaration_start)]
        declarations = {
            match["name"]: match for match in FRAME_DECLARATION_ROW.finditer(declaration_text)
        }
        declaration_lines = sum(1 for line in declaration_text.splitlines() if " = 0x" in line)
        if len(declarations) != declaration_lines:
            failures.append(
                f"parsed {len(declarations)} of {declaration_lines} frame declaration rows"
            )
        frame_rust = {
            name: parse_hex(match["value"]) for name, match in declarations.items()
        }
    except ValueError as error:
        failures.append(f"frame_registry: {error}")
        declarations = {}
        frame_rust = {}
    _maps_equal(name_values(frames), frame_rust, "registry", "Rust frame", failures)

    setting_rust = {
        match["name"]: parse_hex(match["value"])
        for match in RUST_U64.finditer(rust_module(rust, "setting_id"))
    }
    _maps_equal(name_values(settings), setting_rust, "registry", "Rust setting", failures)
    try:
        listed_settings = _listed_names(rust, "REGISTERED_SETTINGS", "setting_id")
        if len(listed_settings) != len(set(listed_settings)):
            failures.append("duplicate in REGISTERED_SETTINGS")
        if set(listed_settings) != setting_rust.keys():
            failures.append(
                "REGISTERED_SETTINGS/setting_id mismatch: "
                f"listed-only={set(listed_settings) - setting_rust.keys()}, "
                f"constant-only={setting_rust.keys() - set(listed_settings)}"
            )
    except ValueError as error:
        failures.append(str(error))

    retired = re.search(RETIRED_SETTINGS, rust_module(rust, "setting_id"))
    if retired is None:
        failures.append("setting_id::RETIRED not found")
    else:
        retired_values = [parse_hex(item) for item in re.findall(r"0x[0-9a-f]+", retired["body"])]
        if len(retired_values) != int(retired["count"]):
            failures.append(
                f"RETIRED declares {retired['count']} entries but lists {len(retired_values)}"
            )
        expected_retired = [parse_hex(row["value"]) for row in document["retired_settings"]]
        if retired_values != expected_retired:
            failures.append(
                f"RETIRED {retired_values} does not match registry {expected_retired}"
            )

    operation_rust = {
        match["name"]: parse_hex(match["value"])
        for match in RUST_U64.finditer(rust_module(rust, "operation"))
    }
    _maps_equal(
        name_values(operations), operation_rust, "registry", "Rust operation", failures
    )
    try:
        listed_operations = _listed_names(rust, "REGISTERED_OPERATIONS", "operation")
        if set(listed_operations) != operation_rust.keys():
            failures.append(
                "REGISTERED_OPERATIONS/operation mismatch: "
                f"listed-only={set(listed_operations) - operation_rust.keys()}, "
                f"constant-only={operation_rust.keys() - set(listed_operations)}"
            )
    except ValueError as error:
        failures.append(str(error))

    limit_rust = {
        match["name"]: parse_hex(match["value"])
        for match in RUST_U64.finditer(rust_module(rust, "resource_limit"))
    }
    _maps_equal(name_values(limits), limit_rust, "registry", "Rust limit", failures)
    try:
        listed_limits = _listed_names(rust, "REGISTERED_LIMITS", "resource_limit")
        if set(listed_limits) != limit_rust.keys():
            failures.append(
                "REGISTERED_LIMITS/resource_limit mismatch: "
                f"listed-only={set(listed_limits) - limit_rust.keys()}, "
                f"constant-only={limit_rust.keys() - set(listed_limits)}"
            )
    except ValueError as error:
        failures.append(str(error))

    behavior_text = section(wire, "## 5. Frame behavior registry", "## 6. State and assurance")
    behavior_rows = {
        match["name"]: (match["maximum"], match["auth"])
        for match in BEHAVIOR_ROW.finditer(behavior_text)
    }
    if not behavior_rows:
        failures.append("no frame behavior rows parsed")
    table_lines = _table_lines(behavior_text, "| `")
    if len(behavior_rows) != table_lines:
        failures.append(f"parsed {len(behavior_rows)} of {table_lines} frame behavior rows")
    frame_names = {row["name"] for row in frames}
    if behavior_rows.keys() != frame_names:
        failures.append(
            "frame registry/behavior mismatch: "
            f"registry-only={frame_names - behavior_rows.keys()}, "
            f"behavior-only={behavior_rows.keys() - frame_names}"
        )
    unit_bytes = {None: 1, "KiB": 1024, "MiB": 1024 * 1024}
    frame_status = {row["name"]: row["status"] for row in frames}
    for name, (maximum, auth) in behavior_rows.items():
        declaration = declarations.get(name)
        if declaration is None:
            continue
        expected_exempt = auth in ("no", "depends on phase")
        if (declaration["auth"] == "exempt") != expected_exempt:
            failures.append(
                f"{name}: wire.md says auth {auth!r}, "
                f"the declaration says {declaration['auth']}"
            )
        spec_limit = SPEC_LIMIT.fullmatch(maximum)
        if spec_limit is None:
            failures.append(f"{name}: unparsed wire.md maximum {maximum!r}")
            continue
        spec_bytes = int(spec_limit["amount"]) * unit_bytes[spec_limit["unit"]]
        declared = declaration["limit"].strip()
        if declared == "HARD_MAX_FRAME_PAYLOAD":
            declared = "16 * 1024 * 1024"
        declared_bytes = 1
        for factor in declared.split("*"):
            declared_bytes *= int(factor)
        if declared_bytes != spec_bytes:
            failures.append(
                f"{name}: wire.md maximum is {spec_bytes} bytes, "
                f"the declaration says {declared_bytes}"
            )
        expected_extension = (
            "DATAGRAM_FEC" if frame_status.get(name) == "experimental" else "none"
        )
        if declaration["extension"] != expected_extension:
            failures.append(
                f"{name}: registry status {frame_status.get(name)!r} expects extension "
                f"{expected_extension}, the declaration says {declaration['extension']}"
            )

    error_values = [parse_hex(row["value"]) for row in errors]
    error_names = [row["name"] for row in errors]
    block_class: dict[int, str] = {}
    for value, name, cls in zip(error_values, error_names, (row["class"] for row in errors)):
        held = block_class.setdefault(value >> 8, cls)
        if held != cls:
            failures.append(
                f"{name}: block {value >> 8:#x} holds class {held!r}, row says {cls!r}"
            )
    if len(block_class.values()) != len(set(block_class.values())):
        failures.append("error class spans two blocks")
    if error_values != sorted(error_values):
        failures.append("error table not ascending")

    error_rust = {
        match["name"]: parse_hex(match["value"])
        for match in RUST_U16.finditer(rust_module(rust, "error_code"))
    }
    if not error_rust:
        failures.append("no error_code constants parsed")
    error_source = name_values(errors)
    rust_only = error_rust.keys() - error_source.keys()
    if rust_only:
        failures.append(f"error codes in Rust but not the registry: {rust_only}")
    mismatched = {
        name: (value, error_source[name])
        for name, value in error_rust.items()
        if name in error_source and error_source[name] != value
    }
    if mismatched:
        failures.append(f"error-code value mismatch (rust, registry): {mismatched}")

    return failures
