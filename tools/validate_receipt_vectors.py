#!/usr/bin/env python3
"""Checks the receipt signing transcript against spec/registries.md.

The point is independence. This rebuilds the authenticated input from its parts
the way the registry describes it, in a different language and a different
implementation from the crate that produced the vector, and recomputes the
HMAC-SHA-256 authenticator from scratch. If the crate and the normative text
ever disagree about the domain, the scheme bytes, the length prefix, or where
the canonical receipt begins, that recomputation stops matching.

Ed25519 has no standard-library implementation, so its authenticator is checked
for shape and left for an implementation that has one. Both schemes cover the
same input apart from two scheme bytes, so the HMAC check exercises the whole
construction either way.
"""

import hashlib
import hmac
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTOR = ROOT / "test-vectors" / "receipt" / "signing-transcript.json"
REGISTRIES = ROOT / "spec" / "registries.md"

DOMAIN = b"VOT receipt v0\x00"


def fail(message):
    print(f"receipt vector validation: FAIL: {message}")
    sys.exit(1)


def unhex(text, field):
    stripped = text.replace(" ", "")
    try:
        return bytes.fromhex(stripped)
    except ValueError:
        fail(f"{field} is not hexadecimal")
    return b""


def signing_input(scheme_value, key_id, canonical):
    """The transcript exactly as spec/registries.md orders it."""
    if not 1 <= len(key_id) <= 64:
        fail(f"key identifier is {len(key_id)} bytes, outside the 1 to 64 receipt.cddl allows")
    return b"".join(
        [
            DOMAIN,
            scheme_value.to_bytes(2, "big"),
            len(key_id).to_bytes(1, "big"),
            key_id,
            canonical,
        ]
    )


def check_registry_agrees(vector):
    """The vector is only worth anything if the normative text still says this."""
    # Collapsed, because the normative text is wrapped prose and a phrase that
    # happens to straddle a line break is still the same requirement.
    raw = REGISTRIES.read_text()
    text = re.sub(r"\s+", " ", raw)
    frozen = re.search(r"Status: frozen for `([^`]+)`", text)
    if frozen is None:
        fail("spec/registries.md has no freeze marker")
        return
    if frozen.group(1) != vector["alpn"]:
        fail(f"vector is for {vector['alpn']} but the registry is frozen for {frozen.group(1)}")
    for phrase in (
        "domain separator",
        "two-byte scheme value",
        "key identifier prefixed by its length in a single byte",
        "canonical receipt",
    ):
        if phrase not in text:
            fail(f"spec/registries.md no longer describes the {phrase!r} component")
    for scheme in vector["schemes"]:
        row = f"| `0x{scheme['value']:04x}` | `{scheme['name']}` |"
        if row not in text:
            fail(f"{scheme['name']} is not registered as 0x{scheme['value']:04x}")


def main():
    vector = json.loads(VECTOR.read_text())
    if vector["format"] != "vot-receipt-signing-transcript-v1":
        fail(f"unknown vector format {vector['format']}")

    check_registry_agrees(vector)

    if unhex(vector["domain_separator_hex"], "domain_separator_hex") != DOMAIN:
        fail("domain separator does not match the one this validator was written against")

    key_id = unhex(vector["key_id_hex"], "key_id_hex")
    if key_id.decode("ascii") != vector["key_id_ascii"]:
        fail("key_id_hex and key_id_ascii disagree")
    prefix = unhex(vector["key_id_length_prefix_hex"], "key_id_length_prefix_hex")
    if prefix != len(key_id).to_bytes(1, "big"):
        fail("the recorded length prefix is not the key identifier's length")
    low, high = vector["key_id_bounds_bytes"]
    if (low, high) != (1, 64):
        fail("key identifier bounds no longer match receipt.cddl")

    canonical = unhex(vector["canonical_receipt_hex"], "canonical_receipt_hex")
    if not canonical:
        fail("canonical receipt is empty")

    checked = 0
    for scheme in vector["schemes"]:
        recorded = unhex(scheme["authenticator_hex"], f"{scheme['name']} authenticator")
        if len(recorded) != scheme["authenticator_bytes"]:
            fail(
                f"{scheme['name']} authenticator is {len(recorded)} bytes,"
                f" registered as {scheme['authenticator_bytes']}"
            )
        if unhex(scheme["scheme_hex"], "scheme_hex") != scheme["value"].to_bytes(2, "big"):
            fail(f"{scheme['name']} scheme_hex does not encode {scheme['value']}")

        transcript = signing_input(scheme["value"], key_id, canonical)
        if not transcript.endswith(canonical):
            fail("the canonical receipt is not the tail of the transcript")

        if scheme["name"] == "HMAC_SHA256":
            key = unhex(scheme["secret_key_hex"], "secret_key_hex")
            if len(key) < 32:
                fail("HMAC key is shorter than the 32 bytes the implementation requires")
            computed = hmac.new(key, transcript, hashlib.sha256).digest()
            if not hmac.compare_digest(computed, recorded):
                fail(
                    "recomputed HMAC does not match the recorded authenticator;"
                    " the implementation and spec/registries.md disagree about the transcript"
                )
            checked += 1
        elif scheme["name"] == "ED25519":
            public = unhex(scheme["public_key_hex"], "public_key_hex")
            if len(public) != 32:
                fail("Ed25519 public key is not 32 bytes")
            if not scheme["third_party_verifiable"]:
                fail("ED25519 is the scheme that crosses a trust boundary")
        else:
            fail(f"unregistered scheme {scheme['name']} in the vector")

    if checked == 0:
        fail("nothing was recomputed, so this validated nothing")

    envelope = unhex(
        vector["authenticated_envelope_ed25519_hex"], "authenticated_envelope_ed25519_hex"
    )
    if canonical not in envelope:
        fail("the envelope does not carry the canonical receipt it claims to")
    ed25519 = next(s for s in vector["schemes"] if s["name"] == "ED25519")
    if unhex(ed25519["authenticator_hex"], "authenticator") not in envelope:
        fail("the envelope does not carry its own authenticator")
    if key_id not in envelope:
        fail("the envelope does not carry the key identifier")

    print(f"receipt vector validation: PASS ({checked} authenticator recomputed)")


if __name__ == "__main__":
    main()
