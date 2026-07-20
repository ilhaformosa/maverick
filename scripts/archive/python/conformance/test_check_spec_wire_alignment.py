#!/usr/bin/env python3
"""Unit tests for the spec/wire alignment checker."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_spec_wire_alignment


class SpecWireAlignmentTests(unittest.TestCase):
    def test_matching_frame_maps_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, wire_padding=True, python_padding=True)

            self.assertEqual(check_spec_wire_alignment.check_repo(root), 2)

    def test_wire_format_missing_frame_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, wire_padding=False, python_padding=True)

            with self.assertRaisesRegex(AssertionError, "WIRE_FORMAT.md frame table"):
                check_spec_wire_alignment.check_repo(root)

    def test_python_verifier_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_repo(root, wire_padding=True, python_padding=False)

            with self.assertRaisesRegex(AssertionError, "python verifier FRAME_TYPES"):
                check_spec_wire_alignment.check_repo(root)


def write_repo(root: Path, wire_padding: bool, python_padding: bool) -> None:
    frame_rs = root / "crates/maverick-core/src/frame.rs"
    frame_rs.parent.mkdir(parents=True)
    frame_rs.write_text(
        """pub enum FrameType {
    TcpData = 0x04,
    Padding = 0x10,
}
""",
        encoding="utf-8",
    )

    wire_lines = ["0x04 TCP_DATA"]
    if wire_padding:
        wire_lines.append("0x10 PADDING")
    (root / "WIRE_FORMAT.md").write_text(
        "# Wire\n\n```text\n" + "\n".join(wire_lines) + "\n```\n",
        encoding="utf-8",
    )
    (root / "SPEC.md").write_text(
        "Status: experimental. This is not production-ready.\n",
        encoding="utf-8",
    )

    python_verify = root / "conformance/runner/python_verify.py"
    python_verify.parent.mkdir(parents=True)
    python_lines = ['FRAME_TYPES = {"tcp_data": 0x04']
    if python_padding:
        python_lines.append(', "padding": 0x10')
    python_lines.append("}\n")
    python_verify.write_text("".join(python_lines), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
