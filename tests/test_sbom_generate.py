"""scripts/sbom_generate.py: rpm header decoding and purl generation."""

import importlib.util
import os
import pathlib
import sqlite3
import struct
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "sbom_generate", ROOT / "scripts" / "sbom_generate.py")
sg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sg)


def _rpm_header(tags):
    """Build a headerExport-style blob: {tag: (type, value)}."""
    index = b""
    store = b""
    for tag, (typ, value) in tags.items():
        if typ == sg._RPM_INT32:
            while len(store) % 4:
                store += b"\0"
            data = struct.pack(">i", value)
        else:
            data = value.encode() + b"\0"
        index += struct.pack(">iIiI", tag, typ, len(store), 1)
        store += data
    return struct.pack(">II", len(tags), len(store)) + index + store


class RpmTest(unittest.TestCase):
    def test_header_blob_decoded(self):
        blob = _rpm_header({
            sg._RPMTAG_NAME: (sg._RPM_STRING, "bash"),
            sg._RPMTAG_VERSION: (sg._RPM_STRING, "5.2.26"),
            sg._RPMTAG_RELEASE: (sg._RPM_STRING, "1.fc40"),
            sg._RPMTAG_EPOCH: (sg._RPM_INT32, 2),
            sg._RPMTAG_ARCH: (sg._RPM_STRING, "x86_64"),
            sg._RPMTAG_SUMMARY: (sg._RPM_I18NSTRING, "The GNU shell"),
        })
        hdr = sg.parse_rpm_header_blob(blob)
        self.assertEqual(hdr[sg._RPMTAG_NAME], "bash")
        self.assertEqual(hdr[sg._RPMTAG_EPOCH], 2)
        self.assertEqual(hdr[sg._RPMTAG_SUMMARY], "The GNU shell")

    def test_truncated_blob_rejected(self):
        self.assertIsNone(sg.parse_rpm_header_blob(b"\0\0\0\x05\0\0\0\x10"))

    def test_sqlite_packages_table(self):
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "rpmdb.sqlite")
            conn = sqlite3.connect(db)
            conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY,"
                         " blob BLOB NOT NULL)")
            for name in ("bash", "gpg-pubkey"):
                conn.execute("INSERT INTO Packages (blob) VALUES (?)", (
                    _rpm_header({
                        sg._RPMTAG_NAME: (sg._RPM_STRING, name),
                        sg._RPMTAG_VERSION: (sg._RPM_STRING, "1"),
                        sg._RPMTAG_RELEASE: (sg._RPM_STRING, "2"),
                        sg._RPMTAG_ARCH: (sg._RPM_STRING, "noarch"),
                    }),))
            conn.commit()
            conn.close()
            pkgs = sg.parse_rpm_sqlite(db)
        self.assertEqual([(p["name"], p["version"]) for p in pkgs],
                         [("bash", "1-2")])


class PurlTest(unittest.TestCase):
    def test_deb_type_and_namespace(self):
        purl = sg.make_purl({"type": "dpkg", "name": "libc6",
                             "version": "2.36-9+deb12u4", "arch": "amd64"},
                            "debian")
        self.assertEqual(purl, "pkg:deb/debian/libc6@2.36-9%2Bdeb12u4"
                               "?arch=amd64&distro=debian")

    def test_apk_defaults_to_alpine(self):
        self.assertTrue(sg.make_purl({"type": "apk", "name": "musl",
                                      "version": "1.2.5-r0"}, "")
                        .startswith("pkg:apk/alpine/musl@"))

    def test_rpm_epoch_qualifier(self):
        purl = sg.make_purl({"type": "rpm", "name": "bash", "epoch": 1,
                             "version": "5-1", "arch": "x86_64"}, "fedora")
        self.assertIn("epoch=1", purl)
        self.assertTrue(purl.startswith("pkg:rpm/fedora/bash@5-1?"))


if __name__ == "__main__":
    unittest.main()
