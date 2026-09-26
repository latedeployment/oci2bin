"""scripts/sbom_generate.py: rpm header decoding and purl generation."""

import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import sqlite3
import struct
import subprocess
import tarfile
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
            sg._RPMTAG_VENDOR: (sg._RPM_STRING, "Fedora Project"),
        })
        hdr = sg.parse_rpm_header_blob(blob)
        self.assertEqual(hdr[sg._RPMTAG_NAME], "bash")
        self.assertEqual(hdr[sg._RPMTAG_VENDOR], "Fedora Project")
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
                        sg._RPMTAG_PACKAGER: (sg._RPM_STRING,
                                              "Koji <koji@example>"),
                    }),))
            conn.commit()
            conn.close()
            pkgs = sg.parse_rpm_sqlite(db)
        self.assertEqual([(p["name"], p["version"], p["maintainer"])
                          for p in pkgs],
                         [("bash", "1-2", "Koji <koji@example>")])


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


class DocumentStructureTest(unittest.TestCase):
    """SPDX documents DESCRIBE a root package that CONTAINS the OS packages;
    CycloneDX has the matching bom-refs and dependency graph."""

    PACKAGES = [
        {"type": "dpkg", "name": "bash", "version": "5.2.15-2",
         "arch": "amd64", "desc": "GNU shell",
         "maintainer": "Matthias Klose <doko@debian.org>",
         "purl": "pkg:deb/debian/bash@5.2.15-2?arch=amd64&distro=debian"},
        {"type": "dpkg", "name": "libc6", "version": "2.36-9",
         "arch": "amd64", "desc": "",
         "purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian"},
        # A duplicate row collapses to one element, one relationship.
        {"type": "dpkg", "name": "bash", "version": "5.2.15-2",
         "arch": "amd64", "desc": "GNU shell",
         "purl": "pkg:deb/debian/bash@5.2.15-2?arch=amd64&distro=debian"},
    ]
    DIGEST = "a" * 64

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.binary = os.path.join(self._td.name, "app.bin")
        with open(self.binary, "wb") as f:
            f.write(b"not really a polyglot")
        self.file_sha = hashlib.sha256(b"not really a polyglot").hexdigest()
        self._orig = sg._inspect.read_meta_block
        sg._inspect.read_meta_block = lambda path: {
            "image": "docker.io/library/debian:12",
            "digest": "debian@sha256:" + self.DIGEST,
            "timestamp": "2026-01-02T03:04:05Z",
        }

    def tearDown(self):
        sg._inspect.read_meta_block = self._orig
        self._td.cleanup()

    def test_spdx_root_and_relationships(self):
        doc = sg.build_spdx_document(self.PACKAGES, self.binary,
                                     now="2026-01-02T03:04:05Z")
        json.dumps(doc)    # serialisable
        ids = [p["SPDXID"] for p in doc["packages"]]
        self.assertEqual(ids[0], sg.ROOT_SPDX_ID)
        self.assertEqual(len(ids), len(set(ids)), "duplicate SPDXIDs")
        self.assertEqual(len(ids), 3)    # root + bash + libc6
        self.assertEqual(doc["documentDescribes"], [sg.ROOT_SPDX_ID])
        root = doc["packages"][0]
        self.assertEqual(root["name"], "docker.io/library/debian:12")
        self.assertEqual(root["versionInfo"], "sha256:" + self.DIGEST)
        self.assertEqual(root["primaryPackagePurpose"], "CONTAINER")
        self.assertEqual(root["checksums"],
                         [{"algorithm": "SHA256",
                           "checksumValue": self.file_sha}])
        self.assertEqual(
            root["externalRefs"][0]["referenceLocator"],
            "pkg:oci/debian@sha256%3A" + self.DIGEST
            + "?repository_url=docker.io%2Flibrary%2Fdebian&tag=12")
        rels = {(r["spdxElementId"], r["relationshipType"],
                 r["relatedSpdxElement"]) for r in doc["relationships"]}
        self.assertIn(("SPDXRef-DOCUMENT", "DESCRIBES", sg.ROOT_SPDX_ID),
                      rels)
        for spdx_id in ids[1:]:
            self.assertIn((sg.ROOT_SPDX_ID, "CONTAINS", spdx_id), rels)
        self.assertEqual(len(rels), 3)
        # Every relationship points at an element in the document.
        for _, _, target in rels:
            self.assertIn(target, ids)
        by_name = {p["name"]: p for p in doc["packages"]}
        self.assertEqual(by_name["bash"]["supplier"],
                         "Person: Matthias Klose (doko@debian.org)")
        self.assertEqual(by_name["libc6"]["supplier"], "NOASSERTION")
        self.assertEqual(root["supplier"], "NOASSERTION")

    def test_spdx_falls_back_without_metadata(self):
        sg._inspect.read_meta_block = lambda path: None
        doc = sg.build_spdx_document(self.PACKAGES[:1], self.binary)
        root = doc["packages"][0]
        self.assertEqual(root["name"], "app.bin")
        self.assertEqual(root["versionInfo"], "unknown")
        self.assertEqual(root["externalRefs"][0]["referenceLocator"],
                         "pkg:oci/app.bin")
        self.assertEqual(doc["documentDescribes"], [sg.ROOT_SPDX_ID])

    def test_spdx_ignores_malformed_digest(self):
        sg._inspect.read_meta_block = lambda path: {
            "image": "x:1", "digest": "sha256:not-hex"}
        doc = sg.build_spdx_document(self.PACKAGES[:1], self.binary)
        self.assertEqual(doc["packages"][0]["versionInfo"], "unknown")
        self.assertEqual(doc["packages"][0]["externalRefs"][0]
                         ["referenceLocator"], "pkg:oci/x?tag=1")

    def test_cyclonedx_root_and_dependencies(self):
        doc = sg.build_cyclonedx_document(self.PACKAGES, self.binary,
                                          now="2026-01-02T03:04:05Z")
        json.dumps(doc)
        comp = doc["metadata"]["component"]
        self.assertEqual(comp["bom-ref"], sg.ROOT_BOM_REF)
        self.assertEqual(comp["type"], "container")
        self.assertEqual(comp["name"], "docker.io/library/debian:12")
        self.assertEqual(comp["version"], "sha256:" + self.DIGEST)
        self.assertEqual(comp["hashes"], [{"alg": "SHA-256",
                                           "content": self.file_sha}])
        refs = [c["bom-ref"] for c in doc["components"]]
        self.assertEqual(len(refs), 2)
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(doc["dependencies"],
                         [{"ref": sg.ROOT_BOM_REF, "dependsOn": refs}])
        self.assertEqual(doc["components"][0]["supplier"],
                         {"name": "Matthias Klose",
                          "contact": [{"email": "doko@debian.org"}]})
        self.assertNotIn("supplier", doc["components"][1])

    def test_supplier_forms(self):
        self.assertEqual(sg.spdx_supplier({"maintainer":
                         "Debian Bash Maintainers <bash@packages.debian.org>"}),
                         "Organization: Debian Bash Maintainers"
                         " (bash@packages.debian.org)")
        self.assertEqual(sg.spdx_supplier({"maintainer": "Fedora Project"}),
                         "Organization: Fedora Project")
        self.assertEqual(sg.spdx_supplier({"maintainer": "Natanael Copa"
                                           " <ncopa@alpinelinux.org>"}),
                         "Person: Natanael Copa (ncopa@alpinelinux.org)")
        self.assertEqual(sg.spdx_supplier({"maintainer": "  "}), "NOASSERTION")
        self.assertEqual(sg.spdx_supplier({}), "NOASSERTION")
        self.assertIsNone(sg.cyclonedx_supplier({"maintainer": ""}))

    def test_oci_purl_shapes(self):
        self.assertEqual(sg.make_oci_purl("nginx", ""), "pkg:oci/nginx")
        self.assertEqual(sg.make_oci_purl("Nginx:latest", ""),
                         "pkg:oci/nginx?tag=latest")
        self.assertEqual(
            sg.make_oci_purl("ghcr.io/org/app:1.2", "b" * 64),
            "pkg:oci/app@sha256%3A" + "b" * 64
            + "?repository_url=ghcr.io%2Forg%2Fapp&tag=1.2")
        self.assertEqual(
            sg.make_oci_purl("localhost:5000/app", ""),
            "pkg:oci/app?repository_url=localhost%3A5000%2Fapp")


def _docker_save_tar(layer_files, repo_tag):
    """A docker-save style OCI tar with one layer."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in layer_files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    layer = buf.getvalue()
    config = json.dumps({
        "architecture": "amd64", "os": "linux",
        "config": {"Cmd": ["/bin/sh"]},
        "rootfs": {"type": "layers",
                   "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]},
    }).encode()
    cfg = "blobs/sha256/" + hashlib.sha256(config).hexdigest()
    lay = "blobs/sha256/" + hashlib.sha256(layer).hexdigest()
    manifest = json.dumps([{"Config": cfg, "RepoTags": [repo_tag],
                            "Layers": [lay]}]).encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tf:
        for name, data in (("manifest.json", manifest), (cfg, config),
                           (lay, layer)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return out.getvalue()


class EndToEndTest(unittest.TestCase):
    """`oci2bin sbom` on a real polyglot built from a dpkg-carrying image."""

    DIGEST = "c" * 64

    @classmethod
    def setUpClass(cls):
        if not shutil.which("gcc"):
            raise unittest.SkipTest("gcc not available")
        cls._td = tempfile.TemporaryDirectory(prefix="oci2bin-sbom-")
        td = pathlib.Path(cls._td.name)
        loader = td / "loader"
        build = subprocess.run(
            ["gcc", "-static", "-O2", "-s", "-o", str(loader),
             str(ROOT / "src" / "loader.c")],
            capture_output=True, text=True, timeout=300)
        if build.returncode != 0:
            raise unittest.SkipTest(f"failed to build loader: {build.stderr}")
        status = (b"Package: bash\nStatus: install ok installed\n"
                  b"Architecture: amd64\nVersion: 5.2.15-2+b7\n"
                  b"Maintainer: Matthias Klose <doko@debian.org>\n"
                  b"Description: GNU Bourne Again SHell\n\n"
                  b"Package: libc6\nStatus: install ok installed\n"
                  b"Architecture: amd64\nVersion: 2.36-9+deb12u10\n"
                  b"Description: GNU C Library: Shared libraries\n")
        tar_path = td / "image.tar"
        tar_path.write_bytes(_docker_save_tar(
            [("var/lib/dpkg/status", status),
             ("etc/os-release", b'ID=debian\nVERSION_ID="12"\n')],
            "docker.io/library/debian:12"))
        cls.binary = td / "deb.bin"
        built = subprocess.run(
            ["python3", str(ROOT / "scripts" / "build_polyglot.py"),
             "--loader", str(loader), "--tar", str(tar_path),
             "--image-name", "docker.io/library/debian:12",
             "--digest", "debian@sha256:" + cls.DIGEST,
             "--output", str(cls.binary)],
            capture_output=True, text=True, timeout=300)
        if built.returncode != 0:
            raise unittest.SkipTest(f"build_polyglot failed: {built.stderr}")

    @classmethod
    def tearDownClass(cls):
        cls._td.cleanup()

    def _sbom(self, *args):
        result = subprocess.run(
            [str(ROOT / "oci2bin"), "sbom", str(self.binary), *args],
            capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return json.loads(result.stdout)

    def test_spdx_end_to_end(self):
        doc = self._sbom()
        self.assertEqual(doc["documentDescribes"], [sg.ROOT_SPDX_ID])
        root = doc["packages"][0]
        self.assertEqual(root["name"], "docker.io/library/debian:12")
        self.assertEqual(root["versionInfo"], "sha256:" + self.DIGEST)
        self.assertEqual(root["checksums"][0]["checksumValue"],
                         hashlib.sha256(self.binary.read_bytes()).hexdigest())
        names = sorted(p["name"] for p in doc["packages"][1:])
        self.assertEqual(names, ["bash", "libc6"])
        suppliers = {p["name"]: p["supplier"] for p in doc["packages"]}
        self.assertEqual(suppliers["bash"],
                         "Person: Matthias Klose (doko@debian.org)")
        self.assertEqual(suppliers["libc6"], "NOASSERTION")
        contains = sorted(r["relatedSpdxElement"] for r in doc["relationships"]
                          if r["relationshipType"] == "CONTAINS")
        self.assertEqual(contains,
                         sorted(p["SPDXID"] for p in doc["packages"][1:]))
        self.assertIn("pkg:deb/debian/bash@5.2.15-2%2Bb7?arch=amd64"
                      "&distro=debian",
                      [p["externalRefs"][0]["referenceLocator"]
                       for p in doc["packages"]])

    def test_cyclonedx_end_to_end(self):
        doc = self._sbom("--format", "cyclonedx")
        self.assertEqual(doc["metadata"]["component"]["version"],
                         "sha256:" + self.DIGEST)
        refs = [c["bom-ref"] for c in doc["components"]]
        self.assertEqual(len(refs), 2)
        self.assertEqual(doc["dependencies"][0]["dependsOn"], refs)


if __name__ == "__main__":
    unittest.main()
