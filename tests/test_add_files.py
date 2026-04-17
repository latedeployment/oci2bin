import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
import importlib.util


ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    "add_files", ROOT / "scripts" / "add_files.py"
)
add_files_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(add_files_mod)


class TestAddFiles(unittest.TestCase):
    def _write_minimal_oci_tar(self, path: Path):
        config_path = "blobs/sha256/" + ("1" * 64)
        config = {
            "architecture": "amd64",
            "rootfs": {"type": "layers", "diff_ids": []},
        }
        manifest = [{
            "Config": config_path,
            "RepoTags": ["demo:latest"],
            "Layers": [],
        }]
        config_raw = json.dumps(config).encode()
        manifest_raw = json.dumps(manifest).encode()

        with tarfile.open(path, "w") as tf:
            for name, data in [
                ("manifest.json", manifest_raw),
                (config_path, config_raw),
            ]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

    def test_add_files_rewrites_config_digest_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            input_tar = tmp / "input.tar"
            output_tar = tmp / "output.tar"
            payload = tmp / "payload.txt"
            payload.write_text("hello\n", encoding="utf-8")
            self._write_minimal_oci_tar(input_tar)

            add_files_mod.add_files(
                str(input_tar),
                str(output_tar),
                [f"{payload}:/etc/payload.txt"],
                [],
            )

            with tarfile.open(output_tar, "r") as tf:
                manifest = json.loads(tf.extractfile("manifest.json").read())
                config_name = manifest[0]["Config"]
                config_raw = tf.extractfile(config_name).read()
                config = json.loads(config_raw)

                self.assertEqual(
                    config_name,
                    "blobs/sha256/" + add_files_mod.hashlib.sha256(config_raw).hexdigest(),
                )
                self.assertEqual(len(manifest[0]["Layers"]), 1)
                self.assertEqual(len(config["rootfs"]["diff_ids"]), 1)


if __name__ == "__main__":
    unittest.main()
