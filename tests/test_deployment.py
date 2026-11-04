"""Offline release-context security and artifact preservation tests."""

import hashlib
from pathlib import Path
import shutil
from unittest.mock import patch

from scripts import prepare_docker_context as packaging
from tests.offline import OfflineTestCase


class DockerReleaseTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.root = Path(self.temporary) / "checkout"
        self.root.mkdir()
        for name in packaging.CONTEXT_FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            source = self.index_path if name == "data/index/portfolio.json" else packaging.ROOT / name
            shutil.copyfile(source, target)
        self.destination = Path(self.temporary) / "release"

    def prepare(self):
        return packaging.prepare_context(self.destination, root=self.root)

    def test_only_allowlisted_files_reach_context(self):
        for name in (".env", ".env.production", ".codex/config.toml", ".git/config",
                     ".aws/credentials", ".venv/secret", "src/private.py",
                     "data/private.md", "data/index/other.json", "tests/result.log"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PRIVATE-NOT-FOR-IMAGE", encoding="utf-8")
        self.assertEqual(self.prepare(), len(self.payload_chunks()))
        actual = {str(p.relative_to(self.destination)) for p in self.destination.rglob("*") if p.is_file()}
        self.assertEqual(actual, set(packaging.CONTEXT_FILES) | {"release.sha256"})
        for path in self.destination.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"PRIVATE-NOT-FOR-IMAGE", path.read_bytes())
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        for guard in self.network_guards:
            guard.assert_not_called()

    def payload_chunks(self):
        from src.index_store import load_index
        return load_index(self.index_path).chunks

    def test_source_index_and_manifest_are_exact_and_repeatable(self):
        originals = {name: (self.root / name).read_bytes() for name in packaging.IMAGE_FILES}
        self.prepare()
        for name, content in originals.items():
            self.assertEqual((self.destination / name).read_bytes(), content)
            self.assertEqual((self.root / name).read_bytes(), content)
        manifest = (self.destination / "release.sha256").read_text()
        entries = {}
        for line in manifest.splitlines():
            digest, name = line.split("  ", 1)
            entries[name] = digest
            self.assertEqual(hashlib.sha256((self.destination / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(set(entries), set(packaging.IMAGE_FILES))
        second = Path(self.temporary) / "second-release"
        packaging.prepare_context(second, root=self.root)
        self.assertEqual((second / "release.sha256").read_text(), manifest)

    def test_missing_or_corrupt_index_fails_without_output(self):
        path = self.root / "data/index/portfolio.json"
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertFalse(self.destination.exists())
        path.write_text("{invalid json")
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_changed_knowledge_cannot_be_packaged_with_old_index(self):
        path = self.root / "data/portfolio.md"
        path.write_text(path.read_text() + "\n")
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_existing_destination_is_never_overwritten(self):
        self.destination.mkdir()
        keep = self.destination / "keep.txt"
        keep.write_text("keep")
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(keep.read_text(), "keep")

    def test_context_inside_checkout_is_rejected(self):
        self.destination = self.root / "release"
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_symlinked_file_or_parent_cannot_copy_credentials(self):
        target = self.root / "src/api.py"
        target.unlink()
        private = Path(self.temporary) / "credentials"
        private.write_text("PRIVATE-NOT-FOR-IMAGE")
        target.symlink_to(private)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.destination.exists())
        target.unlink()
        (self.root / "src").rename(self.root / "other-src")
        (self.root / "src").symlink_to(self.root / "other-src", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_failed_copy_cleans_only_new_output_directory(self):
        original = Path.write_bytes
        def fail(path, content):
            if path == (self.destination / "uv.lock").resolve():
                raise OSError("Synthetic copy failure")
            return original(path, content)
        with patch.object(Path, "write_bytes", fail):
            with self.assertRaises(OSError):
                self.prepare()
        self.assertFalse(self.destination.exists())
        self.assertTrue((self.root / "uv.lock").is_file())
