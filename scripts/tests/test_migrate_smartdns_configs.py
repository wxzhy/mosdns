"""Policy-preserving merge checks using the checked-in deployment profiles."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError as exc:
    raise unittest.SkipTest("PyYAML is required; use the documented SmartDNS Python environment") from exc

from scripts.migrate_smartdns_configs import merge_example_services, render_config


ROOT = Path(__file__).resolve().parents[2]
POLICY_HASHES = {
    # Entire policy graphs at 559ee09 before the runtime-service merge.
    "config.yaml": "a917e6233944d61ddb3513d8af4f86a90deb7b3cf27070864d686b871b34583a",
    "config-cernet.yaml": "5be2864b4675d1d833b79abd245bb56995a506d005ffa5085f1ebcafc5b2d382",
}


def policy_view(cfg):
    plugins = copy.deepcopy(cfg["plugins"])
    plugins = [p for p in plugins if p["tag"] not in ("stats_collector", "response_cache")]
    main = next(p for p in plugins if p["tag"] == "main")
    if main["args"] and main["args"][0] == {"exec": "$stats_collector"}:
        main["args"].pop(0)
    return {"geodata": cfg["geodata"], "plugins": plugins}


def profile_for(name):
    return "cernet" if name == "config-cernet.yaml" else "default"


class MigrationServicesTest(unittest.TestCase):
    def load(self, name):
        return yaml.safe_load((ROOT / "examples/smartdns" / name).read_text(encoding="utf-8"))

    def test_entire_prior_policy_is_preserved(self):
        for name, expected in POLICY_HASHES.items():
            with self.subTest(name=name):
                view = policy_view(self.load(name))
                actual = hashlib.sha256(json.dumps(view, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                self.assertEqual(actual, expected)

    def test_merged_services_and_auxiliary_entry(self):
        for name in POLICY_HASHES:
            with self.subTest(name=name):
                cfg = self.load(name)
                suffix = "-cernet" if profile_for(name) == "cernet" else ""
                self.assertEqual(cfg["log"], {"level": "info", "file": "/var/log/mosdns.log"})
                self.assertEqual(cfg["api"], {"http": "127.0.0.1:9091"})
                self.assertEqual(cfg["include"], [])
                plugins = {p["tag"]: p for p in cfg["plugins"]}
                self.assertEqual(len(plugins), len(cfg["plugins"]))
                self.assertEqual(cfg["plugins"][0]["tag"], "stats_collector")
                self.assertEqual(plugins["stats_collector"]["args"], {
                    "capacity": 2000, "dump_file": f"/etc/mosdns/stats{suffix}.dump", "dump_interval": 600,
                })
                self.assertEqual(plugins["response_cache"]["args"], {
                    "size": 20000, "lazy_cache_ttl": 86400,
                    "dump_file": f"/etc/mosdns/cache{suffix}.dump", "dump_interval": 600,
                })
                self.assertEqual(sum(p["type"] == "cache" for p in cfg["plugins"]), 1)
                self.assertEqual(plugins["main"]["args"][:2], [
                    {"exec": "$stats_collector"}, {"exec": "$response_cache"},
                ])
                users = [p["tag"] for p in cfg["plugins"] if p["type"] == "sequence"
                         and any(r.get("exec") == "$stats_collector" for r in p["args"])]
                self.assertEqual(users, ["main"])

    def test_merge_is_pure_and_idempotent(self):
        for name in POLICY_HASHES:
            original = self.load(name)
            before = copy.deepcopy(original)
            first = merge_example_services(original, profile=profile_for(name))
            second = merge_example_services(first, profile=profile_for(name))
            self.assertEqual(original, before)
            self.assertEqual(first, second)
            self.assertEqual(render_config(first), render_config(second))

    def test_merge_cli_preserves_provenance_and_needs_no_changed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "profiles"
            out.mkdir()
            for name in POLICY_HASHES:
                text = (ROOT / "examples/smartdns" / name).read_text(encoding="utf-8")
                (out / name).write_text(text, encoding="utf-8")
            cmd = [sys.executable, str(ROOT / "scripts/migrate_smartdns_configs.py"),
                   "--merge-existing", "--output", str(out), "--source", str(Path(directory) / "absent-source")]
            subprocess.run(cmd, check=True, capture_output=True)
            first = {name: (out / name).read_bytes() for name in POLICY_HASHES}
            subprocess.run(cmd, check=True, capture_output=True)
            for name in POLICY_HASHES:
                self.assertEqual((out / name).read_bytes(), first[name])
                expected_header = (ROOT / "examples/smartdns" / name).read_text(encoding="utf-8").splitlines()[0]
                self.assertEqual(first[name].decode().splitlines()[0], expected_header)
            self.assertFalse((Path(directory) / "absent-source").exists())

    def test_merge_rejects_tag_conflicts(self):
        cfg = self.load("config.yaml")
        cfg["plugins"][0]["type"] = "hosts"
        with self.assertRaisesRegex(ValueError, "another plugin type"):
            merge_example_services(cfg)
        cfg = self.load("config.yaml")
        cfg["plugins"].append(copy.deepcopy(cfg["plugins"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            merge_example_services(cfg)


if __name__ == "__main__":
    unittest.main()
