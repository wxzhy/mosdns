"""Synthetic checks; no SmartDNS checkout or third-party Python packages needed."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import migrate_smartdns_data as migration


def read_fields(data: bytes) -> list[tuple[int, int, bytes | int]]:
    """Independent reader for the two protobuf wire types used by GeoSite."""
    offset = 0

    def varint() -> int:
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                return value
        raise AssertionError("invalid varint")

    result = []
    while offset < len(data):
        key = varint()
        number, wire = key >> 3, key & 7
        if wire == 0:
            value = varint()
        elif wire == 2:
            length = varint()
            value = data[offset : offset + length]
            if len(value) != length:
                raise AssertionError("truncated field")
            offset += length
        else:
            raise AssertionError(f"unexpected wire type {wire}")
        result.append((number, wire, value))
    return result


def read_sites(data: bytes) -> dict[str, list[tuple[int, str]]]:
    sites = {}
    for number, wire, entry in read_fields(data):
        if (number, wire) != (1, 2):
            raise AssertionError("expected GeoSiteList.entry")
        fields = read_fields(entry)
        if fields[0][:2] != (1, 2):
            raise AssertionError("country_code must be the first field")
        code = fields[0][2].decode("ascii")
        if code in sites:
            raise AssertionError("duplicate GeoSite entry")
        rules = []
        for number, wire, domain in fields[1:]:
            if (number, wire) != (2, 2):
                raise AssertionError("expected GeoSite.domain")
            fields = read_fields(domain)
            if [field[:2] for field in fields] != [(1, 0), (2, 2)]:
                raise AssertionError("unexpected Domain fields")
            rules.append((fields[0][2], fields[1][2].decode("utf-8")))
        sites[code] = rules
    return sites


class GeoSiteExportTests(unittest.TestCase):
    def test_all_rule_types_and_long_utf8_field(self):
        long_regex = "^" + "例" * 100 + ":443$"
        data = migration.encode_geosite(
            {"selected": {"keyword:needle", "domain:example.test", "full:host.test", f"regexp:{long_regex}"}},
            ("selected",),
        )
        self.assertEqual(
            set(read_sites(data)["selected"]),
            {(0, "needle"), (1, long_regex), (2, "example.test"), (3, "host.test")},
        )

    def test_stable_sorting_deduplication_and_group_boundaries(self):
        first = migration.encode_geosite(
            {"z": ["domain:z.test", "full:only.test", "domain:z.test"], "a": {"domain:a.test"}, "unused@tag": {"full:unused.test"}},
            ("z", "a", "z"),
        )
        second = migration.encode_geosite(
            {"a": {"domain:a.test"}, "z": {"full:only.test", "domain:z.test"}},
            ("a", "z"),
        )
        self.assertEqual(first, second)
        self.assertEqual(
            read_sites(first),
            {"a": [(2, "a.test")], "z": [(2, "z.test"), (3, "only.test")]},
        )
        self.assertEqual(list(read_sites(first)), ["a", "z"])

    def test_invalid_selected_tags_and_rules(self):
        for tag in ("", ".", "..", "../tag", "ads@cn"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                migration.encode_geosite({tag: {"domain:example.test"}}, (tag,))
        with self.assertRaisesRegex(ValueError, "absent"):
            migration.encode_geosite({}, ("missing",))
        for rule in ("example.test", "other:example.test", "domain:"):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                migration.encode_geosite({"a": {rule}}, ("a",))

    def test_empty_group_is_retained(self):
        self.assertEqual(read_sites(migration.encode_geosite({"empty": set()}, ("empty",))), {"empty": []})

    def test_attribute_tag_is_rejected_before_loading_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(migration, "runtime_domains", side_effect=AssertionError("source must not be loaded")):
                with self.assertRaisesRegex(ValueError, "attribute separator"):
                    migration.migrate(root / "source", root / "output", "runtime", ("ads@cn",), ())

    def test_runtime_and_typed_exports_keep_text_and_manifest(self):
        cases = (
            ("runtime", {"a": {"domain:a.test"}, "z": {"domain:z.test"}}, 2),
            ("typed", {"a": {"full:a.test", "keyword:needle"}, "z": {"domain:z.test", "regexp:^z\\.test$"}}, 4),
        )
        for mode, groups, rule_count in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output = root / "source", root / "output"
                inputs = {
                    "tags/rules.input": b"synthetic rules source\n",
                    "tags/output/geoip.metadb": b"synthetic country database",
                    "tags/output/asn.mmdb": b"synthetic ASN database",
                    "tags/geoip/github.txt": b"203.0.113.2/24\n203.0.113.0/24\n",
                }
                for relative, data in inputs.items():
                    path = source / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                with patch.object(migration, f"{mode}_domains", return_value=(groups, [source / "tags/rules.input"])):
                    manifest = migration.migrate(source, output, mode, ("z", "a", "z"), ("github",))
                    repeat = root / "repeat"
                    migration.migrate(source, repeat, mode, ("a", "z"), ("github",))
                dat = (output / "geosite.dat").read_bytes()
                self.assertEqual(dat, (repeat / "geosite.dat").read_bytes())
                self.assertEqual(set(read_sites(dat)), {"a", "z"})
                self.assertEqual(
                    manifest["outputs"]["geosite.dat"],
                    {"entries": 2, "groups": {tag: len(rules) for tag, rules in groups.items()}, "rules": rule_count, "sha256": hashlib.sha256(dat).hexdigest()},
                )
                for tag, rules in groups.items():
                    self.assertEqual((output / "domains" / f"{tag}.txt").read_text(), "".join(f"{rule}\n" for rule in sorted(rules)))
                self.assertEqual((output / "ips/github.txt").read_text(), "203.0.113.0/24\n")
                self.assertEqual((output / "Country.mmdb").read_bytes(), inputs["tags/output/geoip.metadb"])
                self.assertEqual((output / "ASN.mmdb").read_bytes(), inputs["tags/output/asn.mmdb"])


if __name__ == "__main__":
    unittest.main()
