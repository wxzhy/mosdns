#!/usr/bin/env python3
"""Export the data used by the two migrated SmartDNS configurations.

Run with smartdns-test's Python environment; no mosdns runtime dependency is added.
The source tree is read-only. Pick runtime mode to reproduce its active trie, or
typed mode to retain the original GeoSite protobuf domain types instead.
Both modes write geosite.dat plus the same text rules for inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import ipaddress
import json
import re
import shutil
import sys
from pathlib import Path

DOMAIN_TAGS = (
    "ads",
    "apple-cn",
    "category-ads",
    "category-ads-all",
    "category-ntp",
    "category-stun",
    "cloudflare-cn",
    "cn",
    "dropbox",
    "facebook",
    "gfw",
    "google",
    "google-cn",
    "googlefcm",
    "meta",
    "mozilla",
    "proxy",
    "tld-opennic",
    "twitter",
)
IP_TAGS = ("github", "github-raw")
DOMAIN_TYPES = {0: "keyword", 1: "regexp", 2: "domain", 3: "full"}
DOMAIN_TYPE_NUMBERS = {name: number for number, name in DOMAIN_TYPES.items()}


def checked_tag(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9_!@.+-]+", value):
        raise ValueError(f"invalid data tag: {value!r}")
    if value in (".", ".."):
        raise ValueError(f"invalid data tag: {value!r}")
    return value


def checked_geosite_tag(value: str) -> str:
    value = checked_tag(value)
    if "@" in value:
        raise ValueError(f"GeoSite tag cannot contain the attribute separator '@': {value!r}")
    return value


def protobuf_varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def protobuf_bytes_field(number: int, value: bytes) -> bytes:
    return protobuf_varint((number << 3) | 2) + protobuf_varint(len(value)) + value


def encode_geosite(domains: dict[str, set[str]], tags: tuple[str, ...]) -> bytes:
    """Pack selected rule groups without changing their existing match types."""
    result = bytearray()
    for tag in sorted({checked_geosite_tag(tag) for tag in tags}):
        if tag not in domains:
            raise ValueError(f"domain tag absent from data: {tag}")
        # The Go loader locates entries by peeking at country_code (field 1).
        # It must precede the repeated domain field, even for an empty group.
        entry = bytearray(protobuf_bytes_field(1, tag.encode("ascii")))
        for expression in sorted(set(domains[tag])):
            kind, separator, value = expression.partition(":")
            if not separator or kind not in DOMAIN_TYPE_NUMBERS or not value:
                raise ValueError(f"invalid domain rule in {tag!r}: {expression!r}")
            domain = b"\x08" + protobuf_varint(DOMAIN_TYPE_NUMBERS[kind])
            domain += protobuf_bytes_field(2, value.encode("utf-8"))
            entry += protobuf_bytes_field(2, domain)
        result += protobuf_bytes_field(1, bytes(entry))
    return bytes(result)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def runtime_domains(source: Path) -> tuple[dict[str, set[str]], list[Path]]:
    """Decode the actual active trie rather than rebuilding from stale inputs."""
    try:
        import marisa_trie
    except ImportError as exc:
        raise ValueError(
            "runtime mode requires smartdns-test's existing marisa_trie; "
            "run this script with its .venv Python"
        ) from exc
    path = source / "tags/output/geosite.trie"
    trie = marisa_trie.BytesTrie().load(str(path))
    domains: dict[str, set[str]] = {}
    for key, value in trie.iteritems():
        if not key.startswith(".") or not key.endswith("."):
            raise ValueError(f"unexpected reverse-label trie key: {key!r}")
        name = ".".join(reversed(key.strip(".").split("."))) or "."
        label = checked_tag(value.decode("ascii").lower())
        domains.setdefault(label, set()).add(f"domain:{name}")
    return domains, [path]


def typed_domains(source: Path) -> tuple[dict[str, set[str]], list[Path]]:
    """Retain full/domain/regexp/keyword and GeoSite attribute membership.

    Includes inside geosite.dat are already expanded by its upstream compiler.
    The source project's generated protobuf classes supply the wire decoder.
    """
    sys.path.insert(0, str(source))
    try:
        router = importlib.import_module("utils.mihomo.component.geodata.router")
    except ImportError as exc:
        raise ValueError(
            "typed mode requires smartdns-test's existing generated protobuf "
            "module and betterproto2; run with its .venv Python"
        ) from exc
    finally:
        sys.path.pop(0)
    path = source / "tags/geosite.dat"
    with path.open("rb") as stream:
        geosite = router.GeoSiteList().load(stream)
    domains: dict[str, set[str]] = {}
    inputs = [path]
    for entry in geosite.entry:
        group = checked_tag(entry.country_code.lower())
        domains.setdefault(group, set())
        for rule in entry.domain:
            kind = DOMAIN_TYPES.get(int(rule.type))
            if kind is None:
                raise ValueError(f"unsupported GeoSite domain type {rule.type}")
            labels = {group}
            labels.update(checked_tag(attr.key.lower()) for attr in rule.attribute)
            for label in labels:
                domains.setdefault(label, set()).add(f"{kind}:{rule.value}")

    # Existing SmartDNS custom files are bare domain names. Recognize explicit
    # mosdns/V2Ray rule types for future edits rather than weakening them to suffixes.
    for path in sorted((source / "tags/geosite").glob("*.txt")):
        inputs.append(path)
        group = checked_tag(path.stem.lower())
        domains.setdefault(group, set())
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            fields = line.split()
            expression, attributes = fields[0], fields[1:]
            if expression.startswith("include:"):
                raise ValueError(
                    f"{path}:{number}: compile include directives into geosite.dat "
                    "before using typed mode"
                )
            if any(not attr.startswith("@") for attr in attributes):
                raise ValueError(f"{path}:{number}: invalid rule attributes")
            kind, separator, value = expression.partition(":")
            if not separator:
                expression = f"domain:{expression}"
            elif kind not in DOMAIN_TYPES.values() or not value:
                raise ValueError(f"{path}:{number}: unsupported rule {expression!r}")
            labels = {group, *(checked_tag(attr[1:].lower()) for attr in attributes)}
            for label in labels:
                domains.setdefault(label, set()).add(expression)
    return domains, inputs


def ip_rules(path: Path) -> list[str]:
    prefixes = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            prefixes.add(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: {exc}") from exc
    return [
        str(prefix)
        for prefix in sorted(
            prefixes,
            key=lambda item: (item.version, int(item.network_address), item.prefixlen),
        )
    ]


def migrate(
    source: Path,
    output: Path,
    mode: str,
    domain_tags: tuple[str, ...] = DOMAIN_TAGS,
    ip_tags: tuple[str, ...] = IP_TAGS,
) -> dict:
    source, output = source.resolve(), output.resolve()
    if output == source or source in output.parents:
        raise ValueError(
            "output must be outside the read-only smartdns-test source tree"
        )
    domain_tags = tuple(dict.fromkeys(checked_geosite_tag(tag) for tag in domain_tags))
    ip_tags = tuple(dict.fromkeys(checked_tag(tag) for tag in ip_tags))
    if mode == "runtime":
        domains, inputs = runtime_domains(source)
    elif mode == "typed":
        domains, inputs = typed_domains(source)
    else:
        raise ValueError(f"unsupported domain mode: {mode}")
    missing = sorted(set(domain_tags) - domains.keys())
    if missing:
        raise ValueError(f"domain tags absent from {mode} data: {', '.join(missing)}")

    # Prepare everything before writing, so a bad tag/address does not leave a
    # superficially complete deployment. Never unpickle geoip.radix.
    files: dict[str, list[str]] = {
        f"domains/{tag}.txt": sorted(domains[tag]) for tag in domain_tags
    }
    geosite = encode_geosite(domains, domain_tags)
    for tag in ip_tags:
        path = source / f"tags/geoip/{tag}.txt"
        files[f"ips/{tag}.txt"] = ip_rules(path)
        inputs.append(path)
    copies = {
        "Country.mmdb": source / "tags/output/geoip.metadb",
        "ASN.mmdb": source / "tags/output/asn.mmdb",
    }
    for path in copies.values():
        if not path.is_file():
            raise ValueError(f"missing MaxMind database: {path}")
        inputs.append(path)
    manifest = {
        "schema_version": 1,
        "domain_mode": mode,
        "sources": {
            str(path.relative_to(source)).replace("\\", "/"): digest(path)
            for path in sorted(set(inputs))
        },
        "outputs": {},
    }
    output.mkdir(parents=True, exist_ok=True)
    geosite_path = output / "geosite.dat"
    geosite_path.write_bytes(geosite)
    group_counts = {tag: len(domains[tag]) for tag in sorted(domain_tags)}
    manifest["outputs"]["geosite.dat"] = {
        "entries": len(group_counts),
        "groups": group_counts,
        "rules": sum(group_counts.values()),
        "sha256": digest(geosite_path),
    }
    for relative, rules in files.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(f"{rule}\n" for rule in rules), encoding="utf-8", newline="\n"
        )
        manifest["outputs"][relative] = {"rules": len(rules), "sha256": digest(path)}
    for relative, source_path in copies.items():
        path = output / relative
        shutil.copyfile(source_path, path)
        manifest["outputs"][relative] = {"sha256": digest(path)}
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../smartdns-test"))
    parser.add_argument("--output", type=Path, default=Path("data/smartdns"))
    parser.add_argument(
        "--domain-mode", choices=("runtime", "typed"), default="runtime"
    )
    parser.add_argument(
        "--domain-tag", action="append", help="override default domain tags; repeatable"
    )
    parser.add_argument(
        "--ip-tag", action="append", help="override default IP tags; repeatable"
    )
    args = parser.parse_args()
    try:
        manifest = migrate(
            args.source,
            args.output,
            args.domain_mode,
            tuple(args.domain_tag) if args.domain_tag else DOMAIN_TAGS,
            tuple(args.ip_tag) if args.ip_tag else IP_TAGS,
        )
    except (OSError, ValueError) as exc:
        parser.exit(1, f"migration failed: {exc}\n")
    count = len(manifest["outputs"])
    print(
        f"Exported {count} data files ({args.domain_mode}) to {args.output.resolve()}"
    )


if __name__ == "__main__":
    main()
