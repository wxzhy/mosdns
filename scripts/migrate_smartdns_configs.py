#!/usr/bin/env python3
"""Migrate the two repository SmartDNS profiles; run with its existing PyYAML.

This is an explicit mapping of these profiles, not a general SmartDNS compiler.
The source is read-only. Runtime mosdns needs only the YAML and exported data.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

import yaml


def endpoint(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def rule(exec_: str, *matches: str) -> dict:
    return {"matches": list(matches), "exec": exec_} if matches else {"exec": exec_}


def merge_example_services(cfg: dict, *, profile: str = "default") -> dict:
    """Merge runtime services into an existing policy without changing routing."""
    if profile not in ("default", "cernet"):
        raise ValueError(f"unknown deployment profile {profile!r}")
    merged = copy.deepcopy(cfg)
    plugins = merged["plugins"]
    by_tag = {plugin["tag"]: plugin for plugin in plugins}
    if len(by_tag) != len(plugins):
        raise ValueError("duplicate plugin tags in migrated configuration")
    cache = by_tag.get("response_cache")
    main = by_tag.get("main")
    if cache is None or cache["type"] != "cache" or main is None or main["type"] != "sequence":
        raise ValueError("migrated configuration needs response_cache and main")
    suffix = "-cernet" if profile == "cernet" else ""
    stats = by_tag.get("stats_collector")
    if stats is None:
        stats = {"tag": "stats_collector", "type": "stats_api", "args": {}}
    elif stats["type"] != "stats_api":
        raise ValueError("stats_collector is already used by another plugin type")
    stats["args"].update(
        capacity=2000, dump_file=f"/etc/mosdns/stats{suffix}.dump", dump_interval=600
    )
    cache["args"].update(
        size=20000,
        lazy_cache_ttl=86400,
        dump_file=f"/etc/mosdns/cache{suffix}.dump",
        dump_interval=600,
    )
    main["args"] = [rule("$stats_collector")] + [
        item for item in main["args"] if item != rule("$stats_collector")
    ]
    merged["plugins"] = [stats] + [p for p in plugins if p["tag"] != "stats_collector"]
    merged.setdefault("log", {}).update(level="info", file="/var/log/mosdns.log")
    merged.setdefault("api", {})["http"] = "0.0.0.0:9091"
    merged.setdefault("include", [])
    return merged


class Migration:
    def __init__(self, cfg: dict, *, profile: str = "default"):
        if profile not in ("default", "cernet"):
            raise ValueError(f"unknown deployment profile {profile!r}")
        self.cfg = cfg
        self.profile = profile
        self.plugins: list[dict] = []
        self.nameservers = {x["name"]: x for x in cfg["nameservers"]}
        self.resolvers = {x["name"]: x for x in cfg["resolvers"]}
        self.actions = {x["name"]: x for x in cfg["actions"]}
        self.leaves: dict[str, list[str]] = {}

    def add(self, tag: str, kind: str, args: dict | list) -> str:
        if any(p["tag"] == tag for p in self.plugins):
            raise ValueError(f"duplicate generated tag {tag}")
        self.plugins.append({"tag": tag, "type": kind, "args": args})
        return tag

    def sequence(self, tag: str, rules: list[dict]) -> str:
        return self.add(tag, "sequence", rules)

    @staticmethod
    def ip_expressions(match: dict, side: str) -> list[str]:
        return [f"$ip_{x}" for x in match.get(f"ip_{side}", [])] + [
            f"$ip_asn_{x}" for x in match.get(f"asn_{side}", [])
        ]

    @staticmethod
    def names(labels: list[str]) -> str:
        return " ".join(f"geosite:{x}" for x in labels)

    def name_gate(self, match: dict) -> list[dict]:
        rules = []
        if excluded := match.get("domain_exclude"):
            names = self.names(excluded)
            rules += [
                rule("return", f"qname {names}"),
                rule("return", f"cname {names}"),
            ]
        if included := match.get("domain_include"):
            names = self.names(included)
            rules += [rule("return", f"!qname {names}", f"!cname {names}")]
        if types := match.get("query_types"):
            numbers = {"A": 1, "AAAA": 28, "SVCB": 64, "HTTPS": 65}
            rules += [
                rule("return", "!qtype " + " ".join(str(numbers[x]) for x in types))
            ]
        return rules

    def providers(self) -> None:
        for label in (
            "cloudflare",
            "cloudfront",
            "fastly",
            "private",
            "facebook",
            "twitter",
        ):
            self.add(
                f"ip_{label}",
                "ip_set",
                {"ips": [f"geoip:{label}"]},
            )
        for label in ("github", "github-raw"):
            self.add(
                f"ip_{label}", "ip_set", {"files": [f"./data/smartdns/ips/{label}.txt"]}
            )
        for asn in (19679, 33191):
            self.add(
                f"ip_asn_{asn}",
                "ip_set",
                {"ips": [f"asn:{asn}"]},
            )

    def forwards(self) -> None:
        # Expand the old HTTP hosts pool into independent concurrent candidates.
        # URL, TLS SNI, HTTP Host and POST are kept separate.
        for name, ns in self.nameservers.items():
            if ns["type"] == "curl":
                host = urlsplit(ns["url"]).hostname
                targets = self.cfg["client"].get("hosts", {}).get(host, [None])
                options = {
                    "addr": ns["url"],
                    "http_host": ns.get("host", host),
                    "http_method": "GET" if ns.get("want_get", False) else "POST",
                    "insecure_skip_verify": not ns.get("verify", True),
                }
                if ech := ns.get("ech"):
                    resolver = self.cfg["client"]["resolver"]["nameservers"][0]
                    options["ech_config_list"] = f"{ech}+udp://{endpoint(resolver, 53)}"
                # The old implicit ech:true is opportunistic libcurl DNS-ECH.
                # Fixed-source fail-closed ECH is not a substitute; see the guide.
                if fingerprint := ns.get("fingerprint", "chrome"):
                    options["fingerprint"] = fingerprint
            else:
                targets = [None]
                options = {
                    "addr": f"{ns['type']}://{endpoint(ns['address'], ns.get('port', 53))}"
                }
                for key in ("repeat", "use_tricks"):
                    if key in ns:
                        options[key] = ns[key]
            tags = []
            for i, target in enumerate(targets, 1):
                upstream = dict(options)
                if target:
                    upstream["dial_addr"] = endpoint(
                        target, urlsplit(ns["url"]).port or 443
                    )
                tags.append(
                    self.add(
                        f"upstream_{name}_{i}", "forward", {"upstreams": [upstream]}
                    )
                )
            self.leaves[f"ns:{name}"] = tags
        for name, resolver in self.resolvers.items():
            if resolver["type"] == "aiodns":
                protocol = "tcp" if resolver.get("tcp") else "udp"
                self.leaves[name] = [
                    self.add(
                        f"upstream_{name}_{i}",
                        "forward",
                        {"upstreams": [{"addr": f"{protocol}://{endpoint(host, 53)}"}]},
                    )
                    for i, host in enumerate(resolver["nameservers"], 1)
                ]
            elif resolver["type"] == "plain":
                self.leaves[name] = [
                    tag
                    for ns in resolver["nameservers"]
                    for tag in self.leaves[f"ns:{ns}"]
                ]

    def policies(self) -> None:
        for name in ("block", "proxy"):
            action = self.actions[name]
            addresses = action.get("ipv4", ["127.0.0.1"]) + action.get("ipv6", ["::1"])
            self.sequence(
                f"static_{name}",
                [
                    rule("black_hole " + " ".join(addresses)),
                    rule(f"ttl {action.get('ttl', 86400)}", "has_resp"),
                    rule("accept", "has_resp"),
                    rule("reject 0"),
                ],
            )
        for name, action in self.actions.items():
            if action["type"] != "replace":
                continue
            tag = "replace_cdn" if name == "replace" else f"replace_{name}"
            replacements = []
            for item in action["replace_map"]:
                replacements.append(
                    {
                        "match_ip": self.ip_expressions(item["match_ip"], "include"),
                        "exclude_ip": self.ip_expressions(item["match_ip"], "exclude"),
                        "ipv4_prefixlen": item.get("ipv4_prefixlen", 32),
                        "ipv6_prefixlen": item.get("ipv6_prefixlen", 128),
                        "ipv4": item.get("ipv4", []),
                        "ipv6": item.get("ipv6", []),
                    }
                )
            self.add(tag, "ip_replace", {"replace_map": replacements})
            self.sequence(
                f"apply_{name}",
                self.name_gate(action["match_name"]) + [rule(f"${tag}")],
            )
        filter_rules = []
        for i, item in enumerate(self.actions["filter"]["filters"], 1):
            forbidden = " ".join(self.ip_expressions(item["match_ip"], "exclude"))
            gate = self.name_gate(item["match_name"]) + [
                rule("drop_resp", f"resp_ip {forbidden}")
            ]
            tag = self.sequence(f"filter_item_{i}", gate)
            filter_rules += [rule(f"${tag}"), rule("return", "!has_resp")]
        self.sequence("filter_response", filter_rules)
        fallback = self.actions["fallback"]["map"]
        if len(fallback) != 1:
            raise ValueError("these profiles expect one fallback rule")
        item = fallback[0]
        self.add(
            "fallback_google",
            "ip_fallback",
            {
                "ipv4": item.get("ipv4", []),
                "ipv6": item.get("ipv6", []),
                "ttl": item.get("ttl", 86400),
                "on": ["all_probes_failed", "nodata"],
            },
        )
        self.sequence(
            "apply_fallback",
            self.name_gate(item["match_name"]) + [rule("$fallback_google")],
        )

    def selectors(self) -> None:
        speed = self.actions["speedcheck"]
        ping = speed.get("ping_config", {})
        # Probe/label/multiplier 配置对每组相同：共享同一对象，YAML 输出
        # 锚点与别名，避免三个 selector 重复十几行完全一致的参数。
        labels = {"private": ["$ip_private"]}
        weights = []
        for label, multiplier in speed.get("tag_multipliers", {}).items():
            labels[label] = [f"$ip_{label}"]
            weights.append({"tag": label, "multiplier": multiplier})
        probe = {
            "tcp_ports": ping.get("port") or [],
            "icmp": ping.get("ping", True),
            "timeout": f"{round(ping.get('timeout', 0.3) * 1000)}ms",
        }
        asn_multipliers = speed.get("asn_multipliers", {})
        probe_match = {
            "labels_exclude": speed["match_ip"].get("ip_exclude", []),
        }
        for group in ("cn", "global", "default"):
            resolver = self.resolvers[group]
            sources = []
            for leaf in resolver["resolvers"]:
                for i, upstream in enumerate(self.leaves[leaf], 1):
                    rules = [rule(f"${upstream}")]
                    for action in resolver.get("actions", []):
                        if action == "speedcheck":
                            continue
                        if action not in ("filter", "replace", "twitter"):
                            raise ValueError(f"unsupported source action {action}")
                        target = (
                            "filter_response"
                            if action == "filter"
                            else f"apply_{action}"
                        )
                        rules += [rule(f"${target}"), rule("return", "!has_resp")]
                    sources.append(self.sequence(f"source_{group}__{leaf}__{i}", rules))
            self.add(
                f"select_{group}",
                "speedcheck",
                {
                    "sources": sources,
                    "mode": "wait_all"
                    if resolver.get("wait_all", False)
                    else "bounded",
                    "total_timeout": f"{resolver['timeout']}s",
                    "selection_timeout": "300ms",
                    "settle_window": "25ms",
                    "probe": probe,
                    "max_num": speed.get("max_num", 1),
                    "threshold_ms": speed.get("threshold", 100),
                    "labels": labels,
                    "tag_multipliers": weights,
                    "asn_multipliers": asn_multipliers,
                    "probe_match": probe_match,
                },
            )

    def forward_pool(self, tag: str, leaves: list[str]) -> str:
        # Non-speedchecked DNS pools may choose the first usable complete reply.
        by_tag = {p["tag"]: p for p in self.plugins}
        upstreams = [dict(by_tag[x]["args"]["upstreams"][0]) for x in leaves]
        return self.add(
            tag, "forward", {"concurrent": len(upstreams), "upstreams": upstreams}
        )

    def routes(self) -> None:
        google = self.resolvers["google-cn"]
        subnet = ipaddress.ip_network(google["ecs"], strict=False)
        self.add(
            "google_ecs",
            "ecs_handler",
            {
                "forward": False,
                "send": False,
                "preset": str(subnet.network_address),
                "mask6": subnet.prefixlen,
            },
        )
        self.forward_pool("upstream_google_cn", self.leaves["google-cn"])
        self.forward_pool("upstream_opennic", self.leaves["opennic"])
        for tag, upstream, mark in (
            ("google_cn", "upstream_google_cn", 3),
            ("cn", "select_cn", 4),
            ("global", "select_global", 5),
            ("opennic", "upstream_opennic", 6),
            ("default", "select_default", 7),
        ):
            rules = [rule(f"mark {mark}")]
            if tag == "google_cn":
                rules.append(rule("$google_ecs"))
            rules.append(rule(f"${upstream}"))
            if tag in ("global", "default"):
                rules.append(rule("$apply_fallback"))
            self.sequence(f"route_{tag}", rules)
        self.sequence("route_block", [rule("mark 1"), rule("$static_block")])
        self.sequence("route_proxy", [rule("mark 2"), rule("$static_proxy")])
        tags = {
            "ads": "block",
            "proxy": "proxy",
            "google": "google_cn",
            "rule1": "cn",
            "rule3": "global",
            "opennic": "opennic",
            "default": "default",
        }
        rules = []
        for route in self.cfg["routing"]:
            match = route.get("matcher", {})
            matches = []
            if included := match.get("domain_include"):
                matches.append(f"qname {self.names(included)}")
            if types := match.get("query_types"):
                matches.append(
                    "qtype " + " ".join({"A": "1", "AAAA": "28"}[x] for x in types)
                )
            rules += [
                rule(f"$route_{tags[route['name']]}", *matches),
                rule("accept", "has_resp"),
            ]
        self.sequence("resolve_base", rules)
        self.add(
            "response_cache",
            "cache",
            {"size": self.cfg.get("cache_size", 10000), "lazy_cache_ttl": 0},
        )
        self.sequence(
            "resolve_cached",
            [
                rule("$response_cache"),
                rule("accept", "has_resp"),
                rule("$resolve_base"),
            ],
        )

    def https_and_listeners(self) -> None:
        self.forward_pool("ech_lookup", self.leaves["114dns"])
        self.add(
            "https_cleanup",
            "https_record",
            {
                "remove_hint": True,
                "remove_h3": True,
                "add_ech": False,
                "enable_subquery": False,
            },
        )
        for name, action in self.actions.items():
            if action["type"] != "https":
                continue
            args = {
                "remove_hint": action.get("remove_hint", True),
                "remove_h3": action.get("remove_h3", True),
                "add_ech": action.get("add_ech", True),
                "enable_subquery": action.get("enable_subquery", True),
                "ech_source": "ech_lookup",
                "ech_domain": action.get("ech_domain", "crypto.cloudflare.com"),
                "ip_source": "resolve_cached",
                "match_ip": self.ip_expressions(action["match_ip"], "include"),
                "timeout": "500ms",
            }
            tag = name.replace("-", "_")
            self.add(f"process_{tag}", "https_record", args)
            self.sequence(
                f"inject_{tag}",
                self.name_gate(action["match_name"]) + [rule(f"$process_{tag}")],
            )
            # In the legacy action name gates affect injection, not hint/H3 cleanup.
            self.sequence(
                f"apply_{tag}", [rule(f"$inject_{tag}"), rule("$https_cleanup")]
            )
        rules = [
            rule("$response_cache"),
            rule("accept", "has_resp"),
            rule("$resolve_base"),
            rule("accept", "!rcode 0"),
        ]
        marks = {"google": 3, "rule1": 4, "rule3": 5, "default": 7}
        for route in self.cfg["routing"]:
            for action in route.get("after", []):
                if action.startswith("https"):
                    rules.append(
                        rule(
                            f"$apply_{action.replace('-', '_')}",
                            "qtype 64 65",
                            f"mark {marks[route['name']]}",
                        )
                    )
        self.sequence("main", rules)
        for listener in self.cfg["listeners"]:
            host = listener.get("host", "::")
            args = {"entry": "main", "listen": endpoint(host, listener["port"])}
            if listener["type"] == "tcp":
                args["idle_timeout"] = listener.get("timeout", 5)
            self.add(f"dns_{listener['type']}", f"{listener['type']}_server", args)

    def run(self) -> dict:
        self.providers()
        self.forwards()
        self.policies()
        self.selectors()
        self.routes()
        self.https_and_listeners()
        return merge_example_services({
            "log": {"level": "info"},
            "geodata": {
                "geosite": "./data/smartdns/geosite.dat",
                "geoip": "./data/smartdns/Country.mmdb",
                "asn": "./data/smartdns/ASN.mmdb",
            },
            "plugins": self.plugins,
        }, profile=self.profile)


def render_config(cfg: dict) -> str:
    """Add comments to the normal YAML dump without changing its policy graph."""
    comments = {
        "stats_collector": (
            "示例基础功能：仅在主入口最前方统计，包含缓存命中；不统计 HTTPS 辅助查询。\n"
            "正常关闭及定时转储保留统计，普通/CERNET 使用各自文件，避免切换配置时混用。"
        ),
        "ip_cloudflare": (
            "IP 集合保留原标签：GeoIP/ASN 使用上面的默认库；GitHub 两个自定义集合仍读原导出文本。"
        ),
        "static_block": (
            "静态路由：A/AAAA 返回配置地址；其他类型保持 NOERROR/NODATA。\n"
            "black_hole 后的 has_resp/accept 与 reject 0 不能省略，否则会继续落到其他路由。"
        ),
        "replace_cdn": (
            "CDN 替换保留 replace_map 原顺序，GitHub raw 的例外须先于 Fastly 的宽泛集合。\n"
            "Fastly 的 IPv4 /22、IPv6 /64 替换保留主机位，不能改成逐地址的 /32、/128。"
        ),
        "filter_response": (
            "命中过滤条件时丢弃整份响应，不是仅删去一个地址；名称豁免同时检查 qname/CNAME。\n"
            "每项过滤后保留 !has_resp 返回，阻止被丢弃的候选继续参与替换和测速。"
        ),
        "fallback_google": (
            "固定地址兜底仅接受 all_probes_failed 或合法 NODATA。\n"
            "unmeasured（未启动、取消或不支持）不等于测速失败；NXDOMAIN 也不等于 NODATA。"
        ),
        "apply_fallback": (
            "名称包含/排除门控保持原顺序，同时检查 qname 和 CNAME；仅在对应路由完成选择后调用。"
        ),
        "upstream_google_cn": (
            "非测速上游池：forward 并发竞速，取第一份完整应答，不做逐候选测速；\n"
            "route_google_cn 先调用 google_ecs 注入 ECS，再查询此池。"
        ),
        "google_ecs": (
            "以下路由保留原 ECS 设置、标记和上游选择方式。\n"
            "标记编号：1=block 2=proxy 3=google-cn 4=cn 5=global 6=opennic 7=default；\n"
            "main 依据这些标记为 SVCB/HTTPS 查询选择对应的后处理动作。"
        ),
        "resolve_base": (
            "保留原分流顺序：广告 → proxy（A/AAAA）→ google-cn → 国内 → 全局 → OpenNIC → 默认。\n"
            "每段 has_resp 后立即 accept；合法 NXDOMAIN 也是响应，不能按“没有地址”继续落入默认路由。"
        ),
        "response_cache": (
            "复用迁移配置原有的共享缓存，合入示例的容量、lazy 保留期及持久化。\n"
            "普通/CERNET 使用不同转储文件；过期命中以 TTL 5 秒返回并后台刷新。\n"
            "cache 会包裹后续链，在链执行完后保存最终响应，包括 HTTPS 后处理结果。"
        ),
        "resolve_cached": (
            "HTTPS 的辅助 A 查询复用缓存和完整分流、过滤、替换、测速链。\n"
            "此入口不执行 main 的 HTTPS 后处理，避免递归；也不能直接改成裸 forward 绕过策略。"
        ),
        "ech_lookup": "ECH 查询使用独立上游池，与辅助 IP 解析的完整策略链分开。",
        "https_cleanup": (
            "HTTPS 名称门控控制注入和辅助查询；即使跳过它们，后面的 hint/H3 清理仍执行。\n"
            "因此 inject_* 与 apply_* 两层不能直接合并成同一个带名称条件的动作。"
        ),
        "main": (
            "总入口：先统计，再查共享缓存，未命中按原策略分流；非 NOERROR 响应不执行 HTTPS 后处理。\n"
            "SVCB/HTTPS 按原路由标记执行对应动作，保留各条规则及其顺序；缓存命中不重复处理。"
        ),
        "dns_tcp": "TCP/UDP 监听器共用 main，监听地址和端口保留原配置。",
    }
    # 按前缀在首个匹配的插件前插入一次说明，覆盖成组的重复插件。
    first_tag_comments = {
        "upstream_": (
            "上游连接：addr 中的 URL 主机名用于 TLS SNI，dial_addr 只改变拨号目标；\n"
            "http_host 只改变 HTTP Host，http_method 保留原 GET/POST，三者不能互相替代。\n"
            "同一服务的多个地址按 dial_addr 展开为独立候选，避免在测速前提前丢掉其他可用响应。"
        ),
        "source_": (
            "source_<路由组>__<上游组>__<序号>：候选来源保持各 resolver 的原动作顺序，\n"
            "即 上游应答 →（按原配置）全响应过滤 → CDN 替换 → 其他替换，随后交给同组 selector。\n"
            "任一步之后无响应立即 return 结束该候选，不对原地址先测速。"
        ),
        "select_": (
            "各组 selector 保留原候选顺序、mode 和超时；不能用先选一份响应的 forward 池代替。\n"
            "probe/labels/倍率配置以锚点共享；修改锚点影响其引用，单组调整时先展开对应别名。\n"
            "private 只豁免探测，不代表丢弃该地址；其余地址在过滤和替换完成后才进入测速。"
        ),
        "apply_": (
            "替换门控：豁免名单同时检查 qname 和 CNAME，仅 A/AAAA（1/28）参与地址替换；\n"
            "各名单内容与先后顺序均取自原配置。"
        ),
        "process_": (
            "HTTPS 后处理参数：match_ip 门控注入对象（应答地址命中这些集合才注入 ECH）。\n"
            "add_ech 开启且满足注入条件时，ech_source 通过独立上游池查询 ech_domain。\n"
            "enable_subquery 另行控制辅助 A 查询；ip_source 使用 resolve_cached 完整策略链。"
        ),
    }
    rendered = []
    seen: dict[str, bool] = {}
    for line in yaml.safe_dump(
        cfg, sort_keys=False, allow_unicode=True, width=110
    ).splitlines():
        comment = None
        if line == "geodata:":
            comment = (
                "域名直接使用 geosite:标签，默认库为导出的 runtime 兼容 bundle。\n"
                "不要用原始 GeoSite dat 替换它而声称匹配语义不变；typed 模式是另行选择的语义调整。"
            )
        elif line.startswith("- tag: "):
            tag = line.removeprefix("- tag: ")
            comment = comments.get(tag)
            if comment is None:
                for prefix, text in first_tag_comments.items():
                    if tag.startswith(prefix) and not seen.get(prefix):
                        seen[prefix] = True
                        comment = text
                        break
        if comment:
            rendered.append("")
            rendered.extend("# " + text for text in comment.splitlines())
        rendered.append(line)
    return "\n".join(rendered) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../smartdns-test"))
    parser.add_argument("--output", type=Path, default=Path("examples/smartdns"))
    parser.add_argument(
        "--merge-existing", action="store_true",
        help="merge example runtime services into existing output YAML, preserving its policy",
    )
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output == source or output.is_relative_to(source):
        parser.error("output must not be inside the read-only source tree")
    generated = []
    for name in ("config.yaml", "config-cernet.yaml"):
        profile = "cernet" if name == "config-cernet.yaml" else "default"
        if args.merge_existing:
            text = (output / name).read_text(encoding="utf-8")
            # Preserve the recorded source provenance rather than replacing it
            # with a possibly changed sibling SmartDNS checkout.
            prefix = []
            for line in text.splitlines(keepends=True):
                if not line.startswith("#"):
                    break
                prefix.append(line)
            generated.append((name, "".join(prefix) + render_config(
                merge_example_services(yaml.safe_load(text), profile=profile)
            )))
            continue
        raw = (source / name).read_bytes()
        cfg = Migration(yaml.safe_load(raw), profile=profile).run()
        header = (
            f"# 由 smartdns-test/{name} 迁移而来；源文件 SHA256 {hashlib.sha256(raw).hexdigest()}\n"
            "# 由 scripts/migrate_smartdns_configs.py 生成；说明见 docs/smartdns-migration.md。\n"
            "# 需先导出 data/smartdns，再从 mosdns 仓库根目录启动。\n"
            "# 包含原私有部署端点；对外分享前先审查。\n"
            "# 仅 ICMP 探测保留旧配置行为；启动时检查能力，权限要求取决于平台与系统策略。\n"
        )
        generated.append(
            (
                name,
                header + render_config(cfg),
            )
        )
    output.mkdir(parents=True, exist_ok=True)
    for name, text in generated:
        (output / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"Generated {name}")


if __name__ == "__main__":
    main()
