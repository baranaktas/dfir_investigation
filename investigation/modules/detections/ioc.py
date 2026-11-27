"""Indicator-of-compromise matching across the whole timeline.

IOC files: one indicator per line (# comments). Hashes (MD5/SHA1/SHA256), IPv4/IPv6, URLs, domains and file
names are detected automatically; defanged forms (hxxp, [.], (.)) are accepted.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlsplit

from investigation.core.models import Event, Finding, Severity
from investigation.core.module import DetectionModule, ErrorSink, ModuleMeta, ModuleType
from investigation.core.registry import investigation_home, register
from investigation.core.requirements import Context
from investigation.core.store import EventStore

FILE_EXTENSIONS = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr", "zip", "rar", "7z", "iso", "img",
                   "lnk", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "pdf", "txt", "msi", "sys", "jar", "one"}
_DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HEX = re.compile(r"(?<![0-9a-f])[0-9a-f]{32,64}(?![0-9a-f])")
_HOSTS = re.compile(r"(?<![a-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![a-z0-9-])")
_V6_TOKEN = re.compile(r"[0-9a-f:]*:[0-9a-f:]+")
_URL = re.compile(r"[a-z][a-z0-9+.-]{1,15}://[^\s\"'<>]+")


def _url_candidates(url: str, max_len: int) -> Iterator[str]:
    """The URL and its prefixes at path/query boundaries: an IOC URL matches longer URLs under it.

    Only prefixes no longer than the longest IOC URL are produced, so hostile URLs with huge numbers of
    path segments cost O(max_len) instead of O(n^2).
    """
    url = url.rstrip(".,;)")
    if len(url) <= max_len:
        yield url
    url = url.split("#", 1)[0]
    if len(url) <= max_len:
        yield url
    path, q, query = url.partition("?")
    if q:
        j = query.find("&")
        while j != -1 and len(path) + 1 + j <= max_len:
            yield url[:len(path) + 1 + j]
            j = query.find("&", j + 1)
        if len(path) <= max_len:
            yield path
    pos = path.find("/", path.find("://") + 3)
    while pos != -1 and pos <= max_len:
        yield path[:pos]
        yield path[:pos + 1]
        pos = path.find("/", pos + 1)


def refang(s: str) -> str:
    s = s.strip()
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    return s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://")


@dataclass
class IocSet:
    hashes: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    filenames: set[str] = field(default_factory=set)
    sources: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.hashes | self.ips | self.domains | self.urls | self.filenames)

    def add(self, raw: str, source: str) -> None:
        s = refang(raw).casefold()
        if not s or " " in s:
            return
        kind = None
        if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", s):
            self.hashes.add(s)
            kind = s
        elif "://" in s:
            self.urls.add(s)
            host = urlsplit(s).hostname
            if host and _DOMAIN.fullmatch(host):
                self.domains.add(host)
            kind = s
        else:
            try:
                self.ips.add(str(ipaddress.ip_address(s)))
                kind = str(ipaddress.ip_address(s))
            except ValueError:
                if _DOMAIN.fullmatch(s) and s.rsplit(".", 1)[-1] not in FILE_EXTENSIONS:
                    self.domains.add(s)
                    kind = s
                elif "." in s and not re.search(r"[\\/]", s):
                    self.filenames.add(s)
                    kind = s
        if kind:
            self.sources.setdefault(kind, source)


def load_iocs(paths: Iterable[Path]) -> IocSet:
    iocs = IocSet()
    for p in paths:
        p = Path(p)
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                iocs.add(line, p.name)
    return iocs


class IocMatcher:
    def __init__(self, iocs: IocSet):
        self.iocs = iocs
        self._url_max = max((len(u) for u in iocs.urls), default=0)
        self._url_schemes = {u.partition("://")[0] for u in iocs.urls}

    def _rebase(self, url: str) -> Iterator[str]:
        """The URL, plus re-anchored copies when text is glued to an IOC scheme ("xhttps://" -> "https://")."""
        yield url
        scheme, _, rest = url.partition("://")
        for s in self._url_schemes:
            if len(scheme) > len(s) and scheme.endswith(s):
                yield f"{s}://{rest}"

    def _strings(self, e: Event) -> Iterator[str]:
        yield e.message
        if e.host:
            yield e.host
        for v in e.fields.values():
            if isinstance(v, str):
                yield v

    def match(self, e: Event) -> list[tuple[str, str]]:
        i = self.iocs
        found: set[tuple[str, str]] = set()
        for raw in self._strings(e):
            s = raw.casefold()
            if i.hashes:
                found |= {("hash", h) for h in _HEX.findall(s) if h in i.hashes}
            if i.ips:
                for tok in _IPV4.findall(s):
                    if tok in i.ips:
                        found.add(("ip", tok))
                if ":" in s:
                    for tok in _V6_TOKEN.findall(s):
                        try:
                            ip = str(ipaddress.ip_address(tok.strip(":") if tok.count(":") < 2 else tok))
                        except ValueError:
                            continue
                        if ip in i.ips:
                            found.add(("ip", ip))
            if i.urls and "://" in s:
                for raw_url in _URL.findall(s):
                    for url in self._rebase(raw_url):
                        found |= {("url", c) for c in _url_candidates(url, self._url_max) if c in i.urls}
            if i.domains:
                for host in _HOSTS.findall(s):
                    labels = host.split(".")
                    for k in range(len(labels) - 1):
                        suffix = ".".join(labels[k:])
                        if suffix in i.domains:
                            found.add(("domain", suffix))
            if i.filenames:
                base = re.split(r"[\\/]", s.strip().strip('"'))[-1]
                if base in i.filenames:
                    found.add(("filename", base))
        return sorted(found)


def ioc_files(ctx: Context) -> list[Path]:
    files = [Path(p) for p in ctx.options.get("ioc_files", []) or []]
    home = investigation_home() / "ioc"
    if home.is_dir():
        files += sorted(p for p in home.glob("*.txt") if p.is_file())
    return files


@register
class IocDetection(DetectionModule):
    meta = ModuleMeta(
        name="ioc",
        description="IOC matching (hashes, IPs, domains, URLs, file names) from --ioc files and ~/.investigation/ioc",
        type=ModuleType.DETECTION,
    )

    def detect(self, store: EventStore, ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        files = ioc_files(ctx)
        if not files:
            return
        iocs = load_iocs(files)
        if not iocs.count:
            return
        matcher = IocMatcher(iocs)
        hits: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for e in store.iter_events():
            for key in matcher.match(e):
                if len(hits[key]) < 500:
                    hits[key].append(e)
        for (kind, ioc), events in sorted(hits.items()):
            yield Finding(
                rule_id=f"IOC-{kind}-{ioc[:16]}",
                title=f"IOC match: {ioc}",
                severity=Severity.HIGH,
                description=f"{kind} indicator from {iocs.sources.get(ioc, 'IOC list')} seen in {len(events)} event(s)",
                mitre=(),
                events=events,
            )
