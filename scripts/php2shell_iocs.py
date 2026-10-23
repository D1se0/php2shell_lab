#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 PHP2Shell IOC Hunter — CVE-2026-109618 & CVE-2026-109619
================================================================================
 Analiza los logs de los contenedores del lab (docker logs) en busca de los
 Indicadores de Compromiso documentados para PHP2Shell:

   IOC-1  [HIGH]  Fatal de OOM durante inicialización de request
                  ("Allowed memory size ... in Unknown on line 0")
   IOC-2  [CRIT]  Segfault del worker tras el OOM
                  ("exit signal Segmentation fault") — señal de corrupción
                  de estado: comportamiento del build vulnerable
   IOC-3  [HIGH]  POST correlacionado temporalmente con un OOM fatal
                  (heurística ±2 s sobre los timestamps de Apache)
   IOC-4  [MED]   Aviso de "Input variables exceeded" (cuerpos malformados /
                  de tamaño anómalo durante el parseo)

 Modo de uso:
    python3 php2shell_iocs.py                              # ambos contenedores
    python3 php2shell_iocs.py --container php2shell-vulnerable
    python3 php2shell_iocs.py --container php2shell-vulnerable --json
    python3 php2shell_iocs.py --tail 5000                  # más histórico

 Códigos de salida:
    0  sin hallazgos     1  hallazgos (ver --json para el detalle)     2  error
================================================================================
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

TOOL = "php2shell_iocs"
VERSION = "1.0.0"

LAB_DEFAULT_CONTAINERS = ["php2shell-vulnerable", "php2shell-patched"]

# ---------------------------------------------------------------------------
# Patrones de los IOCs (error log y access log de Apache)
# ---------------------------------------------------------------------------

RE_OOM_FATAL = re.compile(
    r"PHP Fatal error:\s+Allowed memory size of (\d+) bytes exhausted "
    r"\(tried to allocate (\d+) bytes\) in Unknown on line 0"
)
RE_SEGFAULT = re.compile(
    r"AH00051: child pid (\d+) exit signal Segmentation fault \(11\)"
)
RE_MAX_INPUT_VARS = re.compile(r"Input variables exceeded (\d+)")
RE_APACHE_TS = re.compile(
    r"\[([A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]"
)
RE_ACCESS_POST = re.compile(
    r'(\S+) - - \[([^\]]+)\] "(POST) (\S+) HTTP/1\.[01]" (\d+) (\d+)'
)
TS_FORMAT = "%a %b %d %H:%M:%S.%f %Y"          # error log de Apache
ACCESS_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"        # access log de Apache

SEVERITY_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3}

# ---------------------------------------------------------------------------
# Salida con color
# ---------------------------------------------------------------------------


class Style:
    """Texto ANSI desactivable (--no-color, NO_COLOR, stdout no TTY)."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _c(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str: return self._c("1", t)
    def dim(self, t: str) -> str: return self._c("2", t)
    def red(self, t: str) -> str: return self._c("91", t)
    def green(self, t: str) -> str: return self._c("92", t)
    def yellow(self, t: str) -> str: return self._c("93", t)
    def cyan(self, t: str) -> str: return self._c("96", t)
    def magenta(self, t: str) -> str: return self._c("95", t)

    def ok(self, t: str) -> str: return self._c("92", f"[+] {t}")
    def info(self, t: str) -> str: return self._c("96", f"[*] {t}")
    def warn(self, t: str) -> str: return self._c("93", f"[!] {t}")
    def fail(self, t: str) -> str: return self._c("91", f"[x] {t}")


def banner(s: Style) -> None:
    bar = s.magenta("━" * 66)
    print(bar)
    print(f"  {s.bold('PHP2Shell IOC Hunter')}  {s.cyan('CVE-2026-109618 / CVE-2026-109619')}  {s.dim(f'v{VERSION}')}")
    print(f"  {s.dim('Detección de IOCs sobre los logs del lab · uso exclusivo autorizado')}")
    print(bar)


def rule(s: Style, title: str = "") -> None:
    if title:
        print(f"\n{s.dim(f'── {title} '.ljust(66, '─'))}")
    else:
        print(s.dim("─" * 66))


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    ioc: str
    severity: str
    container: str
    timestamp: str
    evidence: str
    line: str


@dataclass
class Report:
    containers_scanned: list[str] = field(default_factory=list)
    containers_failed: list[str] = field(default_factory=list)
    lines_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


# ---------------------------------------------------------------------------
# Adquisición de logs
# ---------------------------------------------------------------------------


def docker_available() -> bool:
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=15
        ).returncode == 0
    except FileNotFoundError:
        return False


def fetch_logs(container: str, tail: int) -> str | None:
    try:
        proc = subprocess.run(
            ["docker", "logs", "--timestamps", "--tail", str(tail), container],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 and not (proc.stdout or proc.stderr):
        return None
    return (proc.stdout or "") + (proc.stderr or "")


# ---------------------------------------------------------------------------
# Parseo
# ---------------------------------------------------------------------------


@dataclass
class Event:
    kind: str            # "oom" | "segfault" | "maxvars" | "post"
    ts: str              # timestamp Apache legible
    ts_key: int          # microsegundos desde epoch (0 si no parseable)
    text: str
    line: str
    related_oom: bool = False


def _ts_key(raw: str) -> int:
    """Timestamps de error log y access log -> microsegundos epoch (UTC).

    El error log de Apache emite timestamps NAIVE (sin zona): hay que
    anclarlos a UTC explícitamente o datetime.timestamp() los interpreta
    en la TZ local del host y la correlación temporal se rompe (offset de
    horas) frente al access log, que sí trae +0000.
    """
    fmt = ACCESS_TS_FORMAT if "/" in raw else TS_FORMAT
    try:
        dt = datetime.strptime(raw, fmt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1_000_000)
    except ValueError:
        return 0


def parse_events(logs: str) -> list[Event]:
    """Extrae eventos relevantes de un volcado de docker logs de Apache."""
    events: list[Event] = []
    # docker --timestamps anteponga '2026-10-23T09:17:23.946584600Z '
    strip_ts = re.compile(r"^\S+Z\s+")
    for raw_line in logs.splitlines():
        if not raw_line.strip():
            continue
        line = strip_ts.sub("", raw_line, count=1)

        m_ts = RE_APACHE_TS.search(line)
        ts = m_ts.group(1) if m_ts else ""
        key = _ts_key(ts) if ts else 0

        m = RE_OOM_FATAL.search(line)
        if m:
            events.append(Event(
                kind="oom", ts=ts, ts_key=key,
                text=(f"OOM fatal: limit={m.group(1)}B intentó={m.group(2)}B "
                      f"en Unknown on line 0"),
                line=line,
            ))
            continue

        m = RE_SEGFAULT.search(line)
        if m:
            events.append(Event(
                kind="segfault", ts=ts, ts_key=key,
                text=f"worker pid {m.group(1)} segfault (corrupción de estado)",
                line=line,
            ))
            continue

        m = RE_MAX_INPUT_VARS.search(line)
        if m:
            events.append(Event(
                kind="maxvars", ts=ts, ts_key=key,
                text=f"max_input_vars excedido (>{m.group(1)} variables)",
                line=line,
            ))
            continue

        m = RE_ACCESS_POST.search(line)
        if m:
            # El access log usa su propio formato de timestamp:
            # '23/Oct/2026:09:17:55 +0000' — se extrae del propio match.
            access_ts = m.group(2)
            events.append(Event(
                kind="post", ts=access_ts, ts_key=_ts_key(access_ts),
                text=f'POST {m.group(4)} → HTTP {m.group(5)} ({m.group(6)}B resp) desde {m.group(1)}',
                line=line,
            ))
    return events


def correlate(events: list[Event], window_s: float = 2.0) -> None:
    """Marca POSTs dentro de ±window_s de un OOM fatal (IOC-3)."""
    oom_keys = [e.ts_key for e in events if e.kind == "oom" and e.ts_key]
    if not oom_keys:
        return
    window_us = int(window_s * 1_000_000)
    for ev in events:
        if ev.kind != "post" or not ev.ts_key:
            continue
        if any(abs(ev.ts_key - k) <= window_us for k in oom_keys):
            ev.related_oom = True


# ---------------------------------------------------------------------------
# Escaneo
# ---------------------------------------------------------------------------


def scan_container(container: str, logs: str, report: Report) -> None:
    events = parse_events(logs)
    correlate(events)

    for ev in events:
        if ev.kind == "oom":
            report.findings.append(Finding(
                ioc="IOC-1", severity="HIGH", container=container,
                timestamp=ev.ts, evidence=ev.text, line=ev.line,
            ))
        elif ev.kind == "segfault":
            report.findings.append(Finding(
                ioc="IOC-2", severity="CRIT", container=container,
                timestamp=ev.ts, evidence=ev.text, line=ev.line,
            ))
        elif ev.kind == "post" and ev.related_oom:
            report.findings.append(Finding(
                ioc="IOC-3", severity="HIGH", container=container,
                timestamp=ev.ts,
                evidence=f"{ev.text}  [correlacionado con OOM ±2s]",
                line=ev.line,
            ))
        elif ev.kind == "maxvars":
            report.findings.append(Finding(
                ioc="IOC-4", severity="MED", container=container,
                timestamp=ev.ts, evidence=ev.text, line=ev.line,
            ))


def severity_summary(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


# ---------------------------------------------------------------------------
# Informe
# ---------------------------------------------------------------------------


def print_report(s: Style, report: Report) -> None:
    rule(s, "Resumen del escaneo")

    for c in report.containers_scanned:
        print(s.ok(f"logs leídos: {c}"))
    for c in report.containers_failed:
        print(s.fail(f"sin acceso a logs: {c}"))
    print(s.dim(f"líneas escaneadas: {report.lines_scanned}"))

    summary = severity_summary(report.findings)
    if summary:
        parts = ", ".join(
            f"{k}: {v}"
            for k, v in sorted(summary.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
        )
        print(s.bold(f"hallazgos: {parts}"))
    else:
        print(s.green("ningún IOC encontrado"))

    for f in sorted(report.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.timestamp)):
        sev_color = {"CRIT": s.red, "HIGH": s.yellow, "MED": s.cyan, "LOW": s.dim}[f.severity]
        print()
        print(f"  {sev_color(f.severity)} {s.bold(f.ioc)}  {s.dim(f'@ {f.container}')}  {s.dim(f'[{f.timestamp}]')}")
        print(f"    {s.dim('evidencia:')} {f.evidence}")

    _verdict(s, report)


def _verdict(s: Style, report: Report) -> None:
    rule(s, "Conclusión")
    has_seg = any(f.ioc == "IOC-2" for f in report.findings)
    has_oom = any(f.ioc == "IOC-1" for f in report.findings)

    if has_seg and has_oom:
        print(s.red(s.bold("  ⚠  SEÑAL DE CORRUPCIÓN CONFIRMADA (build vulnerable)")))
        print(s.dim("    OOM en request startup + segfault del worker al limpiar el estado"))
        print(s.dim("    a medias: es el par IOC-1 + IOC-2 del CVE-2026-109618."))
    elif has_seg:
        print(s.red(s.bold("  ⚠  SEGFAULTS DEL WORKER — investigar causa")))
    elif has_oom:
        print(s.yellow(s.bold("  ~  OOM DURANTE REQUEST STARTUP (sin corrupción observada)")))
        print(s.dim("    En builds parcheadas el límite blando se gestiona en punto seguro"))
        print(s.dim("    y el worker sobrevive: contrasta con el contenedor vulnerable."))
    else:
        print(s.green("  ✔  SIN SEÑALES / logs limpios"))
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description="Caza IOCs de PHP2Shell (CVE-2026-109618/109619) en los logs del lab.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Modo de uso:")[1] if "Modo de uso:" in __doc__ else None,
    )
    p.add_argument("--container", metavar="NOMBRE", default=None,
                   help=f"contenedor concreto (default: {', '.join(LAB_DEFAULT_CONTAINERS)})")
    p.add_argument("--tail", type=int, default=1000, metavar="N",
                   help="líneas de log a analizar por contenedor (default 1000)")
    p.add_argument("--json", action="store_true", help="salida JSON completa (sin decoración)")
    p.add_argument("--no-color", action="store_true", help="desactiva colores ANSI")
    args = p.parse_args(argv)

    enabled = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    args._style = Style(enabled)  # type: ignore[attr-defined]
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    s: Style = args._style  # type: ignore[attr-defined]
    if not args.json:
        banner(s)

    if not docker_available():
        print(s.fail("docker no disponible en este host"))
        return 2

    containers = [args.container] if args.container else LAB_DEFAULT_CONTAINERS
    report = Report(generated_at=datetime.now(timezone.utc).isoformat())

    for c in containers:
        logs = fetch_logs(c, args.tail)
        if logs is None:
            report.containers_failed.append(c)
            continue
        report.containers_scanned.append(c)
        report.lines_scanned += len(logs.splitlines())
        scan_container(c, logs, report)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print_report(s, report)

    if report.containers_failed and not report.containers_scanned:
        return 2
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
