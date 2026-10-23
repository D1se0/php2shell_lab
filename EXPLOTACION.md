# 💥 Guía de Explotación — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

> **Qué logra este documento:** explicar **fase a fase, con dibujos y sin magia**, cómo se pasa de "un POST multipart que parece inofensivo" a **ejecutar comandos como `www-data` dentro del servidor**, sobre la imagen oficial `php:8.5.11-apache`, con las mismas herramientas y metodología que usaron los investigadores.
>
> Es la guía para el vídeo: `README.md` cuenta qué hay en el repo, `WRITEUP.md` cuenta el análisis técnico, y **este documento cuenta la historia de la explotación** — por qué existe cada fase, qué harías a mano sin herramientas, y qué evidencia deja cada paso.
>
> ⚠️ **USO EXCLUSIVO EN ENTORNO AISLADO DE LABORATORIO** (contenedor propio, solo loopback). Ejecutar esto contra sistemas ajenos es ilegal.

---

## 0. El mapita mental: tres capas, dos cadenas

```
┌──────────────────────────────────────────────────────────────────────────┐
│ CAPA 1 — BUG DE PARSING (CVE-2026-109619: amplificación de memoria)      │
│                                                                          │
│   Un POST multipart hace que PHP reserve ~52x más memoria de la que      │
│   viaja por el cable. Con 2.57 MB de cuerpo y memory_limit=128M          │
│   (el default), PHP pide >128M → agotamiento → fatal error OOM           │
│   DENTRO del parseo del POST, en pre-RINIT.                              │
│                                                                          │
│   Lo crucial: el worker SOBREVIVE (mod_php) y el estado de sesión        │
│   queda a MEDIO CONSTRUIR — el "poso" corrupto.                          │
│                                                                          │
│ CAPA 2 — CORRUPCIÓN DE MEMORIA (CVE-2026-109618: use-after-free)         │
│                                                                          │
│   El OOM a mitad de inicialización deja estructuras publicadas pero      │
│   sin terminar (punteros sin asignar, referencias colgando).             │
│                                                                          │
│ CAPA 3 — EJECUCIÓN (el "fire")                                           │
│                                                                          │
│   El siguiente POST esculpe el heap para reclamar el poso con datos      │
│   atacantes → se interpretan como punteros → el destructor de zval       │
│   termina llamando a system("comando del atacante").                     │
└──────────────────────────── terminal: RCE como www-data ─────────────────┘
```

Dos cadenas explotan ese poso de forma distinta (y las dos están en el repo):

| | **Chain A — stale bucket** | **Chain B — dangling reference** |
|---|---|---|
| Poso | bucket de HashTable publicado sin inicializar | `PS(id)`/`PS(http_session_vars)` colgando de una `zend_reference` muerta |
| Allocator | tracked/system (`USE_ZEND_ALLOC=0`, no default) | **default** (Zend MM, el de producción) |
| Calibración | gdb (laboratorio) | **ninguna — todo por HTTP** |
| Terminal | libc `system()` (direcciones gdb-calibradas) | `zif_system` @ `libphp+0x5996e0` (sin libc) |
| Fiabilidad | 12/12 fires, 8 generaciones ASLR | 2/3–3/3 **por generación ASLR** |
| En este repo | `make rce-reproduce` | `make rce CMD="..."` |

> **¿Por qué Chain A cambia el allocator?** No es trampa: es **cirugía**. Con Zend MM (el default), todo el parseo se sirve del mismo pool y el atacante no controla qué bloque reclama el poso. Con tracked/system, cada `_emalloc` se sirve directo del sistema y los autores pueden colocar cada pieza en su dirección exacta — así *prueban el mecanismo* limpiamente. Chain B es la demo de que **no hace falta quirófano**: con suficiente spray sobre el allocator por defecto, el poso también se reclama con contenido 100% atacante. De ahí que las dos cadenas tengan veredictos distintos: Chain A es "Proven" en el marco asistido de laboratorio; Chain B (con el leak in-band) es la demostración remota pura.

---

## 1. FASE 1 — El trigger: la amplificación 52x (por qué cae cualquier `memory_limit`)

**El problema del parser RFC1867** (el de `multipart/form-data`): PHP guarda los nombres de campo con una estrategia de crecimiento fija — cada "salto" de `smart_str` reserva `SMART_STR_START_SIZE` = **256 bytes**, aunque el nombre viaje en 6 bytes de cable.

**La amplificación** (linaje: Calif Research → reconciliación del 2026-10-21): cabeceras cortas repetidas `X: a` (6 bytes en el cable) que PHP guarda con buffer fijo de 256 B → **~314 B de memoria por 6 B de cable ≈ 52x**. Medido por bisección exacta del umbral de OOM en 8.5.11, e idéntico en 7.4.33 / 8.1.34 / 8.4.26:

| memory_limit | cuerpo mínimo para OOM | amplificación |
|---|---|---|
| 8M | 153 KB | 54.8x |
| 32M | 636 KB | 52.8x |
| **128M (default)** | **2.57 MB** | **52.3x** |
| 256M | 5.14 MB | 52.2x |

**Consecuencia demoledora:** todos los cuerpos caben dentro del `post_max_size=8M` por defecto. La barrera práctica "no acepto POSTs de 24 MB" **no protege**: 2.57 MB bastan contra el default. Y con framing **chunked** se salta incluso el pre-check de `Content-Length` (8.85 MB parseados y OOM'ados donde el mismo cuerpo con Content-Length era rechazado).

> **Para el vídeo:** aquí está la gracia del CVE-109619. No es "un POST grande tumba el server" (eso siempre ha sido posible). Es "un POST *pequeño* gasta memoria *grande*", y el OOM cae en un sitio concreto del código: **pre-RINIT**, con la sesión a medio construir. Ese "sitio concreto" es lo que convierte un OOM vulgar en un use-after-free explotable.

El parche 8.5.12 cierra esto con dos medidas: filtrado de cabeceras desconocidas y **enforcement en streaming** de `post_max_size` (cuenta los bytes a medida que llegan, no al final).

---

## 2. FASE 2 — El poso: qué deja roto el OOM

Cuando el parser golpea `memory_limit` en pre-RINIT, PHP hace un *bailout* — pero las estructuras del medio-paso quedan así:

**Chain A (stale bucket):** el bailout deja una HashTable con un **bucket publicado pero sin inicializar**. En el shutdown, PHP recorre la tabla y consume ese bucket como si fuera un `zval` legítimo → zval falso → array falso → **`pDestructor`** (el puntero-a-función que limpia cada elemento) se invoca con datos atacantes.

**Chain B (dangling reference):** el OOM en pre-RINIT deja **`PS(http_session_vars)` apuntando a una `zend_reference` liberada**. Un string vivo de 31 bytes reclama su hueco. Cuando el código de sesión usa esa referencia, el puntero `zend_array*` dentro de lo que ahora es un string atacante se lee como un array → en `zend_hash_destroy`, el **`pDestructor`** del array falso se invoca → `zif_system`.

**La clave conceptual para explicar en cámara:** `pDestructor` es el puntero interno que PHP usa para *limpiar* elementos de un array. Si engañas a PHP haciéndole creer que tu string atacante es un array, el destructor ejecutará **la función que tú pongas en ese campo**. Chain B apunta esa función al símbolo `zif_system` ya cargado en `libphp.so` — no hace falta ni libc ni shellcode: **reutiliza código legítimo del proceso** (return-to-libc de manual, versión "ret2-php").

---

## 3. FASE 3 — El leak in-band: cómo el atacante se PASA las direcciones

En ASLR, las direcciones de `libphp.so` y del heap cambian en cada arranque. Un exploit que necesita punteros **no sabe qué escribir**... a menos que pueda **leerlos antes**. La contribución más elegante del exploit remoto es el **leak in-band**: PHP mismo entrega las direcciones al atacante en una cookie. Dos pasos:

### 3.1 Leak-A — armar la sesión corrupta (el "setup")

Secuencia exacta (desde un solo host HTTP):

1. **Variable 1001**: se envían 1000 variables normales + 1. La 1001 dispara `max_input_vars` → el handler corta y marca `headers_sent=1`.
2. **Cookie vacía**: un `PHPSESSID` vacío hace que `reset_id` falle → el flag `send_cookie` queda a 1 (PHP intentará escribir Set-Cookie más adelante).
3. **El OOM gigante**: un campo de 24 MiB (o el equivalente amplificado) provoca el OOM fatal **pre-RINIT** — con la sesión ya "armada" pero sin terminar. El worker sobrevive con `PS(id)` colgando.

### 3.2 Leak-B — la divulgación (el "read")

El POST siguiente incluye un **array de 257 elementos** cuyo `zend_array` se coloca deliberadamente en el hueco de `PS(id) − 0x10`. Al leer la longitud del string de sesión, PHP interpreta el campo `nTableSize` del array falso como longitud → **512 bytes de memoria contigua** se vuelcan en la cookie:

```
Set-Cookie: PHPSESSID=<512 bytes URL-encoded de memoria cruda>
```

Dentro de esos 512 bytes, la herramienta decodifica con votación por mayoría:

- **`pDestructor`** → resta el offset conocido (`ZVAL_PTR_DTOR`) → **base de `libphp.so`**
- **9 punteros `arData`** → máscara 2MiB + mayoría → **base del chunk del heap**

> **Para el vídeo:** el detalle que suele sorprender es que el **delta** chunk−libphp **no es constante entre generaciones** (se han medido −0x1a00000 / +0x3600000 / −0x1c00000). Eso significa que el leak es **load-bearing** — sin él, el exploit no puede funcionar; no es cosmético. También significa que cada boot es una "lotería": si el delta de esa generación no encaja en la ventana de plausibilidad, la herramienta lo rechaza y reintenta con contenedor fresco (nunca "adivina").

### 3.3 El fire — del puntero al comando

Con las bases en la mano, el POST final construye el array falso con `pDestructor = zif_system = libphp_base + 0x5996e0` y su payload en el nombre del campo. Al destruirse el array falso, `zend_hash_destroy` invoca `zif_system("cmd")` — **el comando se ejecuta como `www-data` y el resultado se escribe al fichero de prueba en el docroot** (el exploit redirige la salida, p. ej. `id>o`).

```
┌─ host del atacante ─┐          ┌─ php:8.5.11-apache (worker prefork) ──────┐
│  POST Leak-A        │ ───────► │ OOM pre-RINIT → PS(id) colgando (poso)    │
│  POST Leak-B        │ ───────► │ zend_array falso en PS(id)-0x10           │
│  ◄─ Set-Cookie 512B ─┤          │ memoria cruda: pDestructor + arData ×9    │
│  POST FIRE          │ ───────► │ array falso → zend_hash_destroy →          │
│                     │          │   zif_system("id>o")  ← ¡RCE!             │
│  GET /o             │ ───────► │ uid=33(www-data) gid=33(www-data) ...     │
└─────────────────────┘          └───────────────────────────────────────────┘
```

---

## 4. Las dos rutas que este lab reprodujo (y cómo elegir una)

### 4.1 Ruta canónica — `make rce-reproduce` (Chain A, lab-asistida) ✅ RECOMENDADA PARA EL VÍDEO

Es la **receta oficial de los autores** (`scripts/reproduce.sh` del repo vendido): levanta su contenedor dedicado (`php-10961x-poc-8511`, imagen fijada por digest), ejecuta gdb **solo para calibrar direcciones**, y lanza la escalera completa de control (abort / marker / negative). Resultado obtenido en esta máquina:

```json
{
  "verdict": "Proven - Lab-Assisted RCE",
  "passed": true,
  "php": "8.5.11",
  "image": "php@sha256:974e3a92…bccf101",
  "gates": { "…19/19 en verde…": true },
  "marker_token": "RCE_20261023T105556Z",
  "marker_path": "/tmp/php-rce-lab"
}
```

**Qué hace en 4 pasos internos** (para narrar): (1) arranca el contenedor con el entorno exacto (`USE_ZEND_ALLOC=0`, `USE_TRACKED_ALLOC=1`, `memory_limit=16M`); (2) gdb lee las direcciones vivas de `system()` en el worker; (3) el POST multipart aborta con OOM y deja el poso; (4) el POST de disparo esculpe el bucket y **el token aparece en `/tmp/php-rce-lab` dentro del contenedor** — la prueba material de ejecución. El caso "negative" corre la misma danza contra el worker **parcheado** (8.5.12) y **no** produce nada (control negativo).

**Boundary honesto** (escrito por los propios autores en el VERDICT): *"This run does not prove a portable ASLR-independent exploit, default-allocator RCE, universal PHP-version impact…"*. Es un RCE probado **en el marco asistido de laboratorio**. Para la demo en vídeo es perfecto: determinista, con evidencia forense (`runs/*/VERDICT.json`, `SHA256SUMS`), y es exactamente la metodología de divulgación responsable.

### 4.2 Ruta stock — `make rce CMD="id"` (Chain B + leak in-band, remoto puro)

La experiencia "exploit real": HTTP nada más, config por defecto de la imagen, sin gdb. En este lab **funcionó end-to-end** (`uid=33(www-data)` ejecutado vía `zif_system`), con matices operativos que aprendimos a base de debugging y que son **oro para el vídeo**:

1. **Fiabilidad por generación ASLR**: cada arranque del worker es una "tirada". El bucle de reintentos del Makefile levanta un **contenedor fresco por intento** (nueva generación) — así las generaciones malas se absorben. Documentado por el autor: 2/3–3/3 por generación.
2. **La geometría del heap es sagrada**: descubrimos que **cualquier request HTTP previo** —¡incluso servir un JSON estático!— desplaza la geometría del heap que la fase de fire espera. Por eso el wrapper hace el preflight **vía docker** (sin red) y la cadena corre contra el worker recién nacido, sin tocarlo antes.
3. **Un solo fire por contenedor**: cada fire fallido segfaultea el worker y **contamina** el estado para los siguientes. La secuencia ganadora es: leak(s) limpios → **un** fire con las bases explícitas.
4. **Ventana de plausibilidad del leak**: la herramienta acepta `delta ∈ [0x1A00000, 0x1F00000]`; si el boot da un delta fuera, lo rechaza y reintenta (no adivina — buen ejemplo de higiene de exploit).
5. **Integridad de veredictos**: si la prueba (`o` en el docroot) ya existe de una tirada anterior, el tool **se niega a re-disparar** ("refusing a stale verdict") — el wrapper la limpia antes de cada intento.

> **Para el vídeo:** la narrativa honesta es "esto es una lotería controlada: cada intento = nueva generación ASLR; el bucle automatiza la tirada hasta que el delta y el heap alinean". El propio repo del autor documenta la fiabilidad por generación; pretender un "one-click 100%" sería vender humo.

---

## 5. Después del parche: 8.5.12 cierra los CVEs… pero deja grietas

Verificado por el autor sobre un build 8.5.12 ASAN con fuente GPG-verificada:

| # | Grieta | Estado en 8.5.12 |
|---|---|---|
| 1 | **var_destroy re-entry UAF** (CWE-416) | idéntica a 8.5.11 (fault en `var_unserializer.c:906`); los guards `ZEND_HAS_OOM` del parche son inertes en esa ruta |
| 2 | **Serialize-handler mismatch** | `php_serialize` escribe `|`, el handler `php` lo decodifica → gadget instanciado en mod_php `php_value` y FPM `.user.ini` |
| 3 | **Upload-progress injection** | clave controlada por el atacante, guardada verbatim en el fichero de sesión |

Y en **FPM**: el stale `BG(unserialize)` tras OOM de sesión (24 MB @ 32M) **sobrevive al request** y persiste en el siguiente — crash repeatable del worker (DoS) + primitiva de corrupción, pero RCE más allá del crash **no probado**. Mensaje: *"FPM protegido" es condición, no garantía*.

---

## 6. Defensa (tabla de mitigaciones, del repo de xuehuolll)

| Mitigación | Efecto |
|---|---|
| **Parchear a ≥ 8.5.12** | cierra los dos CVEs (no las 3 grietas de arriba) |
| `memory_limit=-1` | la única config que mitiga el 109618 — desactiva el OOM-bailout |
| `session.upload_progress.enabled=Off` + restart workers | rompe el productor de sesión del 109619 |
| 8.5 only: `fatal_error_backtraces=0` + restart workers | elimina el productor del caso RCE confirmado |
| Descartar `multipart/form-data` en el proxy si la app no sube ficheros | elimina la superficie de trigger |
| `pm.max_requests=1` / vida corta del worker | acorta la ventana de estado stale |
| **NO** limitar con `RLIMIT_AS`/`RLIMIT_DATA` | los fallos de mmap empujan al mismo OOM/bailout |

**Detección (request side):** `zend_mm_heap corrupted`, worker SIGABRT/SIGSEGV, multipart con filenames enormes o miles de parts, **`Set-Cookie: PHPSESSID=` mucho mayor de 32 bytes** (¡el leak in-band deja esa huella!), `Allowed memory size` en logs pre-RINIT.
**Detección (host side):** `www-data` spawn de `sh`/`bash`/`whoami`/`uname` con padre `apache2`/`php-fpm`.

**WAF bypass:** `Content-Type: multipart/form-data, boundary=X` (¡coma!) es aceptado por PHP — `SAPI.c` recorta en `;`, `,` y espacio. **Todas** las firmas php2shell publicadas ancladas a `;` son bypasseables (ver `docs/WAF-BYPASS.md` del vendor).

---

## 7. Cheatsheet de comandos del lab

```bash
make up                    # lab base: vulnerable :8081 / parcheado :8082
make test-all              # contraste trigger vulnerable vs parcheado
make iocs                  # escaneo de IOCs en los logs

make vendor-exploit        # vende el exploit público (commit fijado b1e4199)
make rce-reproduce         # RCE canónico (Chain A) — determinista, sudo+gdb
make rce CMD="id"          # RCE stock (Chain B+leak) — hasta 8 intentos frescos
make rce-info              # reconocimiento (versión, build, worker)
make rce-check             # oracle de leak sin fire
make rce-down && make clean
```

**Scripts propios:** `scripts/php2shell_repro.py` (trigger/control), `scripts/php2shell_rce.py` (wrapper RCE: `--info`/`--check`/`-c "cmd"`), `scripts/php2shell_iocs.py`.

**Vendor:** `lab/vendor/php2shell-exp/` — verificable con `cd lab/vendor/php2shell-exp && sha256sum -c SOURCE-SHA256SUMS`.

---

## 8. Linaje y fuentes (los 5 repos)

| Repo | Aportación | Estado |
|---|---|---|
| **dinosn/php-cve-2026-10961x-lab-poc** (vendido, commit `b1e4199`) | Chains A+B completas, amplificación 52x, leak in-band, `reproduce.sh` canónico | ✅ **verificado end-to-end aquí** (ambas rutas) |
| Oracle-Security (análisis de referencia citado por dinosn) | leak original del heap | linaje |
| Calif Research | amplificación de memoria original | linaje |
| 9bie/php2shell-bypass-aslr-exp | trabajo concurrente en la clase de bug | ⚠️ no ejecutable tal cual (omite sus módulos `de0/`) |
| xuehuolll/php2shell-CVE-2026-109618-109619 | tabla de mitigaciones, estado post-parche 8.5.12 | documentación |
| ikow/php2shell-poc, 0x4148/CVE-…-lab, syrex1013/php2shell | PoCs de terceros (Chain E de ikow referenciada en el vendor) | contexto |

## 9. Qué NO prueba este lab (boundary honesto)

- **No** es un exploit single-shot portable contra producción endurecida (multi-worker prefork, `display_errors=Off` y `memory_limit` alto siguen siendo barreras reales).
- Chain A no demuestra RCE con el allocator por defecto; Chain B (stock) demuestra default-allocator **en esta geometría concreta**, pero sigue siendo probabilística por generación ASLR.
- No se prueba impacto en versiones fuera de las listadas (7.4.33 / 8.1.34 / 8.4.26 / 8.5.11 / 8.5.12 + 3 builds LiteSpeed, según el vendor).
- El RCE en FPM queda en crash/DoS (no probado más allá).
- La autenticidad de metadatos CVE no publicados no es verificable por nosotros.
