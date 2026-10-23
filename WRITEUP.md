# PHP2Shell — Anatomía de CVE-2026-109618 y CVE-2026-109619

> **TL;DR** — Dos RCE críticos (CVSS v4.0 **9.2**) en el **núcleo de PHP**,
> divulgados el **21 de octubre de 2026**, que permiten a un atacante **no
> autenticado** ejecutar código en el servidor con un simple POST HTTP. El
> fallo ocurre **durante la inicialización del request**: la autenticación, los
> filtros y cualquier defensa a nivel de aplicación llegan tarde. Afectan a
> **PHP 5.4 → 8.5** en todas las SAPIs (mod_php, PHP-FPM, php-cgi, LiteSpeed,
> FrankenPHP) y **se están explotando activamente en la wild**. El fix llegó en
> PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Ninguna mitigación de configuración
> los corrige por completo: **parchear es la única defensa completa**.

---

## 1. Origen y cronología

| Fecha | Acontecimiento |
|---|---|
| (previo) | Investigadores de **Calif** descubren los fallos y los reportan a PHP en disclosure coordinado |
| **17 oct 2026** | AWS observa los **primeros intentos de explotación en la wild**, 4 días antes de la divulgación pública |
| **20 oct 2026** | Los detalles se **filtran en redes sociales** antes de la fecha prevista (22 oct). watchTowr confirma públicamente que las vulnerabilidades son reales |
| 20 oct 2026 | El equipo de seguridad de PHP anuncia una **release de emergencia** para el día siguiente |
| **21 oct 2026 · 14:00 UTC** | PHP publica el advisory y las versiones corregidas (8.5.12, 8.4.27, 8.3.36, 8.2.35). watchTowr confirma **explotación activa** vía su red de honeypots *Attacker Eye* |
| 22 oct 2026 | CERT-EU, NCSC (UK), Datadog, Wiz, Palo Alto Unit42, VulnCheck, Red Hat, Google Cloud publican alertas. CISA aún no las ha añadido al catálogo KEV |
| ~22 oct 2026 | Ya existe artículo en Wikipedia ("PHP2Shell") — velocidad de difusión récord |
| 22-23 oct 2026 | **NCSC-NL** publica su repo de información operacional (`NCSC-NL/php2shell`): inventario de software afectado, material de detección/mitigación. **Sin exploit code** |
| 22-23 oct 2026 | ASEC (AhnLab) analiza el ecosistema de ~100 repos "php2shell" aparecidos en GitHub (véase §13) |

El nombre **PHP2Shell** lo acuñó la comunidad: de *PHP* a *shell* con un solo
POST, sin credenciales.

**Puntos clave del análisis de Datadog** (que construyó un exploit de
laboratorio para desarrollar detecciones):

- La autenticación de la aplicación **no puede bloquear** el ataque: PHP
  procesa el request malicioso antes de ejecutar cualquier código de la app.
- La ejecución de comandos **no crashea necesariamente el worker** — un exploit
  refinado devuelve HTTP 200 y el worker sigue vivo (lo que hace la detección
  más difícil).
- Hay explotación activa confirmada desde el mismo día de la divulgación.

---

## 2. CVE-2026-109618 — corrupción por OOM en la inicialización del request

### 2.1 El ciclo de vida que falla

Cuando PHP recibe un POST `application/x-www-form-urlencoded`, convierte el
cuerpo en el array `$_POST` **antes** de ejecutar el script (fase *request
startup* / RINIT). Internamente, las claves y valores se guardan en una
**HashTable** de Zend, en entradas llamadas *buckets*.

### 2.2 El bug: contadores actualizados antes de asignar la memoria

En `_zend_hash_str_add_or_update_i()`, PHP hace esto:

```c
idx = ht->nNumUsed++;
ht->nNumOfElements++;          // 1) el contador YA cuenta el nuevo bucket
p = ht->arData + idx;
p->key = key = zend_string_init(str, len, ...);  // 2) AHORA asigna la clave
```

Si la asignación de la clave (paso 2) excede `memory_limit`, PHP lanza un
**fatal error** y abandona la inserción a medio hacer. El problema: los
contadores (paso 1) **ya incluyen ese bucket**, pero el bucket **nunca se
inicializó** — contiene los bytes que dejara una asignación anterior.

### 2.3 La explosión: el cleanup confía en el estado a medias

PHP aún debe limpiar el request fallido. Al destruir `$_POST`, recorre **todos**
los buckets que dicen los contadores e **interpreta sus bytes como valores PHP
válidos**. El bucket sin inicializar contiene basura que el atacante puede
controlar (mediante *heap grooming* con campos del propio request).

Datadog demostró el impacto final: durante ese cleanup, PHP sigue el puntero de
un destructor de array falso hasta una llamada a **`system()` de glibc** con un
comando controlado por el atacante:

```text
Request falla en la inicialización
  → el shutdown destruye $_POST
    → PHP interpreta el bucket sin terminar como un array
      → PHP destruye el array falso
        → el destructor del array es system("<comando>")
```

El comando corre con los privilegios del worker (p. ej. `www-data`).

### 2.4 La firma observable (la que reproduce este lab)

El fatal error salta **durante la inicialización**, lo que deja la firma
inequívoca:

```text
PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted
(tried to allocate 3584032 bytes) in Unknown on line 0
```

- `in Unknown on line 0` ⇒ ocurrió **antes de que empezara el script**.
- `(tried to allocate ~3.5 MB)` ⇒ la copia de la clave gigante es lo que
  reventó el límite.
- Y en el build vulnerable, el cleanup sobre el bucket corrupto **mata al
  worker**: `AH00051: child pid ... exit signal Segmentation fault (11)`.

### 2.5 El request desencadenante (forma documentada)

```text
Content-Type: application/x-www-form-urlencoded

=<valor binario de siembra>&a=1&ZZZZ…ZZZZ[x]=1
└─ nombre vacío: PHP copia el valor y lo libera (siembra el heap)
              └─ a=1: fuerza la creación de las HashTable
                                        └─ nombre gigante con sintaxis de
                                           array [x]: fuerza la ruta de
                                           inserción vulnerable y agota
                                           memory_limit al copiar la clave
```

Requisitos del atacante: dimensionar el request para fallar en el momento
exacto, y vencer **ASLR** (por eso los exploits reales combinan esta cadena con
fugas de memoria, p. ej. vía cookie `PHPSESSID`, según documentó Wiz).
**Nota**: nuestro lab reproduce la condición y su corrupción observable — no
incluye la cadena de explotación (véase §8, postura ética).

---

## 3. CVE-2026-109619 — estado global stale entre requests

### 3.1 El patrón: use-after-free a nivel de worker

Un worker PHP atiende cientos de requests a lo largo de su vida. Algunos campos
globales del worker apuntan a memoria **propiedad de un request concreto**. Si
PHP libera esa memoria sin poner esos campos a `NULL`, el request siguiente del
mismo worker sigue el puntero **a memoria liberada**.

Según el advisory de PHP, el estado stale se genera por dos caminos
(confirmados como explotables hasta ejecución de comandos):

1. **Backtraces de fatal error (solo PHP 8.5)**: el reporting del fatal error
   conserva estado del backtrace después del shutdown; un diagnóstico de
   configuración en un request posterior lo lee antes de que PHP lo
   inicialice. Confirmado con ejecución de comandos en **mod_php**.
2. **Procesado de uploads**: tras un fatal error, el procesado de uploads
   puede dejar atrás estado de sesión o de decodificadores. Un upload posterior
   lee ese estado antes de la inicialización normal. Confirmado en **mod_php y
   PHP-FPM** (en FPM requiere además que la app realice una operación
   adecuada tras el startup).

### 3.2 La pieza clave: `session.upload_progress`

El seguimiento de progreso de subida por sesión está **activado por defecto**
en PHP y funciona **aunque la aplicación nunca llame a `session_start()`** —
corre antes de que el script objetivo se ejecute. Por eso la mitigación
habitual es `session.upload_progress.enabled=0` (insuficiente por sí sola).

### 3.3 Requisito operativo

Los requests del atacante deben llegar **al mismo worker** (el estado stale es
por-proceso). Un pool grande baja la probabilidad de acierto pero **no elimina**
el fallo; con `MaxRequestWorkers` pequeño (como en este lab) el exploit se afina mucho más rápido.

---

## 4. Versiones afectadas y corregidas

| Rama | Afectadas | Primera release corregida |
|---|---|---|
| 8.5.x | < 8.5.12 | **8.5.12** |
| 8.4.x | < 8.4.27 | **8.4.27** |
| 8.3.x | < 8.3.36 | **8.3.36** |
| 8.2.x | < 8.2.35 | **8.2.35** |
| 8.1, 8.0, 7.4 | todas | sin release oficial — backports mínimos de fuente publicados por PHP; usa el paquete de tu distribuidor |
| ≤ 7.3 (incl. PHP 5) | todas | **sin fix disponible** — migra de rama |

> watchTowr confirmó que ramas antiguas sin soporte, incluida PHP 5, también
> son vulnerables. Todas las SAPIs están en el alcance: **mod_php** (riesgo
> máximo según PHP: el ataque sucede antes de cualquier código de la app),
> **PHP-FPM**, php-cgi, FrankenPHP, LiteSpeed, y cualquier contenedor/imagen que
> empaquete su propio intérprete.

---

## 5. El laboratorio de este repo

```text
docker compose up -d
```

| Contenedor | Imagen | Puerto | Esperado |
|---|---|---|---|
| `php2shell-vulnerable` | `php:8.5.11-apache` | 8081 | OOM fatal + segfault del worker |
| `php2shell-patched` | `php:8.5.12-apache` | 8082 | OOM gestionado en punto seguro, worker sobrevive |

Configuración calibrada (idéntica en ambos, única variable = versión PHP):

```ini
memory_limit = 16M      # el nombre de campo de ~3.5 MB debe agotarlo
post_max_size = 64M     # admite el cuerpo del trigger (~3.7 MB)
display_errors = On     # el fatal error es visible en la respuesta HTTP
```

Apache `mpm_prefork` con pool mínimo y KeepAlive: comportamiento determinista
y segfaults directamente visibles en el error log.

**Hallazgo importante medido en este lab**: el build **parcheada (8.5.12)
también emite el fatal OOM** `in Unknown on line 0` — es el *límite blando*
(*soft limit*) del parche, que difiere el error hasta un punto seguro. Por eso
la firma OOM **sola no distingue vulnerable de parcheada**; el discriminador
fiable es el **destino del worker**: el vulnerable **crashea** (segfault al
limpiar el bucket corrupto), el parcheado **sobrevive**.

## 6. Las herramientas

### 6.1 `scripts/php2shell_repro.py` — reproducción y veredicto

Cuatro fases con salida estética (ANSI, `--no-color`, `--json`):

1. **Fingerprint** — versión de PHP vía `X-Powered-By`/body + clasificación
   contra la tabla de releases corregidas.
2. **Baseline** — POST pequeño: el objetivo debe procesarlo limpio.
3. **Trigger** — el request desencadenante con escalera de tamaños adaptativa.
4. **Confirmación** — delta de segfaults y fatals en `docker logs`
   (`--container`) + matriz de decisión.

Matriz de veredicto:

| Señales | Veredicto |
|---|---|
| Segfault delta ≥ 1 + (conexión caída u OOM) | **VULNERABLE** (exit 0) |
| Sin crash + procesado limpio/OOM gestionado + versión corregida | **NOT_VULNERABLE** (exit 1) |
| OOM sin crash, versión desconocida, o request rechazado | INDETERMINADO (exit 2) |
| Objetivo inalcanzable | ERROR (exit 3) |

### 6.2 `scripts/php2shell_iocs.py` — detección en logs

Caza los IOCs del §7 en los logs de los contenedores, con correlación temporal
(±2 s) entre el OOM fatal y los POSTs. Modo `--json` para integración en SIEM/
cron. Exit: 0 limpio, 1 con hallazgos, 2 error.

## 7. Detección (para defensores)

### 7.1 IOCs

| IOC | Severidad | Señal |
|---|---|---|
| IOC-1 | HIGH | `PHP Fatal error: Allowed memory size of N bytes exhausted (tried to allocate M bytes) in Unknown on line 0` — el `Unknown on line 0` indica fallo en request startup, antes del script |
| IOC-2 | CRIT | `AH00051: child pid X exit signal Segmentation fault (11)` — segfault del worker tras un OOM: corrupción de estado |
| IOC-3 | HIGH | POST de tamaño anómalo correlacionado temporalmente (±2 s) con un IOC-1 |
| IOC-4 | MED | `Input variables exceeded N` — cuerpos malformados/sobredimensionados en el parseo |

**Correlación recomendada**: IOC-1 + IOC-2 en el mismo worker = señal de
corrupción confirmada. IOC-1 solo puede ser el límite blando de una build
parcheada (así se comporta 8.5.12, medido en este lab) — no alarmes por OOM
solo, pero investiga el origen del cuerpo gigante.

### 7.2 Otras señales (según Datadog / PHP)

- Requests con **nombres de campo de formulario** de megas y **bytes de
  control** (NULs) en el valor de campos con nombre vacío.
- Process tree: un hijo `sh -c <cmd>` bajo el worker web = explotación
  consumada (el exploit refinado **no** crashea el worker).
- Configura el WAF/reverse-proxy para rechazar nombres de campo enormes y
  cuerpos con bytes de control en `x-www-form-urlencoded`; verifica que tu
  motor de inspección no trunque los cuerpos grandes (no se puede inspeccionar
  lo que se descarta).
- Para CVE-2026-109619: revisa avisos tempranos de configuración, diagnósticos
  de shutdown y fatals/timeouts en rutas accesibles.

---

## 8. Mitigaciones (y por qué ninguna sustituye al parche)

Medidas temporales oficiales de PHP:

- **CVE-2026-109618**: `memory_limit=-1` a nivel de administrador + límites de
  tamaño de request en el front + memoria del contenedor. **No** uses
  `RLIMIT_AS`/`RLIMIT_DATA` como sustituto: provocan los fallos de asignación
  que el exploit necesita.
- **CVE-2026-109619**: `session.upload_progress.enabled=0` y, en 8.5,
  `fatal_error_backtraces=0`, aplicados en configuración que cargue **antes**
  del parseo del request, reiniciando todos los workers. Elimina cualquier
  ajuste por-request que genere diagnósticos tempranos.

Ninguna de estas medidas es completa (Datadog: *"setting
session.upload_progress.enabled=0 … doesn't fully protect you"*). Y un
atacante que agote la memoria del sistema puede seguir desestabilizando el
host. **Parchear es el único fix completo**: actualiza, **reconstruye las
imágenes** y **reinicia/reemplaza todos los workers**.

## 9. Cómo lo verificamos (resultados medidos)

| # | Prueba | Resultado |
|---|---|---|
| 1 | Trigger 3.5 MB contra 8.5.11 | `Allowed memory size of 16777216 bytes exhausted (tried to allocate 3584032 bytes) in Unknown on line 0` + `AH00051 … Segmentation fault (11)` — 100% de los intentos |
| 2 | Trigger idéntico contra 8.5.12 | Fatal OOM de límite blando, HTTP 200, **0 segfaults** — 100% de los intentos |
| 3 | Batería de estrés (10 rondas, contenedores recién reiniciados) | **10/10 veredictos correctos y deterministas** |
| 4 | Modo `--json` (parseable por jq/CI), exit codes 0/1/2/3, `--no-color`, objetivo inalcanzable, escalera adaptativa de tamaños | todos validados |
| 5 | IOC hunter: correlación temporal (bug de TZ detectado y corregido en el desarrollo) | IOC-1/2/3/4 presentes; conclusión "corrupción confirmada" en vulnerable |

Detalle del desarrollo (bugs encontrados y corregidos durante el testing —
buen material para el vídeo):

1. El filler binario inicial contenía `&` y `=` → el parser troceaba el cuerpo
   en cientos de variables (`max_input_vars` en vez del OOM). Fix: excluir
   `&`, `=` y `%` del alfabeto del filler.
2. El IOC-3 no correlacionaba: los timestamps del error log son *naive* y
   `datetime.timestamp()` los interpretaba en la TZ local (+2 h) frente al
   `+0000` del access log. Fix: anclar timestamps naive a UTC.
3. El modo `--json` imprimía el banner antes del JSON. Fix: progreso → stderr,
   JSON puro → stdout.

## 10. Guía de demo para el vídeo

> 🎬 **La guía completa de grabación, fase a fase y con las salidas esperadas
> reales, está en [`DEMO.md`](DEMO.md).** Esta sección resume el arco de la
> demo.

Guion sugerido (~5-8 min), todo ejecutable en vivo y sin cortes:

1. **Intro (30 s)**: "Se llaman PHP2Shell, CVSS 9.2, RCE sin autenticación en
   el núcleo de PHP, y llevan explotándose en la wild desde el día del parche".
2. `docker compose up -d` — muestra los dos contenedores arrancando.
3. `curl http://localhost:8081/` y `:8082/` — "mismo código, única diferencia:
   8.5.11 vs 8.5.12".
4. `python3 scripts/php2shell_repro.py http://localhost:8081/ --container php2shell-vulnerable`
   — enseña el banner, las 4 fases, el "conexión cerrada sin respuesta" y el
   veredicto **VULNERABLE**.
5. El contraste:
   `python3 scripts/php2shell_repro.py http://localhost:8082/ --container php2shell-patched`
   → **NOT_VULNERABLE**.
6. La evidencia cruda (momento estrella):
   `docker compose logs vulnerable | grep -E "Fatal|Segmentation"` — el fatal
   `in Unknown on line 0` y el segfault del worker.
7. El remate visual — **el worker muere y es reemplazado**: `make demo` o
   `curl http://localhost:8081/whoami.php` antes y después del trigger: el
   PID cambia porque el worker que atendía tu request murió limpiando el
   estado corrupto y Apache creó otro. En el parcheado el PID es siempre el
   mismo.
8. `python3 scripts/php2shell_iocs.py` — el IOC hunter pintando
   CRIT/HIGH/MED: "esto es lo que meteríais en el SIEM".
9. Cierre: "parchear es lo único que funciona de verdad: 8.5.12 / 8.4.27 /
   8.3.36 / 8.2.35, reconstruye imágenes y reinicia workers".

> Atajo para grabarlo todo en una sola pasada sin cortes: `make demo`
> (identidad de workers → trigger vulnerable → contraste parcheado →
> evidencia cruda → IOCs).

También añade al vídeo el contexto del §12: "el repo de NCSC-NL es info
operacional, no un exploit; los PoCs públicos no están verificados; la cadena
completa solo existe en privado". Eso da credibilidad al contenido.

## 11. Postura ética y alcance de este lab

Este repositorio reproduce y detecta la **condición** de la vulnerabilidad
(corrupción de estado observable), pero **no incluye la cadena de explotación**
(heapspray dirigido, estructuras Zend falsas, robo de direcciones contra ASLR
ni la llamada a `system()`). Razones:

- PHP2Shell se está explotando **activamente** contra servidores reales; una
  herramienta RCE automatizada "llave en mano" multiplica el daño sobre el
  enorme parque de servidores que tardará semanas en parchear.
- El beneficio defensivo (parcheo, detección, IOCs) no requiere publicar el
  arma; los propios investigadores que la documentaron no publicaron su
  exploit.
- Para entrenamiento de explotación existe una vía legítima: los laboratorios
  con exploits publicados por sus autores (HTB, TryHackMe, VulnHub, DVWA…).

Usa este lab únicamente sobre sistemas propios o con autorización explícita.

## 12. Estado del ecosistema público de PoCs (actualizado el 23 oct 2026)

Situación en dos tiempos, porque cambió entre la divulgación y hoy:

**En la divulgación (21 oct 2026)** no existía ninguna cadena de RCE pública
verificada. El repo `NCSC-NL/php2shell` del CERT holandés es material
operacional (inventario, mitigaciones, detección), no un exploit; ASEC analizó
~100 repos "php2shell" aparecidos entonces y encontró PoCs sin verificación
reputada, varios de ellos con posible **malware dirigido a investigadores**.
Datadog construyó la cadena completa de RCE **privadamente** (para desarrollar
detecciones) sin publicarla.

**Hoy (23 oct 2026)** existe al menos una cadena pública completa y verificable:
el repo de **dinosn** (`php-cve-2026-10961x-lab-poc`), que este lab **vende con
commit fijado** (`b1e4199…`) y que **hemos verificado end-to-end en este
entorno**:

| Ruta | Resultado medido aquí |
|---|---|
| Chain A canónica (`reproduce.sh`, lab-asistida con gdb) | `Proven - Lab-Assisted RCE`, 19/19 gates, token materializado en `/tmp/php-rce-lab` |
| Chain B stock (`php2shell_stock_poc.py`, remoto puro) | `uid=33(www-data)` vía `zif_system`, por HTTP y config por defecto |

Detalles de la mecánica, el linaje (Oracle-Security → Calif Research → trabajo
concurrente de 9bie) y las consideraciones operativas (fiabilidad por
generación ASLR, geometría del heap) están en [`EXPLOTACION.md`](EXPLOTACION.md).
Otros repos públicos evaluados: `9bie/php2shell-bypass-aslr-exp` (no ejecutable
tal cual: omite sus módulos `de0/`), `xuehuolll/php2shell-CVE-2026-109618-109619`
(buena tabla de mitigaciones y estado post-parche) y PoCs de terceros
(`ikow`, `0x4148`, `syrex1013`) usados como contexto.

Advertencias que siguen vigentes: la ruta stock es **probabilística** (2/3–3/3
por generación ASLR, según documenta el propio autor) y el veredicto canónico
deja constancia expresa de su boundary (*lab-assisted*, no portable
ASLR-independent). La recomendación de ASEC se mantiene: leer el código
completo antes de ejecutar cualquier PoC de terceros, y hacerlo solo en un
entorno aislado — exactamente lo que hace este lab, con el vendor fijado,
verificado por `SOURCE-SHA256SUMS` y encerrado en contenedor con solo loopback.

## 13. Referencias

- Advisory PHP (CVE-2026-109618): <https://www.php.net/archive/2026.php>
- Advisory PHP (CVE-2026-109619): <https://www.php.net/archive/2026.php>
- NVD CVE-2026-109618: <https://nvd.nist.gov/vuln/detail/cve-2026-109618>
- NVD CVE-2026-109619: <https://nvd.nist.gov/vuln/detail/cve-2026-109619>
- Datadog Security Labs — *PHP2Shell* (análisis técnico y walkthrough):
  <https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/>
- watchTowr — FAQ PHP2Shell (timeline, explotación en la wild):
  <https://watchtowr.com/intelligence/php-cve-2026-109618-faq/>
- CERT-EU advisory 2026-018: <https://cert.europa.eu/publications/security-advisories/2026-018/>
- Palo Alto Unit42 — threat brief:
  <https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/>
- Red Hat CVE entries: <https://access.redhat.com/security/cve/cve-2026-109618>
- Google Cloud blog — respuesta a los CVEs:
  <https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619>
- VulnCheck — PHP2Shell vulnerabilities:
  <https://www.vulncheck.com/blog/php2shell-vulnerabilities>
