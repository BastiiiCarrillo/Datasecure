# Informe técnico — DataSecure SpA: motor didáctico de ofuscación

**Asignatura:** Seguridad en Redes (CI3062) — Evaluación Sumativa N°2
**Carrera:** Ingeniería en Telecomunicaciones — INACAP
**Integrantes:** _Nombre 1 · Nombre 2 · Nombre 3 · Nombre 4_
**Repositorio:** https://github.com/BastiiiCarrillo/Datasecure — versión final: tag `v1.0`
**Fecha:** 15-10-2026

---

## 1. Problema

DataSecure SpA (empresa ficticia) almacena nombres de usuario y contraseñas sin ninguna
transformación: un acceso no autorizado a la base de datos permite leerlos directamente.
Se solicitó un **prototipo didáctico** que aplique tres técnicas consecutivas de ofuscación
sobre datos leídos desde un motor de base de datos, que permita revertirlas y que sirva para
**evidenciar sus debilidades** y diferenciar ofuscación, cifrado y hashing. El prototipo no es,
ni pretende ser, un mecanismo seguro para credenciales reales.

## 2. Arquitectura

La solución se desarrolló en Python con una interfaz web en Streamlit y persistencia en
SQLite (desarrollo) o MariaDB sobre la VM AlmaLinux entregada por el docente. Sigue el
diagrama de arquitectura segura de la pauta, en cinco capas:

| Capa | Componente | Responsabilidad |
|---|---|---|
| 1. Presentación | `app.py` | Interfaz web, simulación de roles, demostraciones |
| 2. Aplicación | `src/motor_ofuscacion.py`, `src/modulo_cripto.py` | Tres técnicas y sus inversas; AES-256-GCM y Argon2id |
| 3. Datos | `database/` + MariaDB | `usuarios_ficticios`, `usuarios_protegidos`, `auditoria` |
| 4. Gestión de claves | `.env` (excluido de Git) | Clave de laboratorio y clave maestra AES fuera del código |
| 5. Soporte | Bitácora y GitHub | Auditoría sin datos sensibles; control de versiones |

La tabla `usuarios_ficticios` conserva los 11 originales para comparar. `usuarios_protegidos`
guarda, por cada cuenta, el usuario y la contraseña ofuscados, el usuario cifrado con
AES-256-GCM y el hash Argon2id de la contraseña. La aplicación accede con un usuario de base
de datos de privilegios mínimos y consultas parametrizadas.

## 3. Técnicas implementadas

Las tres técnicas operan sobre un alfabeto cerrado de 111 símbolos (ASCII imprimible más
`áéíóúÁÉÍÓÚñÑüÜ¿¡`), lo que garantiza que la salida de cada etapa sea entrada válida de la
siguiente. Cualquier otro carácter produce un error controlado.

**Orden de ofuscación:** 1) sustitución → 2) clave → 3) transposición.
**Orden inverso:** 3′) destransposición → 2′) deshacer clave → 1′) desustitución. El inverso se
aplica en orden contrario porque cada etapa trabaja sobre la salida de la anterior:
(f₃∘f₂∘f₁)⁻¹ = f₁⁻¹∘f₂⁻¹∘f₃⁻¹.

**3.1 Sustitución con tabla propia.** Dieciséis pares de intercambio: `a↔@ e↔3 i↔1 o↔0 t↔7
b↔8 g↔9 z↔2 A↔4 E↔& I↔! O↔* S↔5 ñ↔~ Ñ↔# espacio↔_`. Cada par funciona en ambos sentidos,
por lo que la tabla es su propia inversa; al cargarse se valida que no tenga caracteres
repetidos. Reproduce el ejemplo del enunciado: `carlos → c@rl0s`. Una primera versión usaba
un desplazamiento fijo de 47 (César), pero se descartó: dos desplazamientos modulares seguidos
equivalen a uno solo, de modo que la sustitución quedaba absorbida por la técnica 2.

**3.2 Transformación con clave de laboratorio.** Sustitución polialfabética tipo Vigenère:

    d(i) = (ord(clave[i mod m]) + i) mod 111
    ofuscar:  cᵢ = ALFABETO[(índice(pᵢ) + d(i)) mod 111]
    revertir: pᵢ = ALFABETO[(índice(cᵢ) − d(i)) mod 111]

La clave controla el desplazamiento de cada posición (no es un prefijo fijo) y el término `+ i`
hace que caracteres repetidos produzcan símbolos distintos. Se exige una clave de al menos 4
caracteres.

**3.3 Transposición por rieles alternados.** Primero se escriben los caracteres de posición par
y luego los de posición impar (`ABCDEFG → ACEGBDF`). Solo cambia posiciones; el inverso
reintercala ambas mitades.

**Ejemplo real** (clave `LabKey#2026`):

| Etapa | Valor |
|---|---|
| original | `carlos` |
| 1. sustitución | `c@rl0s` |
| 2. clave | `@3gK*ó` |
| 3. transposición | `@g*3Kó` ← se almacena |
| 3′ → 2′ → 1′ | `@3gK*ó` → `c@rl0s` → `carlos` |

## 4. Pruebas

Se ejecutaron 33 pruebas automatizadas (`python -m unittest -v`) más la integración con MariaDB
en la VM (`RUN_MARIADB_TESTS=1`), además de las demostraciones en la interfaz sobre 11 cuentas
ficticias con mayúsculas, minúsculas, números, especiales, `ñ` y una contraseña repetida
(ids 1 y 11).

| Prueba | Esperado | Obtenido |
|---|---|---|
| Consulta de registros antes del proceso | 11 registros legibles | ✔ |
| Procesar, guardar y nueva consulta al motor | 11 filas en `usuarios_protegidos` | ✔ |
| Recuperación con la clave correcta (ofuscación + AES + Argon2id) | 11/11 | ✔ 11/11 |
| Mismo texto con dos claves | Resultados distintos | ✔ `7f*#1¿>vJum` vs `CwéÓ.*Fau{E` |
| Recuperar con clave errónea | No recupera | ✔ `Wb@í!H+9e+A` |
| AES-GCM con clave errónea o dato alterado | Rechazado | ✔ etiqueta GCM inválida |
| Entrada vacía | Devuelve vacío | ✔ |
| Contraseña repetida (ids 1 y 11) | Ofuscación igual; Argon2id distinto | ✔ `5-4Cñ_U*9q` en ambas |
| Caracteres no soportados (emoji, `\n`, `€`) | Error controlado | ✔ `ValueError` |
| Tipos inválidos / clave corta | Error controlado | ✔ |

_[Insertar capturas de la VM — ver `docs/evidencias/`]_

## 5. Riesgos y análisis técnico

**¿En qué se diferencian la ofuscación, el cifrado y el hashing?**
La *ofuscación* solo dificulta la lectura directa; su protección depende de que el método no se
conozca y no resiste análisis. El *cifrado* es reversible, pero su seguridad descansa solo en el
secreto de la clave, aunque el algoritmo sea público (principio de Kerckhoffs), y está respaldado
por décadas de criptoanálisis público. El *hashing* es unidireccional: no permite recuperar el
dato, solo comprobar si otro dato produce el mismo resultado; se usa para integridad y, con
funciones lentas y sal, para verificar contraseñas.

**¿Por qué la sustitución, aun combinada, no equivale a cifrado seguro?**
La tabla de sustitución y la transposición son fijas y están en el código, así que no aportan
secreto: se anulan aplicando su inversa. Todo el secreto queda en la técnica 2, que es lineal y
trabaja carácter por carácter. No hay *difusión* (cambiar un carácter de entrada cambia uno solo
de salida), se conserva el largo y las repeticiones se notan. Un cifrado moderno como AES aplica
muchas rondas no lineales diseñadas precisamente para resistir estos análisis.

**¿Qué debilidades presenta nuestro mecanismo de clave?**
1. *Texto conocido:* con un par original/ofuscado y el código se calcula d(i), se resta `i` y se
   obtiene cada carácter de la clave (módulo 111), lo que basta para desofuscar todo.
2. *Claves parecidas filtran información:* cada posición depende de un solo carácter de la clave.
   Ofuscando `carlos_mora` con `ClaveUno` y recuperando con `ClaveDos` se obtuvo
   **`carloÁ¡1ora`**: la parte común de las claves recupera la parte correspondiente del texto.
3. *Determinismo:* sin valor aleatorio, datos iguales dan salidas iguales (ids 1 y 11).
4. *Fuga de largo:* la salida mide lo mismo que la entrada.
5. *Sin autenticación:* una clave errónea no se detecta, solo produce basura.
6. *Clave en una variable de entorno:* quien acceda al servidor puede leerla.

**Si alguien copia la base ofuscada y obtiene el código fuente, ¿qué podría averiguar?**
Prácticamente todo. Con el código conoce la tabla, el alfabeto y la transposición, así que el
problema se reduce a un Vigenère. Con un dato conocido o adivinable (un usuario evidente como
`admin_test`) recupera la clave y desofusca la tabla completa. Aun sin clave, ve largos y qué
cuentas comparten contraseña. Además, en este laboratorio la tabla de originales está en la misma
base (requisito de comparación), lo que en un sistema real sería inaceptable. En cambio, con la
columna AES-256-GCM no obtendría nada sin la clave maestra (que no está en la base), y con los
hashes Argon2id solo podría intentar adivinar contraseñas a un costo de 64 MiB por intento.

## 6. Comparación con soluciones criptográficas reales

**AES-256-GCM para datos que deben recuperarse.** Es cifrado autenticado (AEAD, NIST SP 800-38D):
da **confidencialidad** con clave de 256 bits e **integridad y autenticidad** mediante una etiqueta
de 128 bits. Con un nonce aleatorio de 96 bits por operación, dos datos iguales generan cifrados
distintos (resuelve el determinismo), y una clave errónea o un dato alterado **se detectan**
porque la etiqueta no verifica (resuelve la falta de autenticación). En el prototipo la clave se
entrega en base64 (32 bytes aleatorios) o, si es una frase, se deriva con scrypt; nunca debe
reutilizarse un nonce con la misma clave.

**Argon2id con sal para contraseñas reales.** Una contraseña no debe poder recuperarse, solo
verificarse, por eso se usa una función unidireccional y no un cifrado. Argon2id (RFC 9106) es
deliberadamente costoso en memoria y tiempo, lo que encarece los ataques con GPU o ASIC. La sal
aleatoria de 16 bytes hace que dos usuarios con la misma contraseña tengan hashes distintos e
inutiliza las tablas precalculadas. Usamos 64 MiB, t = 2, p = 2, por encima del mínimo que
recomienda OWASP (19 MiB, t = 2, p = 1). Un SHA-256 simple no sirve porque es demasiado rápido.

| Necesidad | Ofuscación (prototipo) | Recomendado |
|---|---|---|
| Confidencialidad reversible | 3 técnicas | AES-256-GCM |
| Contraseñas | Reversible (inaceptable) | Argon2id + sal |
| Integridad | No | Etiqueta GCM; SHA-256 / HMAC-SHA-256 |
| Detecta clave errónea | No | Sí |
| Datos iguales → salida igual | Sí | No (nonce / sal) |

## 7. Conclusiones

El prototipo cumple los requisitos: lee 11 cuentas ficticias desde MariaDB, aplica tres técnicas
reversibles en secuencia, guarda el resultado en una tabla separada y recupera el 100 % de los
registros con la clave correcta. Las pruebas también mostraron por qué no debe usarse en
producción: es determinista, conserva largos, no detecta claves erróneas y filtra parte del texto
cuando las claves se parecen. La ofuscación dificulta la lectura casual, pero la protección real
exige primitivas estándar: AES-256-GCM para lo que debe recuperarse y Argon2id con sal para
contraseñas, con las claves gestionadas fuera de la base de datos.

---

## Anexo A — Estándares y normativa (criterio 2.1.3)

| Referencia | Aporte al caso |
|---|---|
| ISO/IEC 27001:2022 y 27002:2022 (control 8.24 *Uso de criptografía*) | Política formal de criptografía y gestión de claves |
| NIST FIPS 197 / SP 800-38D | Definen AES y el modo GCM |
| NIST SP 800-63B | Contraseñas almacenadas con sal y función de derivación resistente |
| RFC 9106 | Especificación de Argon2 (Argon2id recomendado) |
| NIST FIPS 180-4 / FIPS 202 | SHA-2 y SHA-3 para integridad |
| OWASP Top 10 (A02 *Cryptographic Failures*) y *Password Storage Cheat Sheet* | Fallas típicas y parámetros de Argon2id |
| Ley 21.719 (Chile) — Protección de datos personales | Exige medidas de seguridad apropiadas sobre datos personales |
| Ley 21.663 (Chile) — Ley Marco de Ciberseguridad | Crea la ANCI y deberes de gestión de seguridad e incidentes |
| Ley 21.459 (Chile) — Delitos informáticos | Tipifica el acceso ilícito a sistemas como el del escenario |

**Selección de funciones hash (criterio 2.1.2):** SHA-256 o SHA3-256 para verificar respaldos y
archivos; HMAC-SHA-256 cuando además se debe probar el origen; Argon2id solo para contraseñas.
MD5 y SHA-1 se descartan por tener colisiones prácticas.

## Anexo B — Política de seguridad propuesta para DataSecure SpA (criterio 2.1.4)

1. **Alcance:** toda aplicación y base de datos que almacene datos de usuarios.
2. **Contraseñas:** solo como Argon2id (m ≥ 19 MiB, t ≥ 2) con sal aleatoria de 16 bytes.
   Prohibido cifrarlas, ofuscarlas o usar MD5, SHA-1 o SHA-256 simple.
3. **Datos personales reversibles:** AES-256-GCM con nonce aleatorio de 96 bits por registro.
   Prohibidos DES/3DES, modo ECB y algoritmos de diseño propio (como el de este laboratorio).
4. **Gestión de claves:** claves aleatorias de 256 bits, fuera de la base y del código, en un gestor
   de secretos o KMS; rotación al menos anual o ante sospecha de compromiso.
5. **En tránsito:** TLS 1.3 entre aplicación y base (`require_secure_transport` en MariaDB), con
   intercambio ECDHE y certificados RSA-2048+ o ECDSA P-256.
6. **Integridad:** respaldos verificados con SHA-256 y protegidos con HMAC o firma.
7. **Mínimo privilegio y auditoría:** usuario de aplicación sin permisos administrativos; bitácora
   sin datos sensibles ni claves.
8. **Repositorios:** prohibido versionar `.env`, claves, tokens o respaldos; `.gitignore` y escaneo
   de secretos obligatorios.
9. **Revisión:** anual, alineada con ISO/IEC 27001 y la normativa chilena vigente.

## Anexo C — Colaboración

- Historial de commits: https://github.com/BastiiiCarrillo/Datasecure/commits/main
- Issues: https://github.com/BastiiiCarrillo/Datasecure/issues — Pull requests: https://github.com/BastiiiCarrillo/Datasecure/pulls
- Distribución de tareas: _completar (integrante → módulo / issue)_
