"""Motor didáctico de ofuscación: tres técnicas reversibles en secuencia.

Orden de ofuscación:  1) sustitución  -> 2) clave  -> 3) transposición
Orden inverso:        3') destransponer -> 2') deshacer clave -> 1') desustituir

El inverso va en orden contrario porque cada etapa recibe la salida de la
anterior: (f3 o f2 o f1)^-1 = f1^-1 o f2^-1 o f3^-1.

ADVERTENCIA: esto es ofuscación, NO cifrado seguro. Solo para datos ficticios.
"""

# ---------------------------------------------------------------------------
# Alfabeto común: ASCII imprimible (32..126) + caracteres del español.
# Todas las técnicas operan dentro de este conjunto, así la salida de una
# etapa siempre es entrada válida para la siguiente.
# ---------------------------------------------------------------------------
ASCII_IMPRIMIBLE = "".join(chr(c) for c in range(32, 127))   # 95 caracteres
EXTRA_ESPANOL = "áéíóúÁÉÍÓÚñÑüÜ¿¡"                             # 16 caracteres
ALFABETO = ASCII_IMPRIMIBLE + EXTRA_ESPANOL                    # 111 caracteres
N = len(ALFABETO)
INDICE = {c: i for i, c in enumerate(ALFABETO)}

LARGO_MINIMO_CLAVE = 4


def validar_texto(texto, campo="texto"):
    """Exige str y que todos los caracteres pertenezcan al alfabeto."""
    if not isinstance(texto, str):
        raise TypeError(f"{campo} debe ser texto (str), se recibió {type(texto).__name__}")
    fuera = sorted({c for c in texto if c not in INDICE})
    if fuera:
        raise ValueError(f"{campo} contiene caracteres no soportados: {''.join(fuera)!r}")
    return texto


def validar_clave(clave):
    if not clave:
        raise ValueError("Se requiere una clave de laboratorio")
    validar_texto(clave, "clave")
    if len(clave) < LARGO_MINIMO_CLAVE:
        raise ValueError(f"La clave debe tener al menos {LARGO_MINIMO_CLAVE} caracteres")
    return clave


# ---------------------------------------------------------------------------
# Técnica 1: sustitución con TABLA PROPIA (pares de intercambio tipo "leet").
# Cada par funciona en ambos sentidos (a -> @ y @ -> a), por lo que la tabla
# es una biyección: es su propia inversa. Los caracteres que no están en la
# tabla se mantienen.
# Ejemplo del enunciado: "carlos" -> "c@rl0s"
# A diferencia de un desplazamiento fijo (César), esta tabla NO es una suma
# modular, así que no se "fusiona" con la técnica 2.
# ---------------------------------------------------------------------------
PARES_SUSTITUCION = (
    ("a", "@"), ("e", "3"), ("i", "1"), ("o", "0"), ("t", "7"),
    ("b", "8"), ("g", "9"), ("z", "2"), ("A", "4"), ("E", "&"),
    ("I", "!"), ("O", "*"), ("S", "5"), ("ñ", "~"), ("Ñ", "#"),
    (" ", "_"),
)


def _construir_tabla(pares):
    tabla = {}
    for x, y in pares:
        if x == y or x not in INDICE or y not in INDICE:
            raise ValueError(f"Par de sustitución inválido: {x!r}/{y!r}")
        if x in tabla or y in tabla:
            raise ValueError(f"Carácter repetido en la tabla: {x!r}/{y!r}")
        tabla[x] = y
        tabla[y] = x
    return tabla


TABLA_SUSTITUCION = _construir_tabla(PARES_SUSTITUCION)
TABLA_INVERSA = {v: k for k, v in TABLA_SUSTITUCION.items()}


def sustituir_caracteres(texto: str) -> str:
    validar_texto(texto)
    return "".join(TABLA_SUSTITUCION.get(c, c) for c in texto)


def desustituir_caracteres(texto: str) -> str:
    validar_texto(texto)
    return "".join(TABLA_INVERSA.get(c, c) for c in texto)


# ---------------------------------------------------------------------------
# Técnica 2: transformación controlada por la clave de laboratorio.
# Polialfabética (tipo Vigenère) con término por posición:
#     desplazamiento(i) = (ord(clave[i mod m]) + i) mod N
#     ofuscar:  c_i = ALFABETO[(indice(p_i) + desplazamiento(i)) mod N]
#     revertir: p_i = ALFABETO[(indice(c_i) - desplazamiento(i)) mod N]
# Una clave errónea NO se detecta: solo produce un resultado ilegible.
# ---------------------------------------------------------------------------
def _desplazamiento(clave, i):
    return (ord(clave[i % len(clave)]) + i) % N


def transformar_con_clave(texto: str, clave: str) -> str:
    validar_texto(texto)
    validar_clave(clave)
    return "".join(ALFABETO[(INDICE[c] + _desplazamiento(clave, i)) % N]
                   for i, c in enumerate(texto))


def destransformar_con_clave(texto: str, clave: str) -> str:
    validar_texto(texto)
    validar_clave(clave)
    return "".join(ALFABETO[(INDICE[c] - _desplazamiento(clave, i)) % N]
                   for i, c in enumerate(texto))


# ---------------------------------------------------------------------------
# Técnica 3: transposición por rieles alternados (2 rieles).
# Primero los caracteres en posiciones pares y luego los de posiciones impares.
#     "ABCDEFG" -> "ACEG" + "BDF" = "ACEGBDF"
# El inverso vuelve a intercalar ambas mitades.
# ---------------------------------------------------------------------------
def transponer_caracteres(texto: str) -> str:
    validar_texto(texto)
    return texto[0::2] + texto[1::2]


def destransponer_caracteres(texto: str) -> str:
    validar_texto(texto)
    mitad = (len(texto) + 1) // 2
    pares, impares = texto[:mitad], texto[mitad:]
    resultado = []
    for k in range(len(texto)):
        resultado.append(pares[k // 2] if k % 2 == 0 else impares[k // 2])
    return "".join(resultado)


# ---------------------------------------------------------------------------
# Pipeline completo
# ---------------------------------------------------------------------------
def ofuscar_pipeline(texto: str, clave: str) -> dict:
    validar_texto(texto)
    validar_clave(clave)
    p1 = sustituir_caracteres(texto)
    p2 = transformar_con_clave(p1, clave)
    p3 = transponer_caracteres(p2)
    return {
        "original": texto,
        "paso1_sustitucion": p1,
        "paso2_clave": p2,
        "paso3_transposicion": p3,
        "final": p3,
    }


def desofuscar_pipeline(texto_ofuscado: str, clave: str) -> dict:
    validar_texto(texto_ofuscado)
    validar_clave(clave)
    p1_inv = destransponer_caracteres(texto_ofuscado)
    p2_inv = destransformar_con_clave(p1_inv, clave)
    p3_inv = desustituir_caracteres(p2_inv)
    return {
        "ofuscado": texto_ofuscado,
        "paso1_inv_transposicion": p1_inv,
        "paso2_inv_clave": p2_inv,
        "paso3_inv_sustitucion": p3_inv,
        "recuperado": p3_inv,
    }
