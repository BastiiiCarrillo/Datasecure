ASCII_START = 32
ASCII_END = 126
ASCII_SIZE = ASCII_END - ASCII_START + 1
DESPLAZAMIENTO_SUSTITUCION = 47

def sustituir_caracteres(texto: str) -> str:
    if not texto:
        return ""
    resultado = []
    for c in texto:
        code = ord(c)
        if ASCII_START <= code <= ASCII_END:
            nuevo_code = ((code - ASCII_START + DESPLAZAMIENTO_SUSTITUCION) % ASCII_SIZE) + ASCII_START
            resultado.append(chr(nuevo_code))
        else:
            resultado.append(c)
    return "".join(resultado)

def desustituir_caracteres(texto: str) -> str:
    if not texto:
        return ""
    resultado = []
    for c in texto:
        code = ord(c)
        if ASCII_START <= code <= ASCII_END:
            orig_code = ((code - ASCII_START - DESPLAZAMIENTO_SUSTITUCION) % ASCII_SIZE) + ASCII_START
            resultado.append(chr(orig_code))
        else:
            resultado.append(c)
    return "".join(resultado)

def transformar_con_clave(texto: str, clave: str) -> str:
    if not texto:
        return ""
    if not clave:
        raise ValueError("Se requiere una clave")
    resultado = []
    len_clave = len(clave)
    for i, c in enumerate(texto):
        code = ord(c)
        val_clave = ord(clave[i % len_clave])
        if ASCII_START <= code <= ASCII_END:
            desplazamiento = (val_clave + i) % ASCII_SIZE
            nuevo_code = ((code - ASCII_START + desplazamiento) % ASCII_SIZE) + ASCII_START
            resultado.append(chr(nuevo_code))
        else:
            resultado.append(c)
    return "".join(resultado)

def destransformar_con_clave(texto: str, clave: str) -> str:
    if not texto:
        return ""
    if not clave:
        raise ValueError("Se requiere una clave")
    resultado = []
    len_clave = len(clave)
    for i, c in enumerate(texto):
        code = ord(c)
        val_clave = ord(clave[i % len_clave])
        if ASCII_START <= code <= ASCII_END:
            desplazamiento = (val_clave + i) % ASCII_SIZE
            orig_code = ((code - ASCII_START - desplazamiento) % ASCII_SIZE) + ASCII_START
            resultado.append(chr(orig_code))
        else:
            resultado.append(c)
    return "".join(resultado)

def transponer_caracteres(texto: str) -> str:
    if not texto or len(texto) <= 1:
        return texto
    pares = texto[0::2]
    impares = texto[1::2]
    return pares + impares

def destransponer_caracteres(texto: str) -> str:
    if not texto or len(texto) <= 1:
        return texto
    n = len(texto)
    mitad = (n + 1) // 2
    pares = texto[:mitad]
    impares = texto[mitad:]
    resultado = []
    p_idx, i_idx = 0, 0
    for k in range(n):
        if k % 2 == 0:
            resultado.append(pares[p_idx])
            p_idx += 1
        else:
            resultado.append(impares[i_idx])
            i_idx += 1
    return "".join(resultado)

def ofuscar_pipeline(texto: str, clave: str) -> dict:
    if not texto:
        return {
            "original": "",
            "paso1_sustitucion": "",
            "paso2_clave": "",
            "paso3_transposicion": "",
            "final": ""
        }
    p1 = sustituir_caracteres(texto)
    p2 = transformar_con_clave(p1, clave)
    p3 = transponer_caracteres(p2)
    return {
        "original": texto,
        "paso1_sustitucion": p1,
        "paso2_clave": p2,
        "paso3_transposicion": p3,
        "final": p3
    }

def desofuscar_pipeline(texto_ofuscado: str, clave: str) -> dict:
    if not texto_ofuscado:
        return {
            "ofuscado": "",
            "paso1_inv_transposicion": "",
            "paso2_inv_clave": "",
            "paso3_inv_sustitucion": "",
            "recuperado": ""
        }
    p1_inv = destransponer_caracteres(texto_ofuscado)
    p2_inv = destransformar_con_clave(p1_inv, clave)
    p3_inv = desustituir_caracteres(p2_inv)
    return {
        "ofuscado": texto_ofuscado,
        "paso1_inv_transposicion": p1_inv,
        "paso2_inv_clave": p2_inv,
        "paso3_inv_sustitucion": p3_inv,
        "recuperado": p3_inv
    }
