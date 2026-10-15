"""Módulo criptográfico de referencia (comparación con la ofuscación).

- AES-256-GCM: cifrado autenticado para datos que deben recuperarse.
- Argon2id + sal: hash irreversible para contraseñas.
"""
import base64
import binascii
import hashlib
import os

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id (variante por defecto de argon2-cffi).
# 64 MiB, 2 iteraciones, 2 hilos: supera el mínimo OWASP (19 MiB, t=2, p=1).
hasher_argon2 = PasswordHasher(
    time_cost=2,
    memory_cost=65536,   # KiB = 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,         # sal aleatoria de 16 bytes por cada hash
)

LARGO_NONCE = 12         # 96 bits, recomendado por NIST SP 800-38D
LARGO_TAG = 16           # etiqueta de autenticación de 128 bits

# Sal fija SOLO para derivar la clave maestra cuando se entrega como frase.
# En producción la clave sería aleatoria y viviría en un gestor de secretos.
_SAL_KDF_LAB = b"DataSecure-Lab-KDF-v1"


def generar_clave_maestra() -> str:
    """Genera una clave AES-256 aleatoria en base64 (para pegar en .env)."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


def derivar_clave_aes256(clave_maestra: str) -> bytes:
    """Obtiene 32 bytes de clave.

    1. Si la clave es base64 de 32 bytes (generar_clave_maestra), se usa directa.
    2. Si es una frase, se deriva con scrypt (KDF lenta), no con un SHA-256
       directo, para encarecer ataques de diccionario contra la frase.
    """
    if not clave_maestra:
        raise ValueError("Se requiere la clave maestra AES-256")
    try:
        crudo = base64.b64decode(clave_maestra, validate=True)
        if len(crudo) == 32:
            return crudo
    except (binascii.Error, ValueError):
        pass
    return hashlib.scrypt(clave_maestra.encode("utf-8"), salt=_SAL_KDF_LAB,
                          n=2 ** 14, r=8, p=1, dklen=32)


def cifrar_aes256_gcm(texto_plano: str, clave_maestra: str) -> dict:
    if not texto_plano:
        return {"nonce_b64": "", "ciphertext_b64": "", "empaquetado": ""}
    aesgcm = AESGCM(derivar_clave_aes256(clave_maestra))
    nonce = os.urandom(LARGO_NONCE)   # nonce nuevo en cada cifrado: nunca se reutiliza
    ciphertext_con_tag = aesgcm.encrypt(nonce, texto_plano.encode("utf-8"), None)
    return {
        "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext_b64": base64.b64encode(ciphertext_con_tag).decode("utf-8"),
        "empaquetado": base64.b64encode(nonce + ciphertext_con_tag).decode("utf-8"),
    }


def descifrar_aes256_gcm(empaquetado_b64: str, clave_maestra: str) -> str:
    """Descifra y verifica la etiqueta GCM.

    A diferencia de la ofuscación, una clave errónea o un dato alterado
    SE DETECTA: la verificación de la etiqueta falla y se lanza ValueError.
    """
    if not empaquetado_b64:
        return ""
    aesgcm = AESGCM(derivar_clave_aes256(clave_maestra))
    try:
        datos = base64.b64decode(empaquetado_b64.encode("utf-8"), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("El dato cifrado no es base64 válido")
    if len(datos) < LARGO_NONCE + LARGO_TAG:
        raise ValueError("Payload inválido (demasiado corto)")
    nonce, ciphertext_con_tag = datos[:LARGO_NONCE], datos[LARGO_NONCE:]
    try:
        return aesgcm.decrypt(nonce, ciphertext_con_tag, None).decode("utf-8")
    except InvalidTag:
        raise ValueError("Etiqueta GCM inválida: clave incorrecta o dato alterado")


def hashear_password_argon2(password: str) -> str:
    if not password:
        return ""
    return hasher_argon2.hash(password)


def verificar_password_argon2(hash_almacenado: str, password_candidata: str) -> bool:
    if not hash_almacenado or not password_candidata:
        return False
    try:
        return hasher_argon2.verify(hash_almacenado, password_candidata)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
