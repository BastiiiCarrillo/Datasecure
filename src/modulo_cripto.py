import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

hasher_argon2 = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16
)

def derivar_clave_aes256(clave_maestra: str) -> bytes:
    return hashlib.sha256(clave_maestra.encode("utf-8")).digest()

def cifrar_aes256_gcm(texto_plano: str, clave_maestra: str) -> dict:
    if not texto_plano:
        return {"nonce_b64": "", "ciphertext_b64": "", "empaquetado": ""}
    clave_bytes = derivar_clave_aes256(clave_maestra)
    aesgcm = AESGCM(clave_bytes)
    nonce = os.urandom(12)
    datos_bytes = texto_plano.encode("utf-8")
    ciphertext_con_tag = aesgcm.encrypt(nonce, datos_bytes, None)
    empaquetado_bytes = nonce + ciphertext_con_tag
    empaquetado_b64 = base64.b64encode(empaquetado_bytes).decode("utf-8")
    return {
        "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext_b64": base64.b64encode(ciphertext_con_tag).decode("utf-8"),
        "empaquetado": empaquetado_b64
    }

def descifrar_aes256_gcm(empaquetado_b64: str, clave_maestra: str) -> str:
    if not empaquetado_b64:
        return ""
    clave_bytes = derivar_clave_aes256(clave_maestra)
    aesgcm = AESGCM(clave_bytes)
    datos_empaquetados = base64.b64decode(empaquetado_b64.encode("utf-8"))
    if len(datos_empaquetados) < 28:
        raise ValueError("Payload inválido")
    nonce = datos_empaquetados[:12]
    ciphertext_con_tag = datos_empaquetados[12:]
    datos_descifrados = aesgcm.decrypt(nonce, ciphertext_con_tag, None)
    return datos_descifrados.decode("utf-8")

def hashear_password_argon2(password: str) -> str:
    if not password:
        return ""
    return hasher_argon2.hash(password)

def verificar_password_argon2(hash_almacenado: str, password_candidata: str) -> bool:
    if not hash_almacenado or not password_candidata:
        return False
    try:
        return hasher_argon2.verify(hash_almacenado, password_candidata)
    except VerifyMismatchError:
        return False
    except Exception:
        return False
