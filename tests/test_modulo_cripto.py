"""Pruebas del módulo criptográfico de referencia (AES-256-GCM y Argon2id)."""
import base64
import unittest

from src.modulo_cripto import (
    cifrar_aes256_gcm,
    derivar_clave_aes256,
    descifrar_aes256_gcm,
    generar_clave_maestra,
    hashear_password_argon2,
    verificar_password_argon2,
)

CLAVE = "ClaveMaestraAES256!"


class TestAESGCM(unittest.TestCase):
    def test_cifrar_y_descifrar(self):
        cifrado = cifrar_aes256_gcm("Usuario_VIP_99", CLAVE)
        self.assertEqual(descifrar_aes256_gcm(cifrado["empaquetado"], CLAVE), "Usuario_VIP_99")

    def test_clave_erronea_es_detectada(self):
        cifrado = cifrar_aes256_gcm("Usuario_VIP_99", CLAVE)["empaquetado"]
        with self.assertRaises(ValueError):
            descifrar_aes256_gcm(cifrado, "OtraClaveMaestra!")

    def test_dato_alterado_es_detectado(self):
        datos = bytearray(base64.b64decode(cifrar_aes256_gcm("Usuario_VIP_99", CLAVE)["empaquetado"]))
        datos[-1] ^= 0x01   # se altera un bit de la etiqueta
        with self.assertRaises(ValueError):
            descifrar_aes256_gcm(base64.b64encode(bytes(datos)).decode(), CLAVE)

    def test_mismo_texto_cifrados_distintos(self):
        a = cifrar_aes256_gcm("pedro_ñuñez", CLAVE)
        b = cifrar_aes256_gcm("pedro_ñuñez", CLAVE)
        self.assertNotEqual(a["nonce_b64"], b["nonce_b64"])
        self.assertNotEqual(a["empaquetado"], b["empaquetado"])

    def test_clave_base64_aleatoria(self):
        clave = generar_clave_maestra()
        self.assertEqual(derivar_clave_aes256(clave), base64.b64decode(clave))
        cifrado = cifrar_aes256_gcm("dato", clave)["empaquetado"]
        self.assertEqual(descifrar_aes256_gcm(cifrado, clave), "dato")

    def test_frase_se_deriva_a_32_bytes(self):
        self.assertEqual(len(derivar_clave_aes256(CLAVE)), 32)

    def test_entrada_invalida(self):
        with self.assertRaises(ValueError):
            descifrar_aes256_gcm("no-es-base64!!", CLAVE)
        with self.assertRaises(ValueError):
            derivar_clave_aes256("")


class TestArgon2id(unittest.TestCase):
    def test_verificacion(self):
        h = hashear_password_argon2("MiP@ssSegura2026")
        self.assertTrue(h.startswith("$argon2id$"))
        self.assertTrue(verificar_password_argon2(h, "MiP@ssSegura2026"))
        self.assertFalse(verificar_password_argon2(h, "PasswordEquivocada123"))

    def test_sal_hace_hashes_distintos(self):
        # Contraseña repetida (ids 1 y 11): hashes distintos por la sal
        self.assertNotEqual(hashear_password_argon2("Clave#2026!"), hashear_password_argon2("Clave#2026!"))

    def test_hash_invalido(self):
        self.assertFalse(verificar_password_argon2("no-es-un-hash", "x"))
        self.assertFalse(verificar_password_argon2("", "x"))


if __name__ == "__main__":
    unittest.main()
