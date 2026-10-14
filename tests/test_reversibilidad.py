import unittest
from src.motor_ofuscacion import (
    sustituir_caracteres,
    desustituir_caracteres,
    transformar_con_clave,
    destransformar_con_clave,
    transponer_caracteres,
    destransponer_caracteres,
    ofuscar_pipeline,
    desofuscar_pipeline
)
from src.modulo_cripto import (
    cifrar_aes256_gcm,
    descifrar_aes256_gcm,
    hashear_password_argon2,
    verificar_password_argon2
)
from database.seed_data import DATOS_FICTICIOS

class TestMotorOfuscacion(unittest.TestCase):

    def setUp(self):
        self.clave_valida = "LabKey#2026"
        self.clave_erronea = "ClaveIncorrecta!"

    def test_tecnica1_sustitucion_reversible(self):
        texto = "TextoDePrueba_123!#$"
        sustituido = sustituir_caracteres(texto)
        self.assertNotEqual(texto, sustituido)
        recuperado = desustituir_caracteres(sustituido)
        self.assertEqual(texto, recuperado)

    def test_tecnica2_clave_reversible(self):
        texto = "Usuario_Prueba@77"
        transformado = transformar_con_clave(texto, self.clave_valida)
        self.assertNotEqual(texto, transformado)
        recuperado = destransformar_con_clave(transformado, self.clave_valida)
        self.assertEqual(texto, recuperado)

    def test_tecnica3_transposicion_reversible(self):
        texto = "Transposicion_ABC_12345"
        transpuesto = transponer_caracteres(texto)
        self.assertNotEqual(texto, transpuesto)
        recuperado = destransponer_caracteres(transpuesto)
        self.assertEqual(texto, recuperado)

    def test_pipeline_completo_10_cuentas(self):
        for user, pwd in DATOS_FICTICIOS:
            res_user = ofuscar_pipeline(user, self.clave_valida)
            rec_user = desofuscar_pipeline(res_user["final"], self.clave_valida)
            self.assertEqual(user, rec_user["recuperado"])

            res_pwd = ofuscar_pipeline(pwd, self.clave_valida)
            rec_pwd = desofuscar_pipeline(res_pwd["final"], self.clave_valida)
            self.assertEqual(pwd, rec_pwd["recuperado"])

    def test_clave_erronea_falla_recuperacion(self):
        texto_original = "SuperAdmin#2026"
        ofuscado = ofuscar_pipeline(texto_original, self.clave_valida)["final"]
        recuperado_erroneo = desofuscar_pipeline(ofuscado, self.clave_erronea)["recuperado"]
        self.assertNotEqual(texto_original, recuperado_erroneo)

    def test_dos_claves_diferentes(self):
        texto = "Confidencial2026"
        res_clave1 = ofuscar_pipeline(texto, "ClaveAlpha")["final"]
        res_clave2 = ofuscar_pipeline(texto, "ClaveBeta")["final"]
        self.assertNotEqual(res_clave1, res_clave2)

    def test_casos_limite(self):
        vacio = ofuscar_pipeline("", self.clave_valida)
        self.assertEqual(vacio["final"], "")

        simbolos = "!@#$%^&*()_+-=[]{}|;':,.<>?/~`"
        ofuscado_simbolos = ofuscar_pipeline(simbolos, self.clave_valida)["final"]
        recuperado_simbolos = desofuscar_pipeline(ofuscado_simbolos, self.clave_valida)["recuperado"]
        self.assertEqual(simbolos, recuperado_simbolos)

    def test_modulo_criptografico(self):
        secreto = "Usuario_VIP_99"
        cifrado = cifrar_aes256_gcm(secreto, "ClaveMaestraAES256!")
        descifrado = descifrar_aes256_gcm(cifrado["empaquetado"], "ClaveMaestraAES256!")
        self.assertEqual(secreto, descifrado)

        password_real = "MiP@ssSegura2026"
        hash_pwd = hashear_password_argon2(password_real)
        self.assertTrue(verificar_password_argon2(hash_pwd, password_real))
        self.assertFalse(verificar_password_argon2(hash_pwd, "PasswordEquivocada123"))

if __name__ == "__main__":
    unittest.main()
