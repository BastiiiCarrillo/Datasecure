"""Pruebas del motor de ofuscación (técnicas por separado y pipeline completo)."""
import unittest

from src.motor_ofuscacion import (
    ALFABETO,
    PARES_SUSTITUCION,
    TABLA_SUSTITUCION,
    desofuscar_pipeline,
    desustituir_caracteres,
    destransformar_con_clave,
    destransponer_caracteres,
    ofuscar_pipeline,
    sustituir_caracteres,
    transformar_con_clave,
    transponer_caracteres,
)
from database.seed_data import DATOS_FICTICIOS

CLAVE = "LabKey#2026"
CLAVE_ERRONEA = "ClaveIncorrecta!"


class TestTecnica1Sustitucion(unittest.TestCase):
    def test_ejemplo_del_enunciado(self):
        self.assertEqual(sustituir_caracteres("carlos"), "c@rl0s")

    def test_tabla_biyectiva(self):
        self.assertEqual(len(TABLA_SUSTITUCION), 2 * len(PARES_SUSTITUCION))
        self.assertEqual(sorted(sustituir_caracteres(ALFABETO)), sorted(ALFABETO))

    def test_reversible(self):
        for texto in ("TextoDePrueba_123!#$", "ñandú Ñuñoa", ALFABETO, ""):
            self.assertEqual(desustituir_caracteres(sustituir_caracteres(texto)), texto)

    def test_no_es_desplazamiento_fijo(self):
        # Un César movería TODOS los caracteres; la tabla deja intactos los que no están en ella
        self.assertEqual(sustituir_caracteres("crlsw"), "crlsw")


class TestTecnica2Clave(unittest.TestCase):
    def test_reversible(self):
        for texto in ("Usuario_Prueba@77", "pedro_ñuñez", ""):
            self.assertEqual(destransformar_con_clave(transformar_con_clave(texto, CLAVE), CLAVE), texto)

    def test_dos_claves_diferentes(self):
        self.assertNotEqual(transformar_con_clave("carlos", "ClaveAlpha"),
                            transformar_con_clave("carlos", "OtraLlave9"))

    def test_no_es_prefijo_fijo(self):
        # Caracteres repetidos producen salidas distintas (depende de clave y posición)
        self.assertEqual(len(set(transformar_con_clave("aaaaaaaa", "AAAA"))), 8)

    def test_clave_invalida(self):
        for mala in ("", None, "abc"):
            with self.assertRaises(ValueError):
                transformar_con_clave("carlos", mala)


class TestTecnica3Transposicion(unittest.TestCase):
    def test_ejemplo_documentado(self):
        self.assertEqual(transponer_caracteres("ABCDEFG"), "ACEGBDF")

    def test_reversible_largos_0_a_30(self):
        base = "0123456789abcdefghijklmnopqrstu"
        for n in range(len(base) + 1):
            self.assertEqual(destransponer_caracteres(transponer_caracteres(base[:n])), base[:n])

    def test_solo_reordena(self):
        self.assertEqual(sorted(transponer_caracteres("Clave#2026!")), sorted("Clave#2026!"))


class TestPipeline(unittest.TestCase):
    def test_todas_las_cuentas_ficticias(self):
        self.assertGreaterEqual(len(DATOS_FICTICIOS), 10)
        for user, pwd in DATOS_FICTICIOS:
            for texto in (user, pwd):
                with self.subTest(texto=texto):
                    ofus = ofuscar_pipeline(texto, CLAVE)["final"]
                    self.assertNotEqual(ofus, texto)
                    self.assertEqual(desofuscar_pipeline(ofus, CLAVE)["recuperado"], texto)

    def test_orden_inverso_de_las_etapas(self):
        ida = ofuscar_pipeline("carlos", CLAVE)
        vuelta = desofuscar_pipeline(ida["final"], CLAVE)
        self.assertEqual(vuelta["paso1_inv_transposicion"], ida["paso2_clave"])
        self.assertEqual(vuelta["paso2_inv_clave"], ida["paso1_sustitucion"])
        self.assertEqual(vuelta["recuperado"], "carlos")

    def test_clave_erronea_no_recupera(self):
        ofus = ofuscar_pipeline("SuperAdmin#2026", CLAVE)["final"]
        self.assertNotEqual(desofuscar_pipeline(ofus, CLAVE_ERRONEA)["recuperado"], "SuperAdmin#2026")

    def test_dos_claves_y_recuperacion_con_la_correcta(self):
        a = ofuscar_pipeline("Confidencial2026", "ClaveAlpha")["final"]
        b = ofuscar_pipeline("Confidencial2026", "OtraLlave9")["final"]
        self.assertNotEqual(a, b)
        self.assertEqual(desofuscar_pipeline(a, "ClaveAlpha")["recuperado"], "Confidencial2026")
        self.assertEqual(desofuscar_pipeline(b, "OtraLlave9")["recuperado"], "Confidencial2026")

    def test_entrada_vacia(self):
        self.assertEqual(ofuscar_pipeline("", CLAVE)["final"], "")
        self.assertEqual(desofuscar_pipeline("", CLAVE)["recuperado"], "")

    def test_caracteres_especiales(self):
        simbolos = "!@#$%^&*()_+-=[]{}|;':,.<>?/~`\"\\ ¿¡áéíóúñÑ"
        ofus = ofuscar_pipeline(simbolos, CLAVE)["final"]
        self.assertEqual(desofuscar_pipeline(ofus, CLAVE)["recuperado"], simbolos)

    def test_datos_repetidos_son_deterministas(self):
        # Comportamiento esperado y debilidad documentada: igual entrada -> igual salida
        self.assertEqual(ofuscar_pipeline("Clave#2026!", CLAVE)["final"],
                         ofuscar_pipeline("Clave#2026!", CLAVE)["final"])

    def test_caracteres_no_soportados(self):
        for malo in ("emoji😀", "salto\nlinea", "tab\t", "euro€"):
            with self.assertRaises(ValueError):
                ofuscar_pipeline(malo, CLAVE)

    def test_tipo_invalido(self):
        for malo in (None, 123, b"bytes"):
            with self.assertRaises(TypeError):
                ofuscar_pipeline(malo, CLAVE)


if __name__ == "__main__":
    unittest.main()
