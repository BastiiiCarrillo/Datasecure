"""Integración con el motor de base de datos.

- SQLite: siempre se ejecuta, sobre un archivo temporal.
- MariaDB: solo con RUN_MARIADB_TESTS=1 y DB_TYPE=mariadb en el .env
  (ATENCIÓN: vacía y vuelve a llenar usuarios_protegidos).
"""
import os
import tempfile
import unittest
from pathlib import Path

import database.db_manager as dbm
import database.seed_data as seed
from src.modulo_cripto import cifrar_aes256_gcm, descifrar_aes256_gcm
from src.motor_ofuscacion import desofuscar_pipeline, ofuscar_pipeline

CLAVE_LAB, CLAVE_MALA, CLAVE_AES = "LabKey#2026", "OtraClave", "ClaveMaestraAES256!"


class _Flujo:
    def flujo_completo(self):
        originales = dbm.obtener_usuarios_ficticios()                   # consulta antes de procesar
        self.assertGreaterEqual(len(originales), 10)
        dbm.limpiar_usuarios_protegidos()
        for c in originales:
            dbm.guardar_usuario_protegido(
                id_original=c["id"],
                username_ofuscado=ofuscar_pipeline(c["username"], CLAVE_LAB)["final"],
                password_ofuscado=ofuscar_pipeline(c["password"], CLAVE_LAB)["final"],
                username_aes=cifrar_aes256_gcm(c["username"], CLAVE_AES)["empaquetado"],
                password_argon2="(no se prueba aquí)",
            )
        protegidos = dbm.obtener_usuarios_protegidos()                  # nueva consulta al motor
        self.assertEqual(len(protegidos), len(originales))
        por_id = {c["id"]: c for c in originales}
        for p in protegidos:
            o = por_id[p["id_original"]]
            self.assertNotEqual(p["username_ofuscado"], o["username"])
            self.assertEqual(desofuscar_pipeline(p["username_ofuscado"], CLAVE_LAB)["recuperado"], o["username"])
            self.assertEqual(desofuscar_pipeline(p["password_ofuscado"], CLAVE_LAB)["recuperado"], o["password"])
            self.assertNotEqual(desofuscar_pipeline(p["username_ofuscado"], CLAVE_MALA)["recuperado"], o["username"])
            self.assertEqual(descifrar_aes256_gcm(p["username_cifrado_aes"], CLAVE_AES), o["username"])


class TestSQLite(unittest.TestCase, _Flujo):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._prev = (dbm.DB_TYPE, dbm.DB_FILE, seed.DB_TYPE)
        dbm.DB_TYPE = seed.DB_TYPE = "sqlite"
        dbm.DB_FILE = str(Path(self._tmp.name) / "prueba.db")
        seed.cargar_datos_iniciales(forzar=True)

    def tearDown(self):
        dbm.DB_TYPE, dbm.DB_FILE, seed.DB_TYPE = self._prev
        self._tmp.cleanup()

    def test_flujo_completo_sqlite(self):
        self.flujo_completo()

    def test_auditoria_limite_parametrizado(self):
        dbm.registrar_auditoria("PRUEBA", "registro de prueba")
        self.assertEqual(len(dbm.obtener_registros_auditoria(limite=1)), 1)


@unittest.skipUnless(os.getenv("RUN_MARIADB_TESTS") == "1", "defina RUN_MARIADB_TESTS=1 para probar MariaDB")
class TestMariaDB(unittest.TestCase, _Flujo):
    def test_flujo_completo_mariadb(self):
        self.assertEqual(dbm.DB_TYPE, "mariadb", "DB_TYPE debe ser mariadb en el .env")
        self.flujo_completo()


if __name__ == "__main__":
    unittest.main()
