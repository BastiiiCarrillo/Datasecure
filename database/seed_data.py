import os
from database.db_manager import (
    inicializar_bd,
    obtener_conexion,
    registrar_auditoria,
    guardar_usuario_protegido,
    DB_TYPE
)
from src.motor_ofuscacion import ofuscar_pipeline
from src.modulo_cripto import cifrar_aes256_gcm, hashear_password_argon2

DATOS_FICTICIOS = [
    ("carlos_mora", "Clave#2026!"),
    ("ana.valenzuela", "A$egur4da*99"),
    ("admin_test", "Adm!n#R3d2026"),
    ("juan_perez01", "Jperez%_88$"),
    ("sofia.castillo", "S0f!a_Pass#7"),
    ("operador_norte", "Op#Norte!4321"),
    ("diego.soto", "D1eg0*S0t0&24"),
    ("valeria_rojas", "V@l3r1a!992"),
    ("sistema_audit", "Aud!t#S1st3m4_0"),
    ("claudia_m", "Cl@ud1a$2026?"),
    ("pedro_ñuñez", "Clave#2026!")
]

def cargar_datos_iniciales(forzar: bool = False):
    inicializar_bd()
    conn = obtener_conexion()
    cursor = conn.cursor()

    if forzar:
        cursor.execute("DELETE FROM usuarios_ficticios")
        cursor.execute("DELETE FROM usuarios_protegidos")
        if DB_TYPE != "mariadb":
            conn.commit()

    cursor.execute("SELECT COUNT(*) as total FROM usuarios_ficticios")
    res = cursor.fetchone()
    total = res["total"] if isinstance(res, dict) else res[0]

    if total == 0:
        for user, pwd in DATOS_FICTICIOS:
            if DB_TYPE == "mariadb":
                cursor.execute(
                    "INSERT INTO usuarios_ficticios (username, password) VALUES (%s, %s)",
                    (user, pwd)
                )
            else:
                cursor.execute(
                    "INSERT INTO usuarios_ficticios (username, password) VALUES (?, ?)",
                    (user, pwd)
                )
        if DB_TYPE != "mariadb":
            conn.commit()
        registrar_auditoria("SEED_DATA", "Carga inicial de cuentas ficticias")
        print(f"[OK] Cuentas originales insertadas en {DB_TYPE.upper()}")
    else:
        print(f"[INFO] {total} cuentas originales ya presentes")

    conn.close()

    # Guardado automatico obligatorio de los datos ofuscados en usuarios_protegidos
    conn_chk = obtener_conexion()
    cursor_chk = conn_chk.cursor()
    cursor_chk.execute("SELECT COUNT(*) as total FROM usuarios_protegidos")
    res_prot = cursor_chk.fetchone()
    total_prot = res_prot["total"] if isinstance(res_prot, dict) else res_prot[0]
    conn_chk.close()

    if total_prot == 0 or forzar:
        clave_lab = os.getenv("LAB_SECRET_KEY", "LabKey#2026")
        clave_maestra = os.getenv("AES_MASTER_KEY", "ClaveMaestraDataSecure2026!")

        conn_orig = obtener_conexion()
        c_orig = conn_orig.cursor()
        c_orig.execute("SELECT id, username, password FROM usuarios_ficticios ORDER BY id ASC")
        filas = c_orig.fetchall()
        conn_orig.close()

        for f in filas:
            fila_dict = dict(f)
            uid = fila_dict["id"]
            u_orig = fila_dict["username"]
            p_orig = fila_dict["password"]

            try:
                u_ofusc = ofuscar_pipeline(u_orig, clave_lab)["final"]
                p_ofusc = ofuscar_pipeline(p_orig, clave_lab)["final"]
                u_aes = cifrar_aes256_gcm(u_orig, clave_maestra)["empaquetado"]
                p_argon = hashear_password_argon2(p_orig)

                guardar_usuario_protegido(
                    id_original=uid,
                    username_ofuscado=u_ofusc,
                    password_ofuscado=p_ofusc,
                    username_aes=u_aes,
                    password_argon2=p_argon
                )
            except Exception as e:
                print(f"Error ofuscando registro {uid}: {e}")

        registrar_auditoria("PROCESAMIENTO_AUTOMATICO", "Guardado automatico de datos ofuscados en la BD")
        print(f"[OK] Datos ofuscados y protegidos guardados exitosamente en {DB_TYPE.upper()}")
    else:
        print(f"[INFO] {total_prot} registros ofuscados ya almacenados en usuarios_protegidos")

if __name__ == "__main__":
    cargar_datos_iniciales(forzar=True)
