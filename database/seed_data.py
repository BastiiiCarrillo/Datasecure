from database.db_manager import inicializar_bd, obtener_conexion, registrar_auditoria, DB_TYPE

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
    ("claudia_m", "Cl@ud1a$2026?")
]

def cargar_datos_iniciales(forzar: bool = False):
    inicializar_bd()
    conn = obtener_conexion()
    cursor = conn.cursor()

    if forzar:
        cursor.execute("DELETE FROM usuarios_ficticios")
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
        print(f"[OK] 10 cuentas insertadas en {DB_TYPE.upper()}")
    else:
        print(f"[INFO] {total} cuentas ya presentes")

    conn.close()

if __name__ == "__main__":
    cargar_datos_iniciales(forzar=True)
