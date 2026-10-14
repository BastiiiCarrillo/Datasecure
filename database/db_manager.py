import os
import sqlite3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()
DB_FILE = os.getenv("DB_FILE", os.path.join(os.path.dirname(__file__), "datasecure.db"))
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "datasecure_db")

def obtener_conexion():
    if DB_TYPE == "mariadb":
        import pymysql
        return pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
    else:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

def inicializar_bd():
    conn = obtener_conexion()
    cursor = conn.cursor()

    if DB_TYPE == "mariadb":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios_ficticios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                password VARCHAR(100) NOT NULL,
                fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios_protegidos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                id_original INT,
                username_ofuscado TEXT NOT NULL,
                password_ofuscado TEXT NOT NULL,
                username_cifrado_aes TEXT,
                password_hash_argon2 TEXT,
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auditoria (
                id INT AUTO_INCREMENT PRIMARY KEY,
                accion VARCHAR(100) NOT NULL,
                detalle TEXT NOT NULL,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios_ficticios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios_protegidos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                id_original INTEGER,
                username_ofuscado TEXT NOT NULL,
                password_ofuscado TEXT NOT NULL,
                username_cifrado_aes TEXT,
                password_hash_argon2 TEXT,
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auditoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                accion TEXT NOT NULL,
                detalle TEXT NOT NULL,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()

    conn.close()

def registrar_auditoria(accion: str, detalle: str):
    try:
        conn = obtener_conexion()
        cursor = conn.cursor()
        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if DB_TYPE == "mariadb":
            cursor.execute(
                "INSERT INTO auditoria (accion, detalle, fecha) VALUES (%s, %s, %s)",
                (accion, detalle, ahora)
            )
        else:
            cursor.execute(
                "INSERT INTO auditoria (accion, detalle, fecha) VALUES (?, ?, ?)",
                (accion, detalle, ahora)
            )
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error auditoria: {e}")

def obtener_usuarios_ficticios():
    conn = obtener_conexion()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, fecha_creacion FROM usuarios_ficticios ORDER BY id ASC")
    filas = cursor.fetchall()
    conn.close()
    return [dict(f) for f in filas]

def guardar_usuario_protegido(id_original: int, username_ofuscado: str, password_ofuscado: str, username_aes: str, password_argon2: str):
    conn = obtener_conexion()
    cursor = conn.cursor()
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if DB_TYPE == "mariadb":
        cursor.execute("""
            INSERT INTO usuarios_protegidos (id_original, username_ofuscado, password_ofuscado, username_cifrado_aes, password_hash_argon2, fecha_registro)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (id_original, username_ofuscado, password_ofuscado, username_aes, password_argon2, ahora))
    else:
        cursor.execute("""
            INSERT INTO usuarios_protegidos (id_original, username_ofuscado, password_ofuscado, username_cifrado_aes, password_hash_argon2, fecha_registro)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (id_original, username_ofuscado, password_ofuscado, username_aes, password_argon2, ahora))
        conn.commit()

    conn.close()

def obtener_usuarios_protegidos():
    conn = obtener_conexion()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios_protegidos ORDER BY id ASC")
    filas = cursor.fetchall()
    conn.close()
    return [dict(f) for f in filas]

def limpiar_usuarios_protegidos():
    conn = obtener_conexion()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios_protegidos")
    if DB_TYPE != "mariadb":
        conn.commit()
    conn.close()

def obtener_registros_auditoria(limite: int = 50):
    conn = obtener_conexion()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM auditoria ORDER BY id DESC LIMIT {limite}")
    filas = cursor.fetchall()
    conn.close()
    return [dict(f) for f in filas]
