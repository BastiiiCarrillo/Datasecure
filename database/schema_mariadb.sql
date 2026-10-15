-- =============================================================================
-- DataSecure SpA - Script de creación y carga (MariaDB en VM AlmaLinux)
-- Ejecutar en la VM:   sudo mysql < database/schema_mariadb.sql
-- ADVERTENCIA: borra y recrea las tablas. Solo datos 100 % FICTICIOS.
-- =============================================================================
CREATE DATABASE IF NOT EXISTS datasecure_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;

-- Usuario de la aplicación con privilegios mínimos (sin DROP / GRANT).
-- Usar la misma contraseña en el .env (que NO se sube al repositorio).
CREATE USER IF NOT EXISTS 'datasecure_user'@'localhost' IDENTIFIED BY 'CambiarEnLaVM_2026';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE ON datasecure_db.* TO 'datasecure_user'@'localhost';

-- Solo si la app corre en el PC anfitrión y MariaDB en la VM:
-- reemplazar 192.168.56.% por la red de su adaptador (o la IP exacta del PC).
CREATE USER IF NOT EXISTS 'datasecure_user'@'192.168.56.%' IDENTIFIED BY 'CambiarEnLaVM_2026';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE ON datasecure_db.* TO 'datasecure_user'@'192.168.56.%';
FLUSH PRIVILEGES;

USE datasecure_db;

DROP TABLE IF EXISTS usuarios_protegidos;
DROP TABLE IF EXISTS auditoria;
DROP TABLE IF EXISTS usuarios_ficticios;

-- Datos originales ficticios (se conservan para comparar)
CREATE TABLE usuarios_ficticios (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  username        VARCHAR(100) NOT NULL,
  password        VARCHAR(100) NOT NULL,
  fecha_creacion  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Resultados: ofuscación (3 técnicas) + AES-256-GCM + Argon2id
CREATE TABLE usuarios_protegidos (
  id                    INT AUTO_INCREMENT PRIMARY KEY,
  id_original           INT,
  username_ofuscado     TEXT NOT NULL,
  password_ofuscado     TEXT NOT NULL,
  username_cifrado_aes  TEXT,
  password_hash_argon2  TEXT,
  fecha_registro        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Bitácora (nunca guarda claves ni datos en claro)
CREATE TABLE auditoria (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  accion   VARCHAR(100) NOT NULL,
  detalle  TEXT NOT NULL,
  fecha    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 11 cuentas ficticias: mayúsculas, minúsculas, números, especiales,
-- ñ/tildes y una contraseña repetida (ids 1 y 11).
INSERT INTO usuarios_ficticios (username, password) VALUES
  ('carlos_mora',    'Clave#2026!'),
  ('ana.valenzuela', 'A$egur4da*99'),
  ('admin_test',     'Adm!n#R3d2026'),
  ('juan_perez01',   'Jperez%_88$'),
  ('sofia.castillo', 'S0f!a_Pass#7'),
  ('operador_norte', 'Op#Norte!4321'),
  ('diego.soto',     'D1eg0*S0t0&24'),
  ('valeria_rojas',  'V@l3r1a!992'),
  ('sistema_audit',  'Aud!t#S1st3m4_0'),
  ('claudia_m',      'Cl@ud1a$2026?'),
  ('pedro_ñuñez',    'Clave#2026!');

INSERT INTO auditoria (accion, detalle) VALUES ('SEED_DATA', 'Carga inicial de cuentas ficticias (script SQL)');

-- Evidencia: consulta de los registros antes del procesamiento
SELECT id, username, password FROM usuarios_ficticios ORDER BY id;
