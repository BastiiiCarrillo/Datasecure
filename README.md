# 🛡️ DataSecure SpA - Prototipo Didáctico de Ofuscación y Criptografía

**Asignatura:** Seguridad en Redes (CI3062)  
**Institución:** INACAP - Área Tecnologías de la Información y Ciberseguridad  
**Evaluación:** Evaluación Sumativa N°2 (30%) - Proyecto Práctico Grupal  
**Versión de Entrega:** `v1.0`

---

## 📋 1. Objetivo del Proyecto

El proyecto **DataSecure SpA** consiste en el diseño, desarrollo y pruebas de un prototipo interactivo para la protección de credenciales almacenadas en bases de datos. 

El sistema implementa:
1. **Un motor de ofuscación de 3 técnicas consecutivas y reversibles** (Sustitución, Clave de Laboratorio y Transposición) para ilustrar sus limitaciones.
2. **Un módulo criptográfico de grado industrial** basado en **AES-256-GCM** (para información que debe recuperarse) y **Argon2id + sal** (para almacenamiento seguro e irreversible de contraseñas).
3. **Persistencia dual híbrida** con soporte tanto para base de datos local (**SQLite**) como para entorno corporativo (**MariaDB en servidor Linux tipo Red Hat / AlmaLinux**).
4. **Interfaz gráfica interactiva (Capa 1)** desarrollada con **Streamlit**, provista de control de acceso por roles (Operador vs. Administrador) y bitácora de auditoría.

---

## 🏛️ 2. Arquitectura del Sistema (5 Capas)

El diseño sigue estrictamente el diagrama oficial de **Arquitectura Segura del Sistema**:

* **Capa 1 (Presentación):** Interfaz Web moderna desarrollada con Streamlit (`app.py`), con autenticación de operadores y panel de control.
* **Capa 2 (Aplicación):** 
  * `src/motor_ofuscacion.py`: Pipeline con las 3 técnicas de ofuscación secuenciales y sus operaciones inversas.
  * `src/modulo_cripto.py`: Implementación de AES-256-GCM con Nonce de 12 bytes y hashing Argon2id con parámetros de costo OWASP.
* **Capa 3 (Datos):** Tablas `usuarios_ficticios` (10 registros originales), `usuarios_protegidos` (datos procesados) y `auditoria` (registro de operaciones).
* **Capa 4 (Gestión de Claves):** Aislamiento de claves maestras fuera del código fuente mediante variables de entorno (`.env`).
* **Capa 5 (Soporte):** Bitácora de eventos y trazabilidad en base de datos, versionado colaborativo en Git con exclusión de secretos vía `.gitignore`.

---

## ⚙️ 3. Las Tres Técnicas de Ofuscación

| N° | Técnica | Descripción Algorítmica | Operación Inversa |
| :---: | :--- | :--- | :--- |
| **1** | **Sustitución** | Desplazamiento fijo documentado ($K = 47$) sobre el conjunto ASCII imprimible (95 caracteres). | Desplazamiento inverso ($-47$). |
| **2** | **Uso de Clave** | Transformación polialfabética dependiente de la clave de laboratorio (`LabKey#2026`) y la posición del caracter. | Sustracción modular del valor de la clave según posición. |
| **3** | **Transposición** | Reordenamiento por rieles alternados (índices pares agrupados primero, seguidos de índices impares). | Reconstrucción intercalada de pares e impares. |

> **Nota pedagógica:** Si se intenta desofuscar con una clave distinta a la original, el algoritmo produce un resultado corrupto e ilegible, demostrando la dependencia estricta de la clave en la Técnica 2.

---

## 🚀 4. Instalación y Ejecución

### Requisitos Previos
* Python 3.10 o superior (Verificado en Python 3.13)
* Git

### Paso 1: Clonar el Repositorio
```bash
git clone https://github.com/tu-usuario/datasecure_app.git
cd datasecure_app
```

### Paso 2: Crear y Activar Entorno Virtual (Opcional pero recomendado)
```bash
python -m venv venv
# En Windows:
.\venv\Scripts\activate
# En Linux (AlmaLinux / Red Hat):
source venv/bin/activate
```

### Paso 3: Instalar Dependencias
```bash
pip install -r requirements.txt
```

### Paso 4: Configurar Variables de Entorno
Copiar la plantilla de ejemplo:
```bash
cp .env.example .env
```
Por defecto, viene configurado en modo **SQLite Local** (`DB_TYPE=sqlite`). Para conectar a la máquina virtual AlmaLinux con MariaDB, editar `.env` y definir `DB_TYPE=mariadb` junto a la IP del servidor.

### Paso 5: Cargar Datos Iniciales
```bash
python -m database.seed_data
```

### Paso 6: Iniciar la Aplicación Web
```bash
streamlit run app.py
```
La aplicación se abrirá automáticamente en tu navegador en `http://localhost:8501`.

---

## 🧪 5. Pruebas Automatizadas y Verificación

El proyecto incluye una suite de pruebas unitarias que valida todos los requisitos de la rúbrica (reversibilidad de 10 registros, clave errónea, caracteres especiales, entradas vacías y criptografía):

```bash
python -m unittest tests/test_reversibilidad.py
```

**Resultados de la prueba:**
```text
Ran 8 tests in 0.156s
OK
```

---

## 🔒 6. Seguridad y Gestión de Repositorio

En estricto cumplimiento de los estándares de ciberseguridad:
* El archivo `.gitignore` prohíbe explícitamente la subida de:
  * Archivos `.env` con claves o contraseñas reales.
  * Archivos de base de datos locales (`*.db`, `*.sqlite`).
  * Entornos virtuales (`venv/`) y cachés (`__pycache__/`).
* Se provee `.env.example` con valores genéricos de muestra.
* Las 10 cuentas de prueba son **100% ficticias** y diseñadas exclusivamente para laboratorio didáctico.
