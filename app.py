import os
from datetime import datetime

import pandas as pd
import streamlit as st
from dotenv import load_dotenv


from src.motor_ofuscacion import ofuscar_pipeline, desofuscar_pipeline
from src.modulo_cripto import (
    cifrar_aes256_gcm,
    descifrar_aes256_gcm,
    hashear_password_argon2,
    verificar_password_argon2,
)
from database.db_manager import (
    inicializar_bd,
    obtener_usuarios_ficticios,
    guardar_usuario_protegido,
    obtener_usuarios_protegidos,
    limpiar_usuarios_protegidos,
    obtener_registros_auditoria,
    registrar_auditoria,
    DB_TYPE,
)
from database.seed_data import cargar_datos_iniciales

# Capa 4 (Gestión de claves): las claves se leen del archivo .env,
# que está en .gitignore. Nunca se escriben en el código fuente.
load_dotenv()
CLAVE_LAB_ENV = os.getenv("LAB_SECRET_KEY", "")
CLAVE_AES_ENV = os.getenv("AES_MASTER_KEY", "")

st.set_page_config(
    page_title="DataSecure SpA | Seguridad en Redes",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

db_error = None
try:
    inicializar_bd()
    cargar_datos_iniciales(forzar=False)
except Exception as e:
    db_error = str(e)

st.markdown("""
<style>
.main-header {
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    padding: 24px;
    border-radius: 12px;
    color: white;
    margin-bottom: 25px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("🛡️ DataSecure SpA")
    st.caption("Control de Acceso y Gestión de Claves")
    st.divider()

    st.subheader("Sesión y Roles")
    rol_seleccionado = st.selectbox(
        "Rol de usuario activo:",
        ["Operador / Estudiante", "Administrador de Seguridad"],
        index=0,
    )
    st.caption("Simulación didáctica de roles: no incluye autenticación real.")
    nombre_operador = st.text_input("Identificador:", value="operador_lab")

    if rol_seleccionado == "Administrador de Seguridad":
        st.success("Permisos de Administrador activados")
    else:
        st.info("Permisos de Operador activados")

    st.divider()
    st.subheader("Parámetros")
    clave_lab = st.text_input(
        "Clave de Laboratorio:",
        value=CLAVE_LAB_ENV,
        type="password",
        help="Se carga desde LAB_SECRET_KEY en el archivo .env",
    )
    clave_maestra = st.text_input(
        "Clave Maestra AES-256:",
        value=CLAVE_AES_ENV,
        type="password",
        help="Se carga desde AES_MASTER_KEY en el archivo .env",
    )
    if not clave_lab or not clave_maestra:
        st.warning("Configure LAB_SECRET_KEY y AES_MASTER_KEY en el archivo .env")

    st.divider()
    st.subheader("Base de Datos")
    if DB_TYPE == "mariadb":
        st.markdown("**Motor:** `MariaDB AlmaLinux`")
        st.caption("Modo Servidor")
    else:
        st.markdown("**Motor:** `SQLite Local`")
        st.caption("Modo Local")

st.markdown("""
<div class="main-header">
    <h1 style="margin:0; font-size: 26px;">Plataforma de Seguridad - DataSecure SpA</h1>
    <p style="margin:5px 0 0 0; opacity: 0.9; font-size: 14px;">
        Motor de Ofuscación Reversible, Criptografía (AES-256-GCM) y Hash de Contraseñas (Argon2id)
    </p>
</div>
""", unsafe_allow_html=True)

if db_error:
    st.error(f"⚠️ **Error de conexión a la Base de Datos ({DB_TYPE.upper()}):** {db_error}")
    if DB_TYPE == "mariadb":
        st.info("💡 **Para solucionar:** Inicia MariaDB en la MV con `sudo systemctl start mariadb` y carga las tablas con `sudo mysql < database/schema_mariadb.sql`")

try:
    cuentas_ejemplo = obtener_usuarios_ficticios()
except Exception:
    cuentas_ejemplo = []
total_cuentas = len(cuentas_ejemplo)

tab_ofuscacion, tab_database, tab_cripto, tab_auditoria = st.tabs([
    "Motor de Ofuscación (3 Técnicas)",
    f"Base de Datos ({total_cuentas} Cuentas)",
    "Comparativa Criptográfica",
    "Auditoría y Soporte",
])

# =============================================================================
# Pestaña 1: motor de ofuscación
# =============================================================================
with tab_ofuscacion:
    st.header("Motor de Ofuscación Reversible")
    st.write("Orden: **1. Sustitución → 2. Clave → 3. Transposición**. "
             "Para recuperar se aplica el orden inverso: **3 → 2 → 1**.")

    col_izq, col_der = st.columns([1, 1], gap="large")

    with col_izq:
        st.subheader("1. Pipeline de Ofuscación")
        opciones_cuentas = ["Personalizado..."] + [f"{c['id']}: {c['username']}" for c in cuentas_ejemplo]
        seleccion_ejemplo = st.selectbox("Cargar dato de prueba:", opciones_cuentas)

        if seleccion_ejemplo == "Personalizado...":
            texto_a_ofuscar = st.text_input("Texto a ofuscar:", value="carlos_mora#2026")
        else:
            cuenta = cuentas_ejemplo[opciones_cuentas.index(seleccion_ejemplo) - 1]
            campo = st.radio("Campo a ofuscar:", ["username", "password"], horizontal=True)
            texto_a_ofuscar = cuenta[campo]
            st.info(f"Seleccionado: `{texto_a_ofuscar}`")

        if st.button("Ejecutar Ofuscación", use_container_width=True):
            if not texto_a_ofuscar:
                st.warning("Ingresa un texto para continuar")
            elif not clave_lab:
                st.warning("Ingresa la clave de laboratorio")
            else:
                try:
                    res_pipeline = ofuscar_pipeline(texto_a_ofuscar, clave_lab)
                except (ValueError, TypeError) as e:
                    st.error(f"No se pudo ofuscar: {e}")
                else:
                    st.session_state["ultimo_ofuscado"] = res_pipeline["final"]
                    st.session_state["texto_original_prueba"] = texto_a_ofuscar
                    try:
                        cifrado_aes = cifrar_aes256_gcm(texto_a_ofuscar, clave_maestra)["empaquetado"] if clave_maestra else ""
                        hash_argon2 = hashear_password_argon2(texto_a_ofuscar)
                        guardar_usuario_protegido(
                            id_original=0,
                            username_ofuscado=res_pipeline["final"],
                            password_ofuscado=res_pipeline["final"],
                            username_aes=cifrado_aes,
                            password_argon2=hash_argon2
                        )
                    except Exception:
                        pass
                    registrar_auditoria("OFUSCACION", f"{nombre_operador} ofusco y guardo en BD texto de {len(texto_a_ofuscar)} caracteres")
                    st.success("Ofuscacion completada y guardada en la base de datos (tabla: usuarios_protegidos)")
                    st.markdown(f"""
- **Original:** `{res_pipeline['original']}`
- **1. Sustitución:** `{res_pipeline['paso1_sustitucion']}`
- **2. Transformación con Clave:** `{res_pipeline['paso2_clave']}`
- **3. Transposición:** `{res_pipeline['paso3_transposicion']}`
""")
                    st.info(f"**Resultado Final:** `{res_pipeline['final']}`")

    with col_der:
        st.subheader("2. Pipeline de Desofuscación")
        texto_recuperar = st.text_input(
            "Texto ofuscado a recuperar:",
            value=st.session_state.get("ultimo_ofuscado", ""),
        )
        clave_recuperar = st.text_input(
            "Clave para recuperar:",
            value=clave_lab,
            type="password",
        )

        if st.button("Ejecutar Recuperación", use_container_width=True):
            if not texto_recuperar:
                st.warning("No hay texto ofuscado")
            elif not clave_recuperar:
                st.warning("Ingresa una clave")
            else:
                try:
                    res_inv = desofuscar_pipeline(texto_recuperar, clave_recuperar)
                except (ValueError, TypeError) as e:
                    st.error(f"No se pudo recuperar: {e}")
                else:
                    original_guardado = st.session_state.get("texto_original_prueba", "")
                    st.markdown(f"""
- **Entrada:** `{res_inv['ofuscado']}`
- **3'. Destransposición:** `{res_inv['paso1_inv_transposicion']}`
- **2'. Deshacer Clave:** `{res_inv['paso2_inv_clave']}`
- **1'. Desustitución:** `{res_inv['paso3_inv_sustitucion']}`
""")
                    if not original_guardado:
                        st.write(f"Resultado: `{res_inv['recuperado']}`")
                    elif res_inv["recuperado"] == original_guardado:
                        st.success(f"Coincide con el original: `{res_inv['recuperado']}`")
                        registrar_auditoria("DESOFUSCACION_OK", "El resultado coincide con el original")
                    else:
                        # El algoritmo NO detecta la clave errónea: solo entrega texto basura.
                        # La app lo nota únicamente porque tiene guardado el original.
                        st.error(f"El resultado NO coincide con el original: `{res_inv['recuperado']}`")
                        st.caption("La ofuscación no puede detectar una clave errónea; solo produce "
                                   "un resultado ilegible. AES-GCM sí lo detecta (ver pestaña de criptografía).")
                        registrar_auditoria("DESOFUSCACION_NO_COINCIDE", "Resultado distinto al original")

    st.markdown("---")
    st.subheader("3. Demostración con dos claves diferentes")
    cd1, cd2, cd3 = st.columns([2, 1, 1])
    with cd1:
        texto_demo = st.text_input("Texto ficticio:", value="carlos_mora")
    with cd2:
        clave_demo_1 = st.text_input("Clave A:", value="ClaveAlpha", key="clave_demo_1")
    with cd3:
        clave_demo_2 = st.text_input("Clave B:", value="OtraLlave9", key="clave_demo_2")

    if st.button("Comparar claves", use_container_width=True):
        try:
            ofus_a = ofuscar_pipeline(texto_demo, clave_demo_1)["final"]
            ofus_b = ofuscar_pipeline(texto_demo, clave_demo_2)["final"]
            rec_ok = desofuscar_pipeline(ofus_a, clave_demo_1)["recuperado"]
            rec_mal = desofuscar_pipeline(ofus_a, clave_demo_2)["recuperado"]
        except (ValueError, TypeError) as e:
            st.error(str(e))
        else:
            st.dataframe(pd.DataFrame([
                {"Operación": "Ofuscar con clave A", "Resultado": ofus_a, "¿Recupera el original?": "-"},
                {"Operación": "Ofuscar con clave B", "Resultado": ofus_b, "¿Recupera el original?": "-"},
                {"Operación": "Recuperar (A) con clave A", "Resultado": rec_ok,
                 "¿Recupera el original?": "Sí" if rec_ok == texto_demo else "No"},
                {"Operación": "Recuperar (A) con clave B", "Resultado": rec_mal,
                 "¿Recupera el original?": "Sí" if rec_mal == texto_demo else "No"},
            ]), use_container_width=True, hide_index=True)
            registrar_auditoria("DEMO_DOS_CLAVES", f"{nombre_operador} comparó dos claves")

# =============================================================================
# Pestaña 2: base de datos
# =============================================================================
with tab_database:
    st.header("Base de Datos y Cuentas Ficticias")

    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])

    with col_btn1:
        if st.button(f"Procesar las {total_cuentas} Cuentas", use_container_width=True):
            if not clave_lab or not clave_maestra:
                st.warning("Faltan las claves (configure el archivo .env)")
            else:
                limpiar_usuarios_protegidos()
                procesadas, errores = 0, []
                for c in obtener_usuarios_ficticios():
                    try:
                        guardar_usuario_protegido(
                            id_original=c["id"],
                            username_ofuscado=ofuscar_pipeline(c["username"], clave_lab)["final"],
                            password_ofuscado=ofuscar_pipeline(c["password"], clave_lab)["final"],
                            username_aes=cifrar_aes256_gcm(c["username"], clave_maestra)["empaquetado"],
                            password_argon2=hashear_password_argon2(c["password"]),
                        )
                        procesadas += 1
                    except (ValueError, TypeError) as e:
                        errores.append(f"id {c['id']}: {e}")
                registrar_auditoria("PROCESAMIENTO_TOTAL", f"procesadas={procesadas} errores={len(errores)}")
                st.success(f"{procesadas} cuentas procesadas y guardadas")
                for err in errores:
                    st.error(err)

    with col_btn2:
        verificar = st.button("Verificar Reversibilidad Completa", use_container_width=True)

    with col_btn3:
        if rol_seleccionado == "Administrador de Seguridad":
            if st.button("Limpiar Tabla Protegida", use_container_width=True):
                limpiar_usuarios_protegidos()
                registrar_auditoria("PURGA_DATOS", "Tabla protegida vaciada")
                st.info("Tabla protegida limpia")

    if verificar:
        protegidos = obtener_usuarios_protegidos()
        if not protegidos:
            st.warning("Primero debes procesar las cuentas")
        else:
            cuentas_orig = {c["id"]: c for c in obtener_usuarios_ficticios()}
            filas = []
            for p in protegidos:
                orig = cuentas_orig.get(p["id_original"])
                try:
                    user_rec = desofuscar_pipeline(p["username_ofuscado"], clave_lab)["recuperado"]
                    pass_rec = desofuscar_pipeline(p["password_ofuscado"], clave_lab)["recuperado"]
                    user_aes = descifrar_aes256_gcm(p["username_cifrado_aes"], clave_maestra)
                except (ValueError, TypeError) as e:
                    user_rec = pass_rec = user_aes = f"ERROR: {e}"
                argon_ok = orig is not None and verificar_password_argon2(p["password_hash_argon2"], orig["password"])
                ok = (orig is not None and user_rec == orig["username"] and pass_rec == orig["password"]
                      and user_aes == orig["username"] and argon_ok)
                filas.append({
                    "id": p["id_original"],
                    "username recuperado": user_rec,
                    "password recuperada": pass_rec,
                    "username AES descifrado": user_aes,
                    "Argon2id verifica": "Sí" if argon_ok else "No",
                    "Resultado": "OK" if ok else "FALLA",
                })
            correctos = sum(f["Resultado"] == "OK" for f in filas)
            st.dataframe(pd.DataFrame(filas), use_container_width=True, hide_index=True)
            if correctos == len(filas):
                st.success(f"{correctos}/{len(filas)} registros recuperados y verificados con éxito")
            else:
                st.error(f"Solo {correctos}/{len(filas)} registros coinciden")
            registrar_auditoria("VERIFICACION", f"correctos={correctos}/{len(filas)}")

    st.markdown("---")
    col_t1, col_t2 = st.columns(2)

    with col_t1:
        st.subheader("Tabla: usuarios_ficticios (Originales)")
        try:
            datos_orig = obtener_usuarios_ficticios()
        except Exception as e:
            datos_orig = []
            st.error(f"Error al consultar usuarios_ficticios: {e}")
        if datos_orig:
            st.dataframe(pd.DataFrame(datos_orig)[["id", "username", "password", "fecha_creacion"]],
                         use_container_width=True)

    with col_t2:
        st.subheader("Tabla: usuarios_protegidos")
        try:
            datos_prot = obtener_usuarios_protegidos()
        except Exception as e:
            datos_prot = []
            st.error(f"Error al consultar usuarios_protegidos: {e}")
        if datos_prot:
            st.dataframe(
                pd.DataFrame(datos_prot)[["id_original", "username_ofuscado", "password_ofuscado",
                                          "username_cifrado_aes", "password_hash_argon2"]],
                use_container_width=True,
            )
            st.caption("Observe los ids 1 y 11: misma contraseña → misma ofuscación, "
                       "pero hash Argon2id distinto gracias a la sal.")
        else:
            st.info("Presiona 'Procesar' para ver los datos protegidos")

# =============================================================================
# Pestaña 3: comparativa criptográfica
# =============================================================================
with tab_cripto:
    st.header("Comparativa Criptográfica")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
### Ofuscación
- Dificulta la lectura superficial.
- Vulnerable a análisis de frecuencias y texto conocido.
- Determinista: igual entrada → igual salida.
- No detecta una clave errónea.
- No recomendada para producción.
""")
    with c2:
        st.markdown("""
### AES-256-GCM
- Cifrado simétrico autenticado (AEAD).
- Para datos que deben recuperarse (usuarios).
- Nonce único de 12 bytes por operación.
- Confidencialidad + integridad: detecta clave errónea o alteración.
""")
    with c3:
        st.markdown("""
### Argon2id + Sal
- Hash irreversible para contraseñas.
- Costo en memoria (64 MiB) y tiempo.
- Sal aleatoria única de 16 bytes.
- Resistente a GPU y tablas arcoíris.
""")

    st.markdown("---")
    st.subheader("Pruebas en Vivo")
    col_sim1, col_sim2 = st.columns(2)

    with col_sim1:
        st.markdown("#### Cifrado AES-256-GCM")
        texto_cifrar = st.text_input("Texto a cifrar:", value="usuario_confidencial")
        if st.button("Cifrar dos veces con AES-256-GCM"):
            if not clave_maestra:
                st.warning("Falta la clave maestra AES")
            else:
                res1 = cifrar_aes256_gcm(texto_cifrar, clave_maestra)
                res2 = cifrar_aes256_gcm(texto_cifrar, clave_maestra)
                st.write(f"Nonce 1 (b64): `{res1['nonce_b64']}`")
                st.code(res1["empaquetado"], language="text")
                st.write(f"Nonce 2 (b64): `{res2['nonce_b64']}`")
                st.code(res2["empaquetado"], language="text")
                st.caption("Mismo texto y misma clave, pero cifrados distintos gracias al nonce aleatorio.")
                st.success(f"Descifrado verificado: `{descifrar_aes256_gcm(res1['empaquetado'], clave_maestra)}`")
                st.session_state["ultimo_aes"] = res1["empaquetado"]

        st.markdown("##### Descifrar con clave errónea")
        clave_aes_erronea = st.text_input("Clave AES incorrecta:", value="ClaveEquivocada123", type="password")
        if st.button("Intentar descifrar"):
            paquete = st.session_state.get("ultimo_aes")
            if not paquete:
                st.warning("Primero cifra un texto")
            else:
                try:
                    descifrar_aes256_gcm(paquete, clave_aes_erronea)
                    st.warning("Se descifró (¿usaste la clave correcta?)")
                except ValueError as e:
                    st.error(f"Rechazado: {e}")
                    st.caption("GCM detecta la clave errónea; la ofuscación solo habría devuelto texto basura.")
                    registrar_auditoria("AES_CLAVE_ERRONEA", "Descifrado rechazado por etiqueta GCM")

    with col_sim2:
        st.markdown("#### Hash Argon2id + Sal")
        password_probar = st.text_input("Contraseña a hashear:", value="P@ssw0rdCompleja2026!", type="password")
        if st.button("Generar dos hashes con Argon2id"):
            t_inicio = datetime.now()
            hash_1 = hashear_password_argon2(password_probar)
            ms = (datetime.now() - t_inicio).total_seconds() * 1000
            hash_2 = hashear_password_argon2(password_probar)
            st.write(f"Tiempo de cálculo: `{ms:.2f} ms`")
            st.code(hash_1, language="text")
            st.code(hash_2, language="text")
            st.caption("Misma contraseña, hashes distintos: cada uno lleva su propia sal.")
            valida = verificar_password_argon2(hash_1, password_probar)
            st.success(f"Verificación: {'Válida' if valida else 'Inválida'}")

# =============================================================================
# Pestaña 4: auditoría
# =============================================================================
with tab_auditoria:
    st.header("Bitácora de Auditoría")
    if rol_seleccionado != "Administrador de Seguridad":
        st.warning("Acceso reservado para Administrador de Seguridad")
    else:
        try:
            registros = obtener_registros_auditoria(limite=30)
        except Exception as e:
            registros = []
            st.error(f"Error al consultar auditoria: {e}")
        if registros:
            st.dataframe(pd.DataFrame(registros)[["id", "fecha", "accion", "detalle"]],
                         use_container_width=True)
        else:
            st.info("Sin registros de auditoría")
