import streamlit as st
import pandas as pd
from datetime import datetime

from src.motor_ofuscacion import (
    ofuscar_pipeline,
    desofuscar_pipeline,
    sustituir_caracteres,
    transformar_con_clave,
    transponer_caracteres
)
from src.modulo_cripto import (
    cifrar_aes256_gcm,
    descifrar_aes256_gcm,
    hashear_password_argon2,
    verificar_password_argon2
)
from database.db_manager import (
    inicializar_bd,
    obtener_usuarios_ficticios,
    guardar_usuario_protegido,
    obtener_usuarios_protegidos,
    limpiar_usuarios_protegidos,
    obtener_registros_auditoria,
    registrar_auditoria,
    DB_TYPE
)
from database.seed_data import cargar_datos_iniciales

st.set_page_config(
    page_title="DataSecure SpA | Seguridad en Redes",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

inicializar_bd()
cargar_datos_iniciales(forzar=False)

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
    st.image("https://img.icons8.com/fluency/96/shield.png", width=70)
    st.title("DataSecure SpA")
    st.caption("Control de Acceso y Gestión de Claves")
    st.divider()

    st.subheader("Sesión y Roles")
    rol_seleccionado = st.selectbox(
        "Rol de usuario activo:",
        ["Operador / Estudiante", "Administrador de Seguridad"],
        index=0
    )
    nombre_operador = st.text_input("Identificador:", value="basti_operador")

    if rol_seleccionado == "Administrador de Seguridad":
        st.success("Permisos de Administrador activados")
    else:
        st.info("Permisos de Operador activados")

    st.divider()
    st.subheader("Parámetros")
    clave_lab = st.text_input(
        "Clave de Laboratorio:",
        value="LabKey#2026",
        type="password"
    )
    clave_maestra = st.text_input(
        "Clave Maestra AES-256:",
        value="ClaveMaestraDataSecure2026!",
        type="password"
    )

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

tab_ofuscacion, tab_database, tab_cripto, tab_auditoria = st.tabs([
    "Motor de Ofuscación (3 Técnicas)",
    "Base de Datos (10 Cuentas)",
    "Comparativa Criptográfica",
    "Auditoría y Soporte"
])

with tab_ofuscacion:
    st.header("Motor de Ofuscación Reversible")
    st.write("Tres transformaciones consecutivas en secuencia: Sustitución, Clave y Transposición.")

    col_izq, col_der = st.columns([1, 1], gap="large")

    with col_izq:
        st.subheader("1. Pipeline de Ofuscación")
        cuentas_ejemplo = obtener_usuarios_ficticios()
        opciones_cuentas = ["Personalizado..."] + [f"{c['username']} ({c['password']})" for c in cuentas_ejemplo]
        seleccion_ejemplo = st.selectbox("Cargar dato de prueba:", opciones_cuentas)

        if seleccion_ejemplo == "Personalizado...":
            texto_a_ofuscar = st.text_input("Texto a ofuscar:", value="carlos_mora#2026")
        else:
            idx = opciones_cuentas.index(seleccion_ejemplo) - 1
            texto_a_ofuscar = cuentas_ejemplo[idx]["username"]
            st.info(f"Seleccionado: `{texto_a_ofuscar}`")

        btn_ofuscar = st.button("Ejecutar Ofuscación", use_container_width=True)

        if btn_ofuscar:
            if not texto_a_ofuscar:
                st.warning("Ingresa un texto para continuar")
            elif not clave_lab:
                st.warning("Ingresa la clave de laboratorio")
            else:
                res_pipeline = ofuscar_pipeline(texto_a_ofuscar, clave_lab)
                st.session_state["ultimo_ofuscado"] = res_pipeline["final"]
                st.session_state["texto_original_prueba"] = texto_a_ofuscar

                registrar_auditoria("OFUSCACION", f"{nombre_operador} ofuscó texto de {len(texto_a_ofuscar)} caracteres")

                st.success("Ofuscación completada")
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
            value=st.session_state.get("ultimo_ofuscado", "")
        )
        clave_recuperar = st.text_input(
            "Clave para recuperar:",
            value=clave_lab,
            type="password"
        )

        btn_desofuscar = st.button("Ejecutar Recuperación", use_container_width=True)

        if btn_desofuscar:
            if not texto_recuperar:
                st.warning("No hay texto ofuscado")
            elif not clave_recuperar:
                st.warning("Ingresa una clave")
            else:
                res_inv = desofuscar_pipeline(texto_recuperar, clave_recuperar)
                original_guardado = st.session_state.get("texto_original_prueba", "")

                st.markdown(f"""
                - **Entrada:** `{res_inv['ofuscado']}`
                - **1. Destransposición:** `{res_inv['paso1_inv_transposicion']}`
                - **2. Deshacer Clave:** `{res_inv['paso2_inv_clave']}`
                - **3. Desustitución:** `{res_inv['paso3_inv_sustitucion']}`
                """)

                if original_guardado and res_inv["recuperado"] == original_guardado:
                    st.success(f"Recuperación exitosa: `{res_inv['recuperado']}`")
                    registrar_auditoria("DESOFUSCACION_EXITOSA", "Recuperación exitosa con clave")
                else:
                    if clave_recuperar != clave_lab:
                        st.error(f"Clave incorrecta. Resultado obtenido: `{res_inv['recuperado']}`")
                        registrar_auditoria("DESOFUSCACION_FALLIDA", "Intento fallido con clave incorrecta")
                    else:
                        st.write(f"Resultado: `{res_inv['recuperado']}`")

with tab_database:
    st.header("Base de Datos y Cuentas Ficticias")
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])

    with col_btn1:
        if st.button("Procesar las 10 Cuentas", use_container_width=True):
            limpiar_usuarios_protegidos()
            cuentas = obtener_usuarios_ficticios()
            for c in cuentas:
                ofusc_user = ofuscar_pipeline(c["username"], clave_lab)["final"]
                ofusc_pass = ofuscar_pipeline(c["password"], clave_lab)["final"]
                cifrado_aes = cifrar_aes256_gcm(c["username"], clave_maestra)["empaquetado"]
                hash_argon2 = hashear_password_argon2(c["password"])

                guardar_usuario_protegido(
                    id_original=c["id"],
                    username_ofuscado=ofusc_user,
                    password_ofuscado=ofusc_pass,
                    username_aes=cifrado_aes,
                    password_argon2=hash_argon2
                )

            registrar_auditoria("PROCESAMIENTO_TOTAL", "Procesamiento de 10 cuentas")
            st.success("Cuentas procesadas y guardadas")

    with col_btn2:
        if st.button("Verificar Reversibilidad Completa", use_container_width=True):
            protegidos = obtener_usuarios_protegidos()
            if not protegidos:
                st.warning("Primero debes procesar las cuentas")
            else:
                cuentas_orig = {c["id"]: c for c in obtener_usuarios_ficticios()}
                errores = 0
                for p in protegidos:
                    orig = cuentas_orig.get(p["id_original"])
                    user_rec = desofuscar_pipeline(p["username_ofuscado"], clave_lab)["recuperado"]
                    pass_rec = desofuscar_pipeline(p["password_ofuscado"], clave_lab)["recuperado"]
                    user_aes_rec = descifrar_aes256_gcm(p["username_cifrado_aes"], clave_maestra)
                    pass_valida = verificar_password_argon2(p["password_hash_argon2"], orig["password"])

                    if user_rec != orig["username"] or pass_rec != orig["password"] or user_aes_rec != orig["username"] or not pass_valida:
                        errores += 1

                if errores == 0:
                    st.success("100% de los 10 registros verificados con éxito")
                else:
                    st.error(f"{errores} registros presentaron discrepancias")

    with col_btn3:
        if rol_seleccionado == "Administrador de Seguridad":
            if st.button("Limpiar Tabla Protegida", use_container_width=True):
                limpiar_usuarios_protegidos()
                registrar_auditoria("PURGA_DATOS", "Tabla protegida vaciada")
                st.info("Tabla protegida limpia")

    st.markdown("---")
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        st.subheader("Tabla: usuarios_ficticios (Originales)")
        datos_orig = obtener_usuarios_ficticios()
        if datos_orig:
            df_orig = pd.DataFrame(datos_orig)
            st.dataframe(df_orig[["id", "username", "password", "fecha_creacion"]], use_container_width=True)

    with col_t2:
        st.subheader("Tabla: usuarios_protegidos")
        datos_prot = obtener_usuarios_protegidos()
        if datos_prot:
            df_prot = pd.DataFrame(datos_prot)
            st.dataframe(
                df_prot[["id_original", "username_ofuscado", "password_ofuscado", "username_cifrado_aes", "password_hash_argon2"]],
                use_container_width=True
            )
        else:
            st.info("Presiona 'Procesar las 10 Cuentas' para ver los datos protegidos")

with tab_cripto:
    st.header("Comparativa Criptográfica")
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("""
        ### Ofuscación
        - Dificulta la lectura superficial.
        - Vulnerable a análisis de frecuencias.
        - No usa vector de inicialización.
        - No recomendada para producción.
        """)

    with c2:
        st.markdown("""
        ### AES-256-GCM
        - Cifrado simétrico autenticado (AEAD).
        - Para datos que deben recuperarse (usuarios).
        - Nonce único de 12 bytes por operación.
        - Garantiza confidencialidad e integridad.
        """)

    with c3:
        st.markdown("""
        ### Argon2id + Sal
        - Hash irreversible para contraseñas.
        - Parámetros de costo en memoria y tiempo.
        - Sal criptográfica aleatoria única.
        - Resistente a ataques por GPU y tablas arcoíris.
        """)

    st.markdown("---")
    st.subheader("Pruebas en Vivo")

    col_sim1, col_sim2 = st.columns(2)
    with col_sim1:
        st.markdown("#### Cifrado AES-256-GCM")
        texto_cifrar = st.text_input("Texto a cifrar:", value="usuario_confidencial")
        if st.button("Cifrar con AES-256-GCM"):
            res_aes = cifrar_aes256_gcm(texto_cifrar, clave_maestra)
            descifrado_aes = descifrar_aes256_gcm(res_aes["empaquetado"], clave_maestra)
            st.write(f"Nonce (b64): `{res_aes['nonce_b64']}`")
            st.code(res_aes['empaquetado'], language="text")
            st.success(f"Descifrado verificado: `{descifrado_aes}`")

    with col_sim2:
        st.markdown("#### Hash Argon2id + Sal")
        password_probar = st.text_input("Contraseña a hashear:", value="P@ssw0rdCompleja2026!", type="password")
        if st.button("Generar Hash con Argon2id"):
            t_inicio = datetime.now()
            hash_generado = hashear_password_argon2(password_probar)
            ms = (datetime.now() - t_inicio).total_seconds() * 1000
            st.write(f"Tiempo de cálculo: `{ms:.2f} ms`")
            st.code(hash_generado, language="text")
            valida = verificar_password_argon2(hash_generado, password_probar)
            st.success(f"Verificación: {'Válida' if valida else 'Inválida'}")

with tab_auditoria:
    st.header("Bitácora de Auditoría")
    if rol_seleccionado != "Administrador de Seguridad":
        st.warning("Acceso reservado para Administrador de Seguridad")
    else:
        registros = obtener_registros_auditoria(limite=30)
        if registros:
            df_audit = pd.DataFrame(registros)
            st.dataframe(df_audit[["id", "fecha", "accion", "detalle"]], use_container_width=True)
        else:
            st.info("Sin registros de auditoría")
