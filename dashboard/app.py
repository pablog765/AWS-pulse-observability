"""AWS Pulse - dashboard local (Streamlit) de observabilidad y seguridad multicuenta, solo lectura.

Ejecutar:  streamlit run app.py      (o con los lanzadores iniciar_dashboard.*)
"""
from __future__ import annotations

import os
import subprocess
import threading
import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import awsdata as A

ORG = os.environ.get("AWS_PULSE_ORG", "")
st.set_page_config(page_title="AWS Pulse" + (f" · {ORG}" if ORG else ""), layout="wide")

AZUL, ROJO, NARANJA, AMARILLO, VERDE, GRIS = "#1F4E79", "#C00000", "#E46C0A", "#BF8F00", "#2E7D32", "#7F7F7F"
SEV_COLOR = {"CRITICAL": ROJO, "HIGH": NARANJA, "MEDIUM": AMARILLO, "LOW": VERDE}
# Perfiles por defecto: variable AWS_PULSE_PROFILES ("prod dev network security") o los de ~/.aws/config
DEFAULT_PROFILES = os.environ.get("AWS_PULSE_PROFILES", "").split()
TTL = 300  # segundos que se reutilizan los datos antes de volver a consultar AWS

st.markdown("""
<style>
.badge{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:0.82rem;font-weight:600;margin-right:6px}
.card{border:1px solid rgba(128,128,128,.35);border-radius:10px;padding:12px 16px;margin-bottom:10px}
.small{font-size:0.85rem;opacity:.8}
</style>""", unsafe_allow_html=True)


def badge(text, color):
    return f'<span class="badge" style="background:{color}">{text}</span>'


# ------------------------------------------------------------------ cache
@st.cache_data(ttl=TTL, show_spinner=False)
def c_identity(p): return A.identity(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_ec2(p): return A.ec2_instances(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_status(p): return A.instance_status(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_alarms(p): return A.alarms(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_vpn(p): return A.vpn_tunnels(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_rds(p): return A.rds_instances(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_rds_metrics(p, db_id, db, hours): return A.rds_metrics(p, db, hours)
@st.cache_data(ttl=3600, show_spinner=False)
def c_mem(p, cls): return A.instance_memory_gb(p, cls)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_waf(p): return A.waf_acls(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_waf_traffic(p, name, days): return A.waf_traffic(p, name, days)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_waf_rules(p, days): return A.waf_counted_by_rule(p, days)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_nfw(p): return A.network_firewalls(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_fms(p): return A.fms_policies(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_sh(p, n): return A.securityhub_findings(p, n)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_ct(p, days): return A.cloudtrail_changes(p, days)


def per_account(fn, profiles, *args):
    """Ejecuta fn(perfil, *args) en paralelo. Devuelve ({perfil: resultado}, {perfil: error})."""
    res, errs = {}, {}

    def run(p):
        try:
            return p, fn(p, *args), None
        except A.SessionExpired as e:
            return p, None, f"Sesión no válida: {e}"
        except A.AwsError as e:
            return p, None, str(e)

    for p, r, e in A.parallel(run, profiles):
        if e:
            errs[p] = e
        else:
            res[p] = r
    return res, errs


def show_errors(errs):
    if not errs:
        return
    if any("Sesión" in e for e in errs.values()):
        st.warning("La sesión SSO no está activa en: " + ", ".join(errs) + ". Ve a **Sesión** e inicia sesión.")
    for p, e in errs.items():
        if "Sesión" not in e:
            st.caption(f"{p}: {e}")


def flat(res: dict) -> list:
    return [x for v in res.values() for x in (v or [])]


# ------------------------------------------------------------------ sidebar
sessions, cfg_profiles = A.read_aws_config()
with st.sidebar:
    st.markdown(f"### AWS Pulse\n<span class='small'>{ORG + ' · ' if ORG else ''}solo lectura</span>", unsafe_allow_html=True)
    page = st.radio("Módulo", ["Sesión", "Resumen", "Salud y VPN", "Bases de datos (RDS)", "WAF y firewalls",
                               "Security Hub", "Cambios recientes"], index=1, label_visibility="collapsed")
    st.divider()
    opts = sorted(set(cfg_profiles) | set(DEFAULT_PROFILES))
    profiles = st.multiselect("Cuentas", opts, default=[p for p in DEFAULT_PROFILES if p in opts] or opts[:4])
    sso_session = st.selectbox("Sesión SSO", sessions or ["mi-sso"], help="Nombre del bloque [sso-session] en ~/.aws/config")
    A.REGION = st.text_input("Región", A.REGION)
    if st.button("Actualizar datos ahora", width="stretch"):
        st.cache_data.clear()
        st.rerun()
    st.caption(f"Los datos se reutilizan {TTL // 60} min para no repetir consultas.")

if not profiles:
    st.info("Selecciona al menos una cuenta en la barra lateral.")
    st.stop()


# ================================================================== SESIÓN
class LoginRunner:
    """Ejecuta `aws sso login --use-device-code` en segundo plano y guarda su salida."""

    def __init__(self, session):
        env = {**os.environ, "AWS_PAGER": "", "PYTHONUNBUFFERED": "1", "BROWSER": "echo"}
        self.proc = subprocess.Popen(["aws", "sso", "login", "--sso-session", session, "--use-device-code", "--no-browser"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        self.lines, self.started = [], time.time()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            self.lines.append(line.rstrip())

    @property
    def done(self):
        return self.proc.poll() is not None


def page_session():
    st.header("Sesión y conexión")
    st.write("Estado del acceso SSO de cada cuenta. Un solo inicio de sesión sirve para todas.")
    ids = A.parallel(c_identity, profiles)
    df = pd.DataFrame(ids)
    ok = (df["estado"] == "OK").sum()
    c1, c2 = st.columns([1, 3])
    c1.metric("Cuentas con sesión", f"{ok} de {len(df)}")
    with c2:
        st.dataframe(df[["perfil", "estado", "cuenta", "rol", "usuario"]], hide_index=True, width="stretch")

    st.subheader("Iniciar sesión SSO")
    run = st.session_state.get("login")
    col1, col2 = st.columns(2)
    if col1.button("Iniciar sesión", type="primary", width="stretch", disabled=bool(run and not run.done)):
        try:
            st.session_state["login"] = LoginRunner(sso_session)
        except FileNotFoundError:
            st.error("No se encontró AWS CLI en el PATH.")
        time.sleep(3)
        st.rerun()
    if col2.button("Verificar sesión", width="stretch"):
        st.cache_data.clear()
        st.rerun()

    run = st.session_state.get("login")
    if run:
        text = "\n".join(run.lines)
        url = next((w for w in text.split() if w.startswith("https://") and "device" in w), None)
        code = next((l.strip() for l in run.lines if len(l.strip()) == 9 and l.strip()[4] == "-"), None)
        if url:
            st.link_button("Abrir la página de autorización", url)
        if code:
            st.markdown(f"Código de verificación: **`{code}`**")
        st.code(text or "Iniciando…", language="text")
        if run.done:
            if run.proc.returncode == 0:
                st.success("Sesión iniciada. Pulsa **Verificar sesión** para actualizar el estado.")
            else:
                st.error("El inicio de sesión no se completó. Revisa el mensaje y vuelve a intentarlo.")
        else:
            st.info("Autoriza el acceso en el navegador con el código mostrado y luego pulsa **Verificar sesión**.")
    st.caption(f"Equivalente en terminal: `aws sso login --sso-session {sso_session} --use-device-code`")


# ================================================================== RESUMEN
def page_summary():
    st.header("Resumen del ecosistema")
    with st.spinner("Consultando las cuentas…"):
        ids = {i["perfil"]: i for i in A.parallel(c_identity, profiles)}
        live = [p for p in profiles if ids[p]["estado"] == "OK"]
        if not live:
            st.warning("No hay sesión activa. Ve a **Sesión** e inicia sesión.")
            return
        sin = [p for p in profiles if p not in live]
        if sin:
            st.warning(f"Sin sesión en: {', '.join(sin)}. El resumen solo incluye las cuentas con sesión activa.")
        ec2, e1 = per_account(c_ec2, live)
        al, e2 = per_account(c_alarms, live)
        st_, e3 = per_account(c_status, live)
        vpn, e4 = per_account(c_vpn, live)
        waf, e5 = per_account(c_waf, live)
        rds, e6 = per_account(c_rds, live)
    ec2f, alf, vpnf, waff, rdsf, stf = flat(ec2), flat(al), flat(vpn), flat(waf), flat(rds), flat(st_)
    running = sum(1 for i in ec2f if i["estado"] == "running")
    up = sum(1 for t in vpnf if t["estado"] == "UP")
    g_total = sum(w["grupos"] for w in waff)
    g_block = sum(w["grupos_bloqueando"] for w in waff)

    k = st.columns(6)
    k[0].metric("Cuentas con sesión", f"{len(live)}/{len(profiles)}", border=True)
    k[1].metric("EC2 en ejecución", running, border=True)
    k[2].metric("Alarmas activas", len(alf), border=True)
    k[3].metric("Túneles VPN arriba", f"{up}/{len(vpnf)}" if vpnf else "-", border=True)
    k[4].metric("Bloqueo WAF", f"{g_block}/{g_total}" if g_total else "-", help="Grupos de reglas del WAF que bloquean / total", border=True)
    k[5].metric("Bases de datos", len(rdsf), border=True)

    def estado(cond_rojo, cond_amarillo):
        return ("Crítico", ROJO) if cond_rojo else ("Atención", NARANJA) if cond_amarillo else ("Normal", VERDE)

    down_vpn = [t["vpn"] for t in vpnf if t["estado"] != "UP"]
    filas = [
        ("Disponibilidad de servidores", *estado(any(x["instancia"] != "ok" or x["sistema"] != "ok" for x in stf), bool(stf)),
         (f"{sum(1 for x in stf if x['instancia'] != 'ok' or x['sistema'] != 'ok')} con fallas; "
          f"{sum(1 for x in stf if x['evento'] != '-')} con mantenimiento programado por AWS") if stf else "Sin fallas de estado"),
        ("Alarmas de CloudWatch", *estado(len(alf) > 2, bool(alf)), ", ".join(a["alarma"] for a in alf[:4]) or "Sin alarmas activas"),
        ("Enlaces VPN", *estado(any(t["estado"] != "UP" for t in vpnf), False),
         f"Caídos: {', '.join(sorted(set(down_vpn)))}" if down_vpn else ("Todos arriba" if vpnf else "Sin VPN en las cuentas elegidas")),
        ("Protección web (WAF)", *estado(g_total and g_block == 0, g_block < g_total),
         f"{g_block} de {g_total} grupos bloquean; logging: {sum(w['logging'] for w in waff)} de {len(waff)} WAF" if waff else "Sin WAF"),
        ("Bases de datos", *estado(any(a["metrica"] == "CPUUtilization" for a in alf), False),
         f"{len(rdsf)} instancias; {sum(1 for d in rdsf if d['cifrada'] == 'No')} sin cifrar; {sum(1 for d in rdsf if not d['respaldo_dias'])} sin respaldo automático"),
    ]
    st.subheader("Semáforo")
    html = "".join(f"<div class='card'>{badge(e, c)} <b>{a}</b><br><span class='small'>{d}</span></div>" for a, e, c, d in filas)
    st.markdown(html, unsafe_allow_html=True)
    show_errors({**e1, **e2, **e3, **e4, **e5, **e6})
    st.caption("Security Hub y los cambios de CloudTrail se consultan en sus módulos porque tardan más.")


# ============================================================ SALUD Y VPN
def page_health():
    st.header("Salud de servidores y enlaces VPN")
    with st.spinner("Consultando EC2, alarmas y VPN…"):
        ec2, e1 = per_account(c_ec2, profiles)
        al, e2 = per_account(c_alarms, profiles)
        stt, e3 = per_account(c_status, profiles)
        vpn, e4 = per_account(c_vpn, profiles)
    show_errors({**e1, **e2, **e3, **e4})

    st.subheader("Enlaces VPN Site-to-Site")
    v = pd.DataFrame(flat(vpn))
    if v.empty:
        st.info("No hay VPN en las cuentas seleccionadas (las VPN suelen estar en la cuenta de red).")
    else:
        for name, g in v.groupby("vpn", sort=False):
            n_up = (g["estado"] == "UP").sum()
            e, c = ("OK: redundancia completa", VERDE) if n_up == len(g) else ("Sin redundancia", NARANJA) if n_up else ("CAÍDA", ROJO)
            st.markdown(f"<div class='card'>{badge(e, c)} <b>{name}</b> <span class='small'>· par remoto "
                        f"{g['par_remoto'].iloc[0]} ({g['nombre_par'].iloc[0]}) · {g['ruteo'].iloc[0]}</span></div>",
                        unsafe_allow_html=True)
        st.dataframe(v[["vpn", "tunel_aws", "estado", "desde", "horas_en_estado", "rutas", "horas_caido_24h", "detalle"]],
                     hide_index=True, width="stretch",
                     column_config={"desde": st.column_config.DatetimeColumn("Desde (hora local)", format="YYYY-MM-DD HH:mm"),
                                    "horas_en_estado": "Horas en ese estado", "horas_caido_24h": "Horas caído (24 h)",
                                    "tunel_aws": "Túnel AWS"})
        fig = px.bar(v, x="horas_caido_24h", y=v["vpn"] + " · " + v["tunel_aws"], orientation="h",
                     color="estado", color_discrete_map={"UP": VERDE, "DOWN": ROJO},
                     labels={"horas_caido_24h": "Horas con caída en las últimas 24 h", "y": ""}, height=60 + 40 * len(v))
        fig.update_layout(margin=dict(l=0, r=10, t=10, b=0), legend_title_text="Estado")
        st.plotly_chart(fig, width="stretch")

    st.subheader("Alarmas activas")
    a = pd.DataFrame(flat(al))
    if a.empty:
        st.success("Sin alarmas en estado ALARM.")
    else:
        st.dataframe(a, hide_index=True, width="stretch",
                     column_config={"desde": st.column_config.DatetimeColumn("Desde", format="YYYY-MM-DD HH:mm")})

    s = pd.DataFrame(flat(stt))
    if not s.empty:
        st.subheader("Instancias con fallas o mantenimiento programado")
        st.dataframe(s, hide_index=True, width="stretch")

    st.subheader("Inventario EC2")
    e = pd.DataFrame(flat(ec2))
    if not e.empty:
        c = st.columns(4)
        c[0].metric("Instancias", len(e), border=True)
        c[1].metric("En ejecución", (e["estado"] == "running").sum(), border=True)
        c[2].metric("Con IP pública", (e["ip_publica"] != "-").sum(), border=True)
        c[3].metric("Sin IMDSv2", (e["imdsv2"] == "No").sum(), border=True)
        st.dataframe(e, hide_index=True, width="stretch",
                     column_config={"encendida": st.column_config.DatetimeColumn("Encendida (EC2)", format="YYYY-MM-DD HH:mm")})


# ======================================================================= RDS
def page_rds():
    st.header("Bases de datos (RDS)")
    with st.spinner("Buscando bases de datos…"):
        rds, errs = per_account(c_rds, profiles)
    show_errors(errs)
    dbs = flat(rds)
    if not dbs:
        st.info("No se encontraron bases de datos RDS en las cuentas seleccionadas.")
        return
    hours = {"Última hora": 1, "Últimas 6 horas": 6, "Últimas 24 horas": 24, "Últimos 7 días": 168}[
        st.segmented_control("Ventana", ["Última hora", "Últimas 6 horas", "Últimas 24 horas", "Últimos 7 días"],
                             default="Últimas 24 horas") or "Últimas 24 horas"]
    st.dataframe(pd.DataFrame(dbs).drop(columns=["aurora"]), hide_index=True, width="stretch")
    st.caption("Umbrales del semáforo: CPU > 85 % crítico y > 70 % atención; retardo de réplica > 1 s atención y > 30 s crítico.")

    for db in dbs:
        with st.spinner(f"Métricas de {db['id']}…"):
            try:
                df = c_rds_metrics(db["cuenta"], db["id"], db, hours)
            except (A.AwsError, A.SessionExpired) as e:
                st.caption(f"{db['id']}: {e}")
                continue
        st.markdown("---")
        total_mem = c_mem(db["cuenta"], db["clase"])
        last = df.iloc[-1] if not df.empty else pd.Series(dtype=float)
        cpu, mem, conn, lag = (last.get(k) for k in ("cpu", "mem", "conn", "lag"))
        cpu_max = df["cpu"].max() if "cpu" in df else None
        if cpu is not None and cpu > 85 or (lag is not None and lag > 30):
            e, c = "Crítico", ROJO
        elif cpu is not None and cpu > 70 or (lag is not None and lag > 1):
            e, c = "Atención", NARANJA
        else:
            e, c = "Normal", VERDE
        st.markdown(f"{badge(e, c)} <b>{db['id']}</b> <span class='small'>· {db['cuenta']} · {db['rol']} · "
                    f"{db['motor']} · {db['clase']}</span>", unsafe_allow_html=True)
        if df.empty:
            st.caption("Sin datos de CloudWatch en la ventana elegida.")
            continue
        k = st.columns(4)
        k[0].metric("CPU actual", f"{cpu:.0f} %" if cpu is not None else "-",
                    help=f"Máximo en la ventana: {cpu_max:.0f} %" if cpu_max is not None else None, border=True)
        if mem is not None and total_mem:
            k[1].metric("Memoria en uso", f"{100 * (1 - mem / total_mem):.0f} %", help=f"Libre: {mem:.1f} GB de {total_mem:.0f} GB", border=True)
        else:
            k[1].metric("Memoria libre", f"{mem:.1f} GB" if mem is not None else "-", border=True)
        k[2].metric("Conexiones", f"{conn:.0f}" if conn is not None else "-", border=True)
        k[3].metric("Retardo de réplica", f"{lag:.2f} s" if lag is not None else "No aplica", border=True)

        cols = st.columns(4 if "lag" in df else 3)
        spec = [("cpu", "CPU (%)", 85), ("mem", "Memoria libre (GB)", None), ("conn", "Conexiones", None)]
        if "lag" in df:
            spec.append(("lag", "Retardo de réplica (s)", 1))
        for col, (key, title, thr) in zip(cols, spec):
            if key not in df:
                continue
            fig = px.area(df, y=key, labels={"index": "", key: ""}, title=title, height=220)
            fig.update_traces(line_color=AZUL, fillcolor="rgba(31,78,121,0.15)")
            if thr is not None:
                fig.add_hline(y=thr, line_dash="dot", line_color=ROJO)
            fig.update_layout(margin=dict(l=0, r=0, t=36, b=0), showlegend=False, title_font_size=13)
            col.plotly_chart(fig, width="stretch", key=f"{db['cuenta']}-{db['id']}-{key}")


# =================================================================== WAF
def page_waf():
    st.header("WAF y firewalls")
    days = st.segmented_control("Ventana de tráfico", [1, 7, 14, 30], default=7, format_func=lambda d: "1 día" if d == 1 else f"{d} días") or 7
    with st.spinner("Consultando WAF, Network Firewall y Firewall Manager…"):
        waf, e1 = per_account(c_waf, profiles)
        nfw, e2 = per_account(c_nfw, profiles)
    show_errors({**e1, **e2})

    c = st.columns(len(profiles))
    for col, p in zip(c, profiles):
        n = nfw.get(p)
        col.markdown(f"<div class='card'><b>{p}</b><br>Network Firewall: "
                     f"{badge('Sí: ' + ', '.join(n), VERDE) if n else badge('No', GRIS)}<br>"
                     f"WAF: {badge(str(len(waf.get(p) or [])), AZUL if waf.get(p) else GRIS)}</div>", unsafe_allow_html=True)

    for p, acls in waf.items():
        for w in acls:
            st.markdown("---")
            blocking = w["grupos_bloqueando"] > 0 and w["reglas_count_total"] == 0
            e, col = ("Bloquea", VERDE) if blocking else ("Parcial", NARANJA) if w["grupos_bloqueando"] else ("Solo monitorea", ROJO)
            st.markdown(f"### {w['nombre']}\n{badge(e, col)}{badge('Logging activo', VERDE) if w['logging'] else badge('Sin logging', ROJO)}"
                        f"{badge('Defecto: ' + w['accion_defecto'], GRIS)}<span class='small'> · cuenta {p} · protege: "
                        f"{', '.join(w['recursos']) or 'ningún recurso'}</span>", unsafe_allow_html=True)
            k = st.columns(3)
            k[0].metric("Grupos de reglas", w["grupos"], border=True)
            k[1].metric("Grupos que bloquean", w["grupos_bloqueando"], border=True)
            k[2].metric("Reglas forzadas a Count", w["reglas_count_total"], border=True)
            st.dataframe(pd.DataFrame(w["reglas"])[["fase", "prioridad", "detalle", "accion_efectiva", "reglas_en_count", "tipo"]],
                         hide_index=True, width="stretch",
                         column_config={"detalle": "Grupo de reglas", "accion_efectiva": "Acción efectiva",
                                        "reglas_en_count": "Reglas en Count", "fase": "Fase (orden)"})

            try:
                t = c_waf_traffic(p, w["nombre"], days)
            except (A.AwsError, A.SessionExpired) as ex:
                st.caption(str(ex))
                t = pd.DataFrame()
            if not t.empty:
                tot = t.sum()
                k = st.columns(3)
                k[0].metric("Permitidas", f"{int(tot.get('Permitidas', 0)):,}".replace(",", " "), border=True)
                k[1].metric("Detectadas sin bloquear", f"{int(tot.get('Detectadas (Count)', 0)):,}".replace(",", " "), border=True)
                k[2].metric("Bloqueadas", f"{int(tot.get('Bloqueadas', 0)):,}".replace(",", " "), border=True)
                fig = go.Figure()
                for name, color in (("Detectadas (Count)", NARANJA), ("Bloqueadas", VERDE)):
                    if name in t:
                        fig.add_bar(x=t.index, y=t[name], name=name, marker_color=color)
                fig.update_layout(barmode="group", height=280, margin=dict(l=0, r=0, t=30, b=0),
                                  title="Solicitudes detectadas y bloqueadas por día", title_font_size=13)
                st.plotly_chart(fig, width="stretch", key=f"t-{p}-{w['nombre']}")

        try:
            r = c_waf_rules(p, days)
        except (A.AwsError, A.SessionExpired):
            r = pd.DataFrame()
        if not r.empty:
            r = r.head(15).copy()
            r["tipo"] = r["regla"].map(lambda x: "Posible falso positivo" if x.startswith(("SizeRestrictions", "NoUserAgent")) else "Probable ataque")
            fig = px.bar(r.iloc[::-1], x="solicitudes", y="regla", orientation="h", color="tipo", log_x=True,
                         color_discrete_map={"Posible falso positivo": GRIS, "Probable ataque": ROJO},
                         title=f"Reglas que más detectan ({p}, escala logarítmica)", height=80 + 28 * len(r))
            fig.update_layout(margin=dict(l=0, r=0, t=36, b=0), title_font_size=13, legend_title_text="")
            st.plotly_chart(fig, width="stretch", key=f"r-{p}")

    st.markdown("---")
    st.subheader("Firewall Manager")
    admin, pols = None, []
    for prof in profiles:  # las políticas solo se ven desde la cuenta administradora de FMS
        try:
            admin, pols = c_fms(prof)
        except (A.AwsError, A.SessionExpired):
            continue
        if pols:
            break
    if not admin:
        st.info("Firewall Manager no está configurado.")
        return
    st.write(f"Cuenta administradora: **{admin}**")
    if not pols:
        st.caption("Las políticas solo se ven desde la cuenta administradora: inclúyela en las cuentas seleccionadas.")
    for pol in pols:
        st.markdown(f"<div class='card'><b>{pol['politica']}</b> · {pol['tipo']} sobre {pol['aplica_a']}<br>"
                    f"Auto-remediación: {pol['auto_remedia']} · Alcance: {pol['alcance']} · Solo recursos con: {pol['solo_tags']} · "
                    f"Logging: {badge(pol['logging'], VERDE if pol['logging'] == 'Sí' else ROJO)}</div>", unsafe_allow_html=True)
        if pol["cumplimiento"]:
            st.dataframe(pd.DataFrame(pol["cumplimiento"]), hide_index=True, width="stretch")


# =========================================================== SECURITY HUB
def page_sh():
    st.header("Security Hub")
    n = st.select_slider("Hallazgos a leer por cuenta", [500, 1000, 1500, 3000], value=1500,
                         help="Más hallazgos tardan más en descargarse.")
    with st.spinner("Descargando hallazgos (puede tardar 1-2 minutos la primera vez)…"):
        res, errs = per_account(c_sh, profiles, n)
        ec2, _ = per_account(c_ec2, profiles)
    show_errors(errs)
    frames = [d for d in res.values() if d is not None and not d.empty]
    if not frames:
        st.info("Sin hallazgos activos o Security Hub no habilitado en las cuentas seleccionadas.")
        return
    df = pd.concat(frames, ignore_index=True)
    names = {i["id"]: i["nombre"] for i in flat(ec2)}
    df["recurso_corto"] = df["recurso_corto"].map(lambda r: names.get(r, r))

    f1, f2, f3 = st.columns(3)
    cuentas = f1.multiselect("Cuenta", sorted(df["cuenta"].unique()), default=sorted(df["cuenta"].unique()))
    sev = f2.multiselect("Severidad", ["CRITICAL", "HIGH", "MEDIUM"], default=["CRITICAL", "HIGH"])
    cat = f3.multiselect("Categoría", sorted(df["categoria"].unique()), default=sorted(df["categoria"].unique()))
    d = df[df["cuenta"].isin(cuentas) & df["sev"].isin(sev) & df["categoria"].isin(cat)]

    k = st.columns(4)
    for col, s in zip(k, ["CRITICAL", "HIGH", "MEDIUM"]):
        col.metric(s.title(), int((df[df["cuenta"].isin(cuentas)]["sev"] == s).sum()), border=True)
    k[3].metric("En la vista", len(d), border=True)

    g = df[df["cuenta"].isin(cuentas)].groupby(["cuenta", "sev"]).size().reset_index(name="hallazgos")
    fig = px.bar(g, x="cuenta", y="hallazgos", color="sev", color_discrete_map=SEV_COLOR, height=280,
                 category_orders={"sev": ["CRITICAL", "HIGH", "MEDIUM"]}, title="Hallazgos por cuenta y severidad")
    fig.update_layout(margin=dict(l=0, r=0, t=36, b=0), legend_title_text="", title_font_size=13)
    st.plotly_chart(fig, width="stretch")

    t1, t2, t3, t4 = st.tabs(["Configuración insegura", "Parches de Windows", "Vulnerabilidades por paquete", "Todos"])
    with t1:
        c = d[d["categoria"] == "Configuración insegura"].groupby(["control", "que_significa"]) \
            .agg(hallazgos=("sev", "size"), severidad=("sev", "first"), cuentas=("cuenta", lambda x: ", ".join(sorted(set(x))))) \
            .reset_index().sort_values("hallazgos", ascending=False)
        st.dataframe(c, hide_index=True, width="stretch")
    with t2:
        w = d[d["categoria"] == "Parche de Windows"].groupby("recurso_corto") \
            .agg(parches=("titulo", "nunique"), lista=("titulo", lambda x: ", ".join(sorted(set(x))))).reset_index() \
            .rename(columns={"recurso_corto": "servidor"}).sort_values("parches", ascending=False)
        st.dataframe(w, hide_index=True, width="stretch")
    with t3:
        v = d[d["categoria"] == "Vulnerabilidad de software"].groupby("paquete") \
            .agg(cves=("titulo", "nunique"), peor=("sev", lambda x: "CRITICAL" if "CRITICAL" in set(x) else "HIGH" if "HIGH" in set(x) else "MEDIUM"),
                 donde=("recurso_corto", lambda x: ", ".join(sorted(set(x))))).reset_index().sort_values("cves", ascending=False)
        if not v.empty:
            fig = px.bar(v.head(15).iloc[::-1], x="cves", y="paquete", color="peor", orientation="h", color_discrete_map=SEV_COLOR,
                         height=80 + 26 * min(15, len(v)), title="Paquetes con más CVE")
            fig.update_layout(margin=dict(l=0, r=0, t=36, b=0), legend_title_text="", title_font_size=13)
            st.plotly_chart(fig, width="stretch")
        st.dataframe(v, hide_index=True, width="stretch")
    with t4:
        st.dataframe(d[["cuenta", "sev", "categoria", "control", "que_significa", "recurso_corto", "actualizado", "remediacion"]],
                     hide_index=True, width="stretch",
                     column_config={"remediacion": st.column_config.LinkColumn("Cómo corregir", display_text="Ver guía"),
                                    "actualizado": st.column_config.DatetimeColumn("Actualizado", format="YYYY-MM-DD")})
        st.download_button("Descargar CSV", d.to_csv(index=False).encode("utf-8"), "securityhub.csv", "text/csv")


# ================================================================ CAMBIOS
def page_changes():
    st.header("Cambios recientes (CloudTrail)")
    days = st.slider("Días hacia atrás", 1, 30, 7)
    with st.spinner("Leyendo CloudTrail (hasta 3000 eventos por cuenta)…"):
        res, errs = per_account(c_ct, profiles, days)
    show_errors(errs)
    frames = [d for d in res.values() if d is not None and not d.empty]
    if not frames:
        st.info("Sin cambios en el período.")
        return
    df = pd.concat(frames, ignore_index=True)

    f1, f2, f3 = st.columns([1, 1, 1])
    only_s = f1.toggle("Solo eventos sensibles", value=False)
    users = f2.multiselect("Usuario", sorted(df["usuario"].unique()), placeholder="Todos")
    svcs = f3.multiselect("Servicio", sorted(df["servicio"].unique()), placeholder="Todos")
    d = df.copy()
    if only_s:
        d = d[d["sensible"]]
    if users:
        d = d[d["usuario"].isin(users)]
    if svcs:
        d = d[d["servicio"].isin(svcs)]

    k = st.columns(4)
    k[0].metric("Cambios", len(d), border=True)
    k[1].metric("Sensibles", int(d["sensible"].sum()), border=True)
    k[2].metric("Usuarios", d["usuario"].nunique(), border=True)
    k[3].metric("Servicios", d["servicio"].nunique(), border=True)

    if not d.empty:
        tl = d.assign(dia=d["fecha"].dt.date).groupby(["dia", "servicio"]).size().reset_index(name="cambios")
        fig = px.bar(tl, x="dia", y="cambios", color="servicio", height=280, title="Cambios por día y servicio")
        fig.update_layout(margin=dict(l=0, r=0, t=36, b=0), legend_title_text="", title_font_size=13)
        st.plotly_chart(fig, width="stretch")
        top = d.groupby("usuario").size().sort_values(ascending=True).tail(10)
        fig2 = px.bar(x=top.values, y=top.index, orientation="h", title="Usuarios con más cambios", height=70 + 26 * len(top),
                      labels={"x": "cambios", "y": ""})
        fig2.update_traces(marker_color=AZUL)
        fig2.update_layout(margin=dict(l=0, r=0, t=36, b=0), title_font_size=13)
        st.plotly_chart(fig2, width="stretch")

    st.dataframe(d[["fecha", "cuenta", "servicio", "usuario", "accion", "recurso", "que_significa", "sensible"]],
                 hide_index=True, width="stretch",
                 column_config={"fecha": st.column_config.DatetimeColumn("Fecha (hora local)", format="YYYY-MM-DD HH:mm"),
                                "sensible": st.column_config.CheckboxColumn("Sensible")})
    st.download_button("Descargar CSV", d.to_csv(index=False).encode("utf-8"), "cambios.csv", "text/csv")


PAGES = {"Sesión": page_session, "Resumen": page_summary, "Salud y VPN": page_health,
         "Bases de datos (RDS)": page_rds, "WAF y firewalls": page_waf, "Security Hub": page_sh,
         "Cambios recientes": page_changes}
PAGES[page]()
