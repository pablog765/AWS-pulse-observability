"""AWS Pulse - dashboard local (Streamlit) de observabilidad y seguridad multicuenta, solo lectura.

Ejecutar:  streamlit run app.py      (o con los lanzadores iniciar_dashboard.*)
"""
from __future__ import annotations

import hmac
import os
import subprocess
import threading
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import awsdata as A
import finops as F

ORG = os.environ.get("AWS_PULSE_ORG", "")
st.set_page_config(page_title="AWS Pulse" + (f" · {ORG}" if ORG else ""), layout="wide")

# Paleta "claro corporativo": fondo claro tipo consola AWS; estados en tonos oscuros para buen contraste sobre blanco
AZUL, ROJO, NARANJA, AMARILLO, VERDE, GRIS = "#2563EB", "#DC2626", "#EC7211", "#CA8A04", "#16A34A", "#6B7280"
# Severidades: tonos y luminosidad bien distintos (rojo oscuro / ámbar / gris azulado) para distinguirlos incluso con daltonismo
SEV_COLOR = {"CRITICAL": "#B91C1C", "HIGH": "#F59E0B", "MEDIUM": "#94A3B8", "LOW": "#CBD5E1"}
SEV_ES = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}
# Perfiles por defecto: variable AWS_PULSE_PROFILES ("prod dev network security") o los de ~/.aws/config
DEFAULT_PROFILES = os.environ.get("AWS_PULSE_PROFILES", "").split()
TTL = 300  # segundos que se reutilizan los datos antes de volver a consultar AWS

st.markdown("""
<style>
.badge{display:inline-block;padding:2px 10px;border-radius:12px;color:#FFFFFF;font-size:0.82rem;font-weight:600;margin-right:6px}
.card{border:1px solid #D5DBE5;background:#FFFFFF;border-radius:10px;padding:12px 16px;margin-bottom:10px}
[data-testid="stMetric"]{background:#FFFFFF}
h1,h2,h3{font-family:"Space Grotesk",Inter,sans-serif;letter-spacing:-.3px}
.small{font-size:0.85rem;opacity:.85}
.vcard{border:1px solid #D5DBE5;border-left:5px solid;border-radius:10px;padding:10px 16px;margin-bottom:8px;color:#1F2937}
.sevcard{background:#FFFFFF;border:1px solid #D5DBE5;border-left:6px solid;border-radius:10px;padding:10px 16px;margin-bottom:8px}
.sevlbl{font-size:.8rem;font-weight:800;letter-spacing:.6px;color:#6B7280}
.sevnum{font-size:1.9rem;font-weight:700;color:#1F2937;line-height:1.2}
.badge-lg{font-size:1.05rem;padding:5px 16px;border-radius:8px;letter-spacing:.5px}
.dbhead{border:1px solid;border-left:6px solid;border-radius:10px;padding:10px 14px;margin:6px 0 10px;font-size:1.05rem}
.alerta{color:#1F2937;font-size:1.2rem;font-weight:600;background:#FFFFFF;border:1px solid #D5DBE5;border-left:6px solid;
        border-radius:10px;padding:10px 18px;margin:4px 0 10px}
.alerta-sub{font-size:.9rem;font-weight:400;color:#6B7280;margin-top:2px}
.acc-title{font-size:1.15rem;margin-bottom:6px}
.brand{font-family:"Space Grotesk",Inter,sans-serif;font-size:2.3rem;font-weight:800;line-height:1.1;letter-spacing:-.5px;color:#FFFFFF}
.brand span{color:#FF9900}
.brand-sub{font-size:.9rem;color:#C9D3E1;margin:2px 0 6px}
[data-testid="stMain"] h1,[data-testid="stMain"] h2,[data-testid="stMain"] h3{text-align:center}
</style>""", unsafe_allow_html=True)


def badge(text, color):
    return f'<span class="badge" style="background:{color}">{text}</span>'


# ------------------------------------------------------------- acceso
PASSWORD = os.environ.get("AWS_PULSE_PASSWORD", "")
_ip = getattr(st.context, "ip_address", None)
CLIENT_IP = _ip if isinstance(_ip, str) and _ip else "127.0.0.1"  # sin IP conocida = mismo equipo
IS_LOCAL = CLIENT_IP.removeprefix("::ffff:").startswith("127.") or CLIENT_IP in ("::1", "localhost")
if not IS_LOCAL and not PASSWORD:
    st.error("El acceso desde la red está deshabilitado. En el equipo anfitrión define AWS_PULSE_PASSWORD y reinicia el dashboard.")
    st.stop()
if PASSWORD and not IS_LOCAL and not st.session_state.get("auth"):
    st.markdown("### AWS Pulse")
    pw = st.text_input("Contraseña", type="password")
    if pw:
        if hmac.compare_digest(pw, PASSWORD):
            st.session_state["auth"] = True
            st.rerun()
        st.error("Contraseña incorrecta.")
    st.stop()


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
def c_rds_storage(p, db_id, db, since_iso): return A.rds_storage_history(p, db, pd.Timestamp(since_iso).to_pydatetime())
@st.cache_data(ttl=TTL, show_spinner=False)
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
def c_config(p): return A.config_status(p)
@st.cache_data(ttl=TTL, show_spinner=False)
def c_config_find(p, days): return A.config_findings(p, days)
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
    st.markdown(f"<div class='brand'>AWS <span>Pulse</span></div>"
                f"<div class='brand-sub'>{ORG + ' · ' if ORG else ''}solo lectura</div>", unsafe_allow_html=True)
    menu = ["Sesión", "Resumen", "Salud y VPN", "Bases de datos (RDS)", "WAF y firewalls",
            "Security Hub", "AWS Config", "Cambios recientes", "FinOps"]
    if not IS_LOCAL:  # quien entra por la red solo consulta; el login SSO se hace en el equipo anfitrión
        menu.remove("Sesión")
    page = st.radio("Módulo", menu, index=menu.index("Resumen"), label_visibility="collapsed")
    st.divider()
    opts = sorted(set(cfg_profiles) | set(DEFAULT_PROFILES))
    profiles = st.multiselect("Cuentas", opts, default=[p for p in DEFAULT_PROFILES if p in opts] or opts[:4])
    sso_session = st.selectbox("Sesión SSO", sessions or ["mi-sso"], help="Nombre del bloque [sso-session] en ~/.aws/config")
    A.REGION = st.text_input("Región", A.REGION)
    st.caption(f"Horas en {A.TZ_NAME}")
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
def vpn_card(name, g, estado, color):
    mb = g["trafico_24h_mb"].sum(min_count=1) if "trafico_24h_mb" in g else None
    traf = "tráfico 24 h: s/d" if mb is None or pd.isna(mb) else f"tráfico 24 h: {mb:,.0f} MB" if mb >= 1 else "sin tráfico en 24 h"
    up = (g["estado"] == "UP").sum()
    return (f"<div class='vcard' style='border-left-color:{color};background:{color}1F'>{badge(estado, color)} <b>{name}</b>"
            f"<span class='small'> · {up}/{len(g)} túneles arriba · {traf} · par remoto {g['par_remoto'].iloc[0]} "
            f"({g['nombre_par'].iloc[0]}) · {g['ruteo'].iloc[0]}</span></div>")


def vpn_section(v: pd.DataFrame):
    """Separa las VPN en uso de las que no tienen tráfico (o llevan más de un día caídas) y oculta estas últimas."""
    if "trafico_24h_mb" not in v:
        v["trafico_24h_mb"] = None
    info = []
    for name, g in v.groupby("vpn", sort=False):
        mb = g["trafico_24h_mb"].sum(min_count=1)
        n_up = (g["estado"] == "UP").sum()
        dias_caida = (g["estado"] != "UP").all() and (g["horas_en_estado"].fillna(0) >= 24).all()
        sin_uso = (not pd.isna(mb) and mb < 1) or (pd.isna(mb) and dias_caida)
        info.append({"vpn": name, "sin_uso": sin_uso, "n_up": n_up, "n": len(g)})
    info = pd.DataFrame(info)
    usadas, libres = info[~info["sin_uso"]], info[info["sin_uso"]]
    c = st.columns(4)
    c[0].metric("VPN totales", len(info), border=True)
    c[1].metric("En uso", len(usadas), border=True)
    c[2].metric("Sin uso", len(libres), border=True, help="Sin tráfico en 24 h, o con todos los túneles caídos hace más de un día.")
    c[3].metric("Costo de las VPN sin uso", f"${len(libres) * F.P['vpn_h'] * F.H:,.0f}/mes", border=True,
                help=f"USD {F.P['vpn_h']}/h por conexión × {F.H} h (precio de lista).")
    for _, r in usadas.iterrows():
        g = v[v["vpn"] == r["vpn"]]
        e, col = ("Redundancia completa", VERDE) if r["n_up"] == r["n"] else ("Sin redundancia", NARANJA) if r["n_up"] else ("CAÍDA", ROJO)
        st.markdown(vpn_card(r["vpn"], g, e, col), unsafe_allow_html=True)
    if not libres.empty:
        with st.expander(f"VPN sin uso ({len(libres)}): ocultas. Candidatas a revisar o eliminar"):
            for _, r in libres.iterrows():
                st.markdown(vpn_card(r["vpn"], v[v["vpn"] == r["vpn"]], "SIN USO", GRIS), unsafe_allow_html=True)
            st.caption("Antes de eliminar, confirma con el dueño del enlace (puede ser un respaldo que solo se activa en contingencia).")
    ver_todas = st.toggle("Incluir las VPN sin uso en la tabla y el gráfico", value=False) if not libres.empty else True
    vv = v if ver_todas else v[v["vpn"].isin(usadas["vpn"])]
    if vv.empty:
        return
    st.dataframe(vv[["vpn", "tunel_aws", "estado", "desde", "horas_en_estado", "rutas", "trafico_24h_mb", "horas_caido_24h", "detalle"]],
                 hide_index=True, width="stretch",
                 column_config={"vpn": "VPN", "tunel_aws": "Túnel AWS", "estado": "Estado",
                                "desde": st.column_config.DatetimeColumn("Desde (hora local)", format="YYYY-MM-DD HH:mm"),
                                "horas_en_estado": "Horas en ese estado", "rutas": "Rutas",
                                "trafico_24h_mb": st.column_config.NumberColumn("Tráfico 24 h (MB)", format="%.1f"),
                                "horas_caido_24h": "Horas caído (24 h)", "detalle": "Detalle"})
    fig = px.bar(vv, x="horas_caido_24h", y=vv["vpn"] + " · " + vv["tunel_aws"], orientation="h",
                 color="estado", color_discrete_map={"UP": VERDE, "DOWN": ROJO},
                 labels={"horas_caido_24h": "Horas con caída en las últimas 24 h", "y": ""}, height=80 + 40 * len(vv))
    fig.update_layout(margin=dict(l=0, r=10, t=10, b=0), legend_title_text="Estado")
    st.plotly_chart(fig, width="stretch")


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
        vpn_section(v)

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
HIDDEN_DB_FILE = Path(__file__).resolve().parent / ".local" / "ocultar_bd.txt"  # local, ignorado por git


def hidden_dbs() -> set[str]:
    env = {x.strip() for x in os.environ.get("AWS_PULSE_HIDE_DBS", "").split(",") if x.strip()}
    try:
        return env | {l.strip() for l in HIDDEN_DB_FILE.read_text().splitlines() if l.strip() and not l.startswith("#")}
    except OSError:
        return env


def save_hidden_dbs(ids: list[str]):
    HIDDEN_DB_FILE.parent.mkdir(exist_ok=True)
    HIDDEN_DB_FILE.write_text("# Bases de datos que AWS Pulse no muestra en la página RDS (una por línea)\n" + "\n".join(sorted(ids)) + "\n")


def page_rds():
    st.header("Bases de datos (RDS)")
    with st.spinner("Buscando bases de datos…"):
        rds, errs = per_account(c_rds, profiles)
    show_errors(errs)
    todas = flat(rds)
    ocultas = hidden_dbs()
    dbs = [d for d in todas if d["id"] not in ocultas]
    with st.popover(f"Bases ocultas ({len([d for d in todas if d['id'] in ocultas])})"):
        sel = st.multiselect("No mostrar estas bases", sorted(d["id"] for d in todas),
                             default=sorted(d["id"] for d in todas if d["id"] in ocultas),
                             help="Se guarda solo en este equipo (dashboard/.local/ocultar_bd.txt). FinOps las sigue contando: cuestan hasta que se eliminen.")
        if st.button("Guardar"):
            save_hidden_dbs(sel)
            st.rerun()
    if not dbs:
        st.info("No se encontraron bases de datos RDS en las cuentas seleccionadas.")
        return
    hours = {"Última hora": 1, "Últimas 6 horas": 6, "Últimas 24 horas": 24, "Últimos 7 días": 168}[
        st.segmented_control("Ventana", ["Última hora", "Últimas 6 horas", "Últimas 24 horas", "Últimos 7 días"],
                             default="Últimas 24 horas") or "Últimas 24 horas"]
    alert_box = st.container()  # se llena después de leer las métricas
    st.dataframe(pd.DataFrame(dbs).drop(columns=["aurora"]), hide_index=True, width="stretch")
    st.subheader("Rendimiento por base de datos")
    alertas = []
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
        motivo = []
        if cpu is not None and cpu > 70:
            motivo.append(f"CPU {cpu:.0f} % (máx. {cpu_max:.0f} %)")
        if lag is not None and lag > 1:
            motivo.append(f"retardo de réplica {lag:.1f} s")
        if e != "Normal":
            alertas.append((e, db, ", ".join(motivo)))
        st.markdown(f"<div class='dbhead' style='border-color:{c};background:{c}14'>"
                    f"<span class='badge badge-lg' style='background:{c}'>{'⚠ ' if e != 'Normal' else ''}{e.upper()}</span> "
                    f"<b>{db['id']}</b> <span class='small'>· {db['cuenta']} · {db['rol']} · {db['motor']} · {db['clase']}"
                    f"{' · ' + ', '.join(motivo) if motivo else ''}</span></div>", unsafe_allow_html=True)
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
            fig.update_traces(line_color=AZUL, fillcolor="rgba(37,99,235,0.15)")
            if thr is not None:
                fig.add_hline(y=thr, line_dash="dot", line_color=ROJO)
            fig.update_layout(margin=dict(l=0, r=0, t=36, b=0), showlegend=False, title_font_size=13)
            col.plotly_chart(fig, width="stretch", key=f"{db['cuenta']}-{db['id']}-{key}")

    with alert_box:
        for e, db, motivo in sorted(alertas, key=lambda x: x[0] != "Crítico"):
            c = ROJO if e == "Crítico" else NARANJA
            st.markdown(f"<div class='alerta' style='border-left-color:{c}'><span style='color:{c};font-weight:800'>⚠ {e.upper()}</span>"
                        f" · {db['id']}"
                        f"<div class='alerta-sub'>{db['cuenta']} · {db['rol']} · {motivo or 'revisar métricas'}</div></div>",
                        unsafe_allow_html=True)
        if not alertas:
            st.markdown(f"<div class='alerta' style='border-left-color:{VERDE}'><span style='color:{VERDE};font-weight:800'>✔ NORMAL</span>"
                        f" · todas las bases sin alertas</div>",
                        unsafe_allow_html=True)
    st.markdown("---")
    rds_storage_section(dbs)


def rds_storage_section(dbs: list[dict]):
    """Espacio usado/libre de cada base (writer y reader), crecimiento mensual desde abril y proyección."""
    st.subheader("Almacenamiento: espacio usado, libre y crecimiento")
    with st.expander("Ver uso del disco y evolución por cuenta", expanded=False):
        _storage_body(dbs)


def _storage_body(dbs: list[dict]):
    hoy = A.local_now()
    c = st.columns([1, 1, 2])
    since = c[0].date_input("Analizar desde", pd.Timestamp(hoy.year if hoy.month >= 4 else hoy.year - 1, 4, 1).date(),
                            help="Por defecto el 1 de abril. CloudWatch guarda datos diarios hasta 15 meses.")
    horizonte = c[1].selectbox("Proyectar", [3, 6, 12], index=1, format_func=lambda m: f"{m} meses")
    since_ts = pd.Timestamp(since, tz=A.LOCAL_TZ)
    rows, hist, growth = [], [], {}
    for db in dbs:
        try:
            h = c_rds_storage(db["cuenta"], db["id"], db, since_ts.isoformat())
        except (A.AwsError, A.SessionExpired) as e:
            st.caption(f"{db['id']}: {e}")
            continue
        if h.empty or h["usado_gb"].dropna().empty:
            st.caption(f"{db['id']}: sin datos de almacenamiento en CloudWatch desde {since}.")
            continue
        tbl, gb_mes = A.storage_growth(h)
        used = float(h["usado_gb"].dropna().iloc[-1])
        alloc = float(db.get("asignado_gb") or 0) if not db["aurora"] else 0.0
        maxa = float(db.get("max_autoescala_gb") or 0)
        free = alloc - used if alloc else None
        pct = 100 * used / alloc if alloc else None
        rate = 100 * gb_mes / used if gb_mes and used else None  # % mensual respecto al uso actual

        def meses_hasta(limite):
            if not limite:
                return None
            if used >= limite:
                return 0.0
            return (limite - used) / gb_mes if gb_mes and gb_mes > 0 else None

        m80, m100, mmax = meses_hasta(0.8 * alloc), meses_hasta(alloc), meses_hasta(maxa)
        MES = "ene feb mar abr may jun jul ago sep oct nov dic".split()

        def fecha(m):
            if m is None:
                return "-"
            if m == 0:
                return "ya superado"
            f = hoy + pd.Timedelta(days=30.44 * m)
            plazo = "menos de 1 mes" if m < 1 else f"{m:.0f} mes" + ("es" if round(m) != 1 else "")
            return f"{plazo} ({MES[f.month - 1]} {f.year})"

        lleno = fecha(m100)
        if maxa and m100 is not None:
            lleno = f"{lleno} → autoescala; tope {maxa:,.0f} GB en {fecha(mmax)}"
        rows.append({"Base": db["id"], "Rol": db["rol"], "Cuenta": db["cuenta"],
                     "Asignado GB": alloc or None, "Usado GB": round(used, 1), "Libre GB": round(free, 1) if free is not None else None,
                     "% de uso": round(pct, 1) if pct is not None else None,
                     "Crecimiento mensual": round(rate, 2) if rate is not None else None, "GB por mes": round(gb_mes, 1) if gb_mes else None,
                     "Llega al 80 %": fecha(m80), "Se llena (100 %)": lleno,
                     "Autoescalado hasta": f"{db['max_autoescala_gb']} GB" if db.get("max_autoescala_gb") else ("Aurora: automático" if db["aurora"] else "No")})
        hist.append(h.assign(base=db["id"]))
        growth[db["id"]] = (tbl, gb_mes, used, alloc)
    if not rows:
        return
    t = pd.DataFrame(rows)
    hh = pd.concat(hist)
    for cuenta, tc in t.groupby("Cuenta", sort=False):
        with st.container(border=True):
            peor = tc["% de uso"].max()
            col_e = ROJO if peor >= 85 else NARANJA if peor >= 70 else VERDE
            st.markdown(f"<div class='acc-title'>{badge(f'{peor:.0f} % máx.' if pd.notna(peor) else 'Aurora', col_e)} "
                        f"Cuenta <b>{cuenta}</b> <span class='small'>· {len(tc)} base(s)</span></div>", unsafe_allow_html=True)
            storage_account(cuenta, tc.drop(columns="Cuenta"), hh[hh["base"].isin(tc["Base"])], growth, since, horizonte)
    st.caption("Proyección lineal: GB/mes según la tendencia de los últimos 90 días; «crecimiento mensual» = esos GB sobre el uso actual. Con autoescalado, RDS amplía el disco cuando queda < 10 % libre (y se paga el nuevo tamaño). RDS: usado = asignado − FreeStorageSpace "
               "(incluye logs binarios y temporales). Aurora: VolumeBytesUsed del clúster. El reader (réplica) tiene su propio disco "
               "con los mismos datos que el writer. Semáforo: ≥ 70 % atención, ≥ 85 % crítico.")


def storage_account(cuenta, t, hh, growth, since, horizonte):
    """KPIs, uso del disco, evolución y crecimiento mes a mes de las bases de una cuenta."""
    k = st.columns(min(len(t), 4))
    for col, (_, r) in zip(k, t.iterrows()):
        val = f"{r['% de uso']:.0f} % usado" if pd.notna(r["% de uso"]) else f"{r['Usado GB']:,.0f} GB"
        col.metric(f"{r['Base']} · {r['Rol']}", val,
                   delta=f"{r['GB por mes']:+.1f} GB/mes ({r['Crecimiento mensual']:+.1f} %)" if pd.notna(r["GB por mes"]) else None,
                   delta_color="inverse",
                   help=f"Usado {r['Usado GB']:,.1f} GB de {r['Asignado GB'] or '-'} GB · libre {r['Libre GB'] or '-'} GB · "
                        f"llega al 80 % en {r['Llega al 80 %']}", border=True)
    tab1, tab2, tab3 = st.tabs(["Uso y evolución", "Detalle", "Mes a mes"])
    with tab1:
        g1 = g2 = st.container()
        bars = t[t["Asignado GB"].notna()]
        if not bars.empty:
            fig = go.Figure()
            fig.add_bar(y=bars["Base"], x=bars["Usado GB"], orientation="h", name="Usado", marker_color=AZUL,
                        text=[f"{u:,.0f} GB ({p:.0f} %)" for u, p in zip(bars["Usado GB"], bars["% de uso"])], textposition="inside")
            fig.add_bar(y=bars["Base"], x=bars["Libre GB"], orientation="h", name="Libre", marker_color="#D5DBE5",
                        text=[f"{f:,.0f} GB libres" for f in bars["Libre GB"]], textposition="inside", insidetextfont_color="#1F2937")
            fig.add_vline(x=0, line_width=0)
            fig.update_layout(barmode="stack", height=150 + 60 * len(bars), title="Uso del disco", title_font_size=13,
                              margin=dict(l=0, r=0, t=40, b=0), legend=dict(orientation="h", y=-0.3), xaxis_title="GB", yaxis_title="")
            g1.plotly_chart(fig, width="stretch", key=f"uso-{cuenta}")
        else:
            g1.caption("Aurora: el almacenamiento crece solo; no hay espacio libre que medir.")
        fig2 = go.Figure()
        pal = [AZUL, NARANJA, VERDE, "#7C3AED", ROJO]
        for i, (name, g) in enumerate(hh.groupby("base", sort=False)):
            col = pal[i % len(pal)]
            g = g["usado_gb"].dropna()
            fig2.add_scatter(x=g.index, y=g.values, mode="lines", name=f"{name} (real)", line=dict(color=col, width=2))
            tbl, gb_mes, used, alloc = growth[name]
            if gb_mes is not None:
                fut = pd.date_range(g.index[-1], periods=horizonte + 1, freq=pd.DateOffset(months=1))
                fig2.add_scatter(x=fut, y=[used + gb_mes * j for j in range(horizonte + 1)], mode="lines",
                                 name=f"{name} (proyección +{gb_mes:.1f} GB/mes)", line=dict(color=col, dash="dash"))
        allocs = t["Asignado GB"].dropna().unique()
        for al in allocs:
            fig2.add_hline(y=al, line_dash="dot", line_color=GRIS, annotation_text=f"asignado {al:,.0f} GB", annotation_position="top left")
            fig2.add_hline(y=0.8 * al, line_dash="dot", line_color=NARANJA, opacity=0.6,
                           annotation_text=f"80 % ({0.8 * al:,.0f} GB)", annotation_position="bottom left")
        fig2.update_layout(height=440, title=f"Evolución del espacio usado desde {since:%d/%m/%Y} y proyección a {horizonte} meses",
                           title_font_size=13, margin=dict(l=0, r=0, t=40, b=0), yaxis_title="GB usados", xaxis_title="",
                           legend=dict(orientation="h", y=-0.2))
        g2.plotly_chart(fig2, width="stretch", key=f"evol-{cuenta}")
    with tab2:
        st.dataframe(t, hide_index=True, width="stretch",
                     column_config={"% de uso": st.column_config.ProgressColumn("% de uso", format="%.1f %%", min_value=0, max_value=100),
                                    "Crecimiento mensual": st.column_config.NumberColumn("% mensual (sobre uso actual)", format="%.1f %%"),
                                    "GB por mes": st.column_config.NumberColumn("GB por mes (tendencia 90 d)", format="%.1f"),
                                    "Asignado GB": st.column_config.NumberColumn(format="%.0f"),
                                    "Libre GB": st.column_config.NumberColumn(format="%.1f")})
    with tab3:
        frames = [growth[b][0].assign(base=b) for b in t["Base"] if not growth[b][0].empty]
        if frames:
            mm = pd.concat(frames)
            piv = mm.pivot(index="mes", columns="base", values=["usado_gb", "crecimiento_gb", "crecimiento_pct"])
            piv.columns = [f"{b} · {dict(usado_gb='GB usados', crecimiento_gb='GB +/−', crecimiento_pct='% vs mes anterior')[m]}"
                           for m, b in piv.columns]
            st.dataframe(piv.sort_index(axis=1, key=lambda c: c.str.split(" · ").str[0]), width="stretch")
            fig3 = px.bar(mm, x="mes", y="crecimiento_gb", color="base", barmode="group", height=260,
                          title="GB agregados cada mes", color_discrete_sequence=[AZUL, NARANJA, VERDE])
            fig3.update_layout(margin=dict(l=0, r=0, t=40, b=0), title_font_size=13, legend_title_text="", xaxis_title="", yaxis_title="GB")
            st.plotly_chart(fig3, width="stretch", key=f"mes-{cuenta}")


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
    fms_section()


WAF_GROUPS = {  # qué protege cada grupo administrado de AWS y con qué marco de referencia se relaciona
    "AWSManagedRulesCommonRuleSet": ("Ataques web comunes: XSS, inclusión de archivos (LFI/RFI), cuerpos y URLs anómalos",
                                     "OWASP Top 10: A03 Inyección, A05 Configuración insegura"),
    "AWSManagedRulesKnownBadInputsRuleSet": ("Entradas maliciosas conocidas: Log4j/Log4Shell, deserialización Java, rutas de explotación",
                                             "OWASP Top 10: A06 Componentes vulnerables, A08 Integridad"),
    "AWSManagedRulesSQLiRuleSet": ("Inyección SQL en parámetros, cuerpo, cookies y encabezados", "OWASP Top 10: A03 Inyección"),
    "AWSManagedRulesAmazonIpReputationList": ("IPs con mala reputación según inteligencia de amenazas de Amazon (bots, escaneo)",
                                              "NIST 800-53 SI-4 (monitoreo) · inteligencia de amenazas"),
    "AWSManagedRulesAnonymousIpList": ("Tráfico desde VPN anónimas, Tor y hosting", "NIST 800-53 SC-7"),
    "AWSManagedRulesBotControlRuleSet": ("Bots automatizados y scrapers", "OWASP Automated Threats"),
    "AWSManagedRulesLinuxRuleSet": ("Ataques específicos de Linux (LFI)", "OWASP Top 10: A03"),
    "AWSManagedRulesWindowsRuleSet": ("Ataques específicos de Windows (PowerShell)", "OWASP Top 10: A03"),
    "AWSManagedRulesPHPRuleSet": ("Ataques específicos de PHP", "OWASP Top 10: A03"),
    "AWSManagedRulesAdminProtectionRuleSet": ("Acceso externo a páginas de administración", "OWASP Top 10: A01 Control de acceso"),
}
FMS_TYPES = {"WAFV2": "AWS WAF (firewall web)", "SHIELD_ADVANCED": "Shield Advanced (DDoS)", "SECURITY_GROUPS_COMMON": "Security Groups comunes",
             "SECURITY_GROUPS_CONTENT_AUDIT": "Auditoría de Security Groups", "NETWORK_FIREWALL": "Network Firewall", "DNS_FIREWALL": "DNS Firewall"}
RES_TYPES = {"AWS::ElasticLoadBalancingV2::LoadBalancer": "balanceadores ALB", "AWS::CloudFront::Distribution": "distribuciones CloudFront",
             "AWS::ApiGateway::Stage": "APIs de API Gateway", "AWS::EC2::VPC": "VPC", "AWS::EC2::SecurityGroup": "Security Groups"}


@st.cache_data(ttl=TTL, show_spinner=False)
def c_names(ps: tuple) -> dict:
    return A.account_names(list(ps))


def fms_section():
    st.subheader("Firewall Manager: cumplimiento de políticas de seguridad")
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
    names = c_names(tuple(profiles))
    nm = lambda acc: names.get(acc, "Cuenta fuera de tus perfiles")
    st.markdown(f"Cuenta administradora de FMS: **{nm(admin)}** <span class='small'>({admin})</span>", unsafe_allow_html=True)
    with st.expander("¿Qué significa «Cumple» (COMPLIANT) en Firewall Manager?", expanded=False):
        st.markdown("""
**El marco de referencia es la propia política de FMS**, definida por tu organización. *Cumple* significa que **todos los recursos
de esa cuenta que entran en el alcance de la política** (p. ej. los ALB con la etiqueta indicada) **tienen aplicada la protección
que la política exige** (p. ej. el web ACL con sus grupos de reglas). *No cumple* = al menos un recurso no la tiene; la columna
*Recursos sin protección* dice cuántos.

**Lo que «Cumple» NO garantiza:** que las reglas bloqueen. Si un grupo tiene reglas en modo *conteo* (Count), el recurso cumple
la política pero esos ataques solo se registran. Revisa la columna *Acción* de la tabla de reglas.

**Relación con marcos externos:** las reglas administradas de AWS cubren riesgos de **OWASP Top 10**; tener un WAF delante de
aplicaciones públicas responde a **PCI DSS v4.0 req. 6.4.2** y **NIST 800-53 SC-7** (protección de frontera). Security Hub
(estándar AWS Foundational Security Best Practices) evalúa además **WAF.10** (el ACL tiene reglas) y **WAF.11** (logging activo).
""")
    if not pols:
        st.caption("Las políticas solo se ven desde la cuenta administradora: inclúyela en las cuentas seleccionadas.")
    for pol in pols:
        alcance = pol["alcance"]
        if alcance != "Toda la organización":
            alcance = ", ".join(nm(x.strip()) for x in alcance.split(","))
        tipo = FMS_TYPES.get(pol["tipo"], pol["tipo"])
        recursos = RES_TYPES.get(pol["aplica_a"], pol["aplica_a"])
        etiqueta = f" con la etiqueta <b>{pol['solo_tags']}</b>" if pol["solo_tags"] != "-" else ""
        comp = pd.DataFrame(pol["cumplimiento"])
        n_ok = (comp["estado"] == "COMPLIANT").sum() if not comp.empty else 0
        estado = badge(f"{n_ok}/{len(comp)} cuentas cumplen", VERDE if n_ok == len(comp) else NARANJA)
        st.markdown(
            f"<div class='card'>{estado} <b>Política «{pol['politica']}»</b> · {tipo}<br>"
            f"<b>Qué exige:</b> que todos los {recursos}{etiqueta} de <b>{alcance}</b> tengan asociado el web ACL de la política "
            f"(acción por defecto: {pol.get('accion_defecto', '-')}).<br>"
            f"<b>Auto-remediación:</b> {'Sí: FMS lo corrige solo' if pol['auto_remedia'] == 'Sí' else 'No: solo reporta'} · "
            f"<b>Cuentas excluidas:</b> {pol.get('excluye', '-')} · "
            f"<b>Logging:</b> {badge(pol['logging'], VERDE if pol['logging'] == 'Sí' else ROJO)}</div>", unsafe_allow_html=True)
        c1, c2 = st.columns([1, 1])
        with c1:
            st.markdown("**Cumplimiento por cuenta**")
            if comp.empty:
                st.caption("Sin datos de cumplimiento.")
            else:
                t = pd.DataFrame({"Cuenta": comp["cuenta"].map(nm), "ID": comp["cuenta"],
                                  "Estado": comp["estado"].map({"COMPLIANT": "✅ Cumple", "NON_COMPLIANT": "❌ No cumple"}).fillna(comp["estado"]),
                                  "Recursos sin protección": comp["violaciones"].fillna(0).astype(int)})
                st.dataframe(t.sort_values("Estado"), hide_index=True, width="stretch")
        with c2:
            st.markdown("**Reglas que exige la política**")
            g = pd.DataFrame(pol.get("grupos") or [])
            if g.empty:
                st.caption("La política no declara grupos de reglas administrados.")
            else:
                g["Qué protege"] = g["grupo"].map(lambda x: WAF_GROUPS.get(x, ("-", "-"))[0])
                g["Marco de referencia"] = g["grupo"].map(lambda x: WAF_GROUPS.get(x, ("-", "-"))[1])
                g["grupo"] = g["grupo"].str.replace("AWSManagedRules", "", regex=False)
                st.dataframe(g.rename(columns={"grupo": "Grupo", "fase": "Orden", "accion": "Acción"})[
                                 ["Grupo", "Qué protege", "Marco de referencia", "Acción"]], hide_index=True, width="stretch")
        if not comp.empty and pol.get("grupos") and any("conteo" in x["accion"] or "no bloquea" in x["accion"] for x in pol["grupos"]):
            st.warning("Las cuentas aparecen como «Cumple», pero hay reglas en modo conteo: esos ataques se registran y no se bloquean.")


# =========================================================== SECURITY HUB
def page_sh():
    st.header("Security Hub")
    n = st.select_slider("Máximo de hallazgos a descargar por cuenta", [500, 1000, 1500, 3000, 5000], value=1500,
                         help="Security Hub no da un conteo total: se descargan hallazgos hasta este tope (activos, nuevos, "
                              "severidad media o mayor). Más alto = más completo pero más lento.")
    with st.spinner("Descargando hallazgos (puede tardar 1-2 minutos la primera vez)…"):
        res, errs = per_account(c_sh, profiles, n)
        ec2, _ = per_account(c_ec2, profiles)
    show_errors(errs)
    frames = [d for d in res.values() if d is not None and not d.empty]
    if not frames:
        st.info("Sin hallazgos activos o Security Hub no habilitado en las cuentas seleccionadas.")
        return
    df = pd.concat(frames, ignore_index=True)
    topados = [p for p, d in res.items() if d is not None and len(d) >= n]
    if topados:
        st.warning(f"{', '.join(topados)}: se alcanzó el tope de {n:,} hallazgos, hay más sin descargar y los conteos "
                   "de esas cuentas son un mínimo. Sube el máximo para verlos todos.")
    else:
        st.caption(f"Se descargaron todos los hallazgos activos (ninguna cuenta llegó al tope de {n:,}).")
    names = {i["id"]: i["nombre"] for i in flat(ec2)}
    df["recurso_corto"] = df["recurso_corto"].map(lambda r: names.get(r, r))

    f1, f2, f3 = st.columns(3)
    cuentas = f1.multiselect("Cuenta", sorted(df["cuenta"].unique()), default=sorted(df["cuenta"].unique()))
    sev = f2.multiselect("Severidad", ["CRITICAL", "HIGH", "MEDIUM"], default=["CRITICAL", "HIGH"])
    cat = f3.multiselect("Categoría", sorted(df["categoria"].unique()), default=sorted(df["categoria"].unique()))
    d = df[df["cuenta"].isin(cuentas) & df["sev"].isin(sev) & df["categoria"].isin(cat)]

    k = st.columns(4)
    for col, sv in zip(k, ["CRITICAL", "HIGH", "MEDIUM"]):
        n_s = int((df[df["cuenta"].isin(cuentas)]["sev"] == sv).sum())
        col.markdown(f"<div class='sevcard' style='border-left-color:{SEV_COLOR[sv]}'><div class='sevlbl' style='color:{'#64748B' if sv == 'MEDIUM' else SEV_COLOR[sv]}'>"
                     f"{SEV_ES[sv].upper()}</div><div class='sevnum'>{n_s:,}</div></div>", unsafe_allow_html=True)
    k[3].markdown(f"<div class='sevcard' style='border-left-color:{GRIS}'><div class='sevlbl'>EN LA VISTA (FILTROS)</div>"
                  f"<div class='sevnum'>{len(d):,}</div></div>", unsafe_allow_html=True)

    g = df[df["cuenta"].isin(cuentas)].groupby(["cuenta", "sev"]).size().reset_index(name="hallazgos")
    g["Severidad"] = g["sev"].map(SEV_ES)
    fig = px.bar(g, x="cuenta", y="hallazgos", color="Severidad", barmode="group", text="hallazgos", height=320,
                 color_discrete_map={SEV_ES[k_]: v for k_, v in SEV_COLOR.items()},
                 category_orders={"Severidad": ["Crítica", "Alta", "Media"]}, title="Hallazgos por cuenta y severidad")
    fig.update_traces(textposition="outside", cliponaxis=False)
    fig.update_layout(margin=dict(l=0, r=0, t=50, b=0), legend_title_text="", title_font_size=13, xaxis_title="", yaxis_title="Hallazgos")
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


# ============================================================== AWS CONFIG
def page_config():
    st.header("AWS Config")
    st.caption("Config registra la configuración de cada recurso y sus cambios. Es la base de Security Hub, Control Tower y "
               "Firewall Manager: sus reglas se evalúan sobre este inventario.")
    with st.spinner("Consultando AWS Config…"):
        res, errs = per_account(c_config, profiles)
    show_errors(errs)
    est = [v for v in res.values() if v]
    if not est:
        st.info("Sin datos de AWS Config en las cuentas seleccionadas.")
        return

    # ---------- estado por cuenta
    st.subheader("Estado por cuenta")
    cols = st.columns(min(len(est), 4))
    for col, e in zip(cols * 4, est):
        ok = e["grabando"] and e["ultimo_estado"] == "SUCCESS"
        c = VERDE if ok else ROJO
        orig = pd.Series([r["origen"] for r in e["reglas"]]).value_counts()
        col.markdown(f"<div class='sevcard' style='border-left-color:{c}'><div class='sevlbl' style='color:{c}'>"
                     f"{'✔ GRABANDO' if ok else '✖ NO GRABA'}</div><div class='sevnum'>{e['cuenta']}</div>"
                     f"<div class='small'>{e['recursos']:,} recursos · {len(e['reglas'])} reglas · grabador: {e['grabador']}<br>"
                     f"{' · '.join(f'{k}: {v}' for k, v in orig.items()) or 'sin reglas'}</div></div>", unsafe_allow_html=True)
    with st.expander("¿Cómo leer esta página?"):
        st.markdown("""
- **Grabando:** Config está registrando los cambios de configuración. Si una cuenta no graba, Security Hub y Control Tower quedan ciegos.
- **Reglas de Security Hub:** las crea Security Hub (son *service-linked*) y su resultado **se ve en la página Security Hub**, no aquí.
- **Reglas con evaluación propia:** las de Firewall Manager, Control Tower, conformance packs o creadas por ustedes: su cumplimiento aparece abajo.
- **Consultas rápidas:** preguntas al inventario de Config (SQL de solo lectura) para encontrar riesgos o desperdicio sin entrar a la consola.
""")

    # ---------- inventario
    st.subheader("Inventario de recursos")
    inv = pd.DataFrame([x for e in est for x in e["por_tipo"]])
    if not inv.empty:
        inv["tipo_corto"] = inv["tipo"].str.replace("AWS::", "", regex=False)
        top = inv.groupby("tipo_corto")["cantidad"].sum().sort_values(ascending=False).head(15).index.tolist()
        iv = inv[inv["tipo_corto"].isin(top)]
        fig = px.bar(iv, y="tipo_corto", x="cantidad", color="cuenta", orientation="h", height=120 + 26 * len(top),
                     category_orders={"tipo_corto": top}, title="Los 15 tipos de recurso más numerosos",
                     color_discrete_sequence=[AZUL, NARANJA, VERDE, "#7C3AED", GRIS])
        fig.update_layout(margin=dict(l=0, r=0, t=40, b=0), title_font_size=13, legend_title_text="", yaxis_title="", xaxis_title="Recursos")
        st.plotly_chart(fig, width="stretch")
        with st.expander("Ver todos los tipos de recurso"):
            piv = inv.pivot_table(index="tipo", columns="cuenta", values="cantidad", aggfunc="sum", fill_value=0)
            piv["Total"] = piv.sum(axis=1)
            st.dataframe(piv.sort_values("Total", ascending=False), width="stretch")

    # ---------- reglas con evaluación propia
    st.subheader("Reglas con evaluación propia")
    reglas = pd.DataFrame([r for e in est for r in e["reglas"]])
    propias = reglas[reglas["origen"] != "Security Hub"] if not reglas.empty else reglas
    if propias.empty:
        st.caption("Solo hay reglas de Security Hub: revisa su resultado en la página Security Hub.")
    else:
        mapa = {"COMPLIANT": "✅ Cumple", "NON_COMPLIANT": "❌ No cumple", "NOT_APPLICABLE": "No aplica", "INSUFFICIENT_DATA": "Sin datos"}
        pr = propias.assign(estado=propias["estado"].map(mapa).fillna(propias["estado"]))
        n_bad = (propias["estado"] == "NON_COMPLIANT").sum()
        (st.error if n_bad else st.success)(f"{n_bad} regla(s) no cumplen de {len(propias)} con evaluación propia.")
        st.dataframe(pr[["cuenta", "origen", "estado", "control_aws", "recursos_no_cumplen", "regla", "descripcion"]]
                     .sort_values("estado"), hide_index=True, width="stretch",
                     column_config={"cuenta": "Cuenta", "origen": "Origen", "estado": "Estado", "control_aws": "Regla AWS",
                                    "recursos_no_cumplen": "Recursos que no cumplen", "regla": "Nombre", "descripcion": "Descripción"})
    if not reglas.empty:
        n_sh = (reglas["origen"] == "Security Hub").sum()
        if n_sh:
            st.caption(f"Además hay {n_sh:,} reglas creadas por Security Hub (su resultado está en la página Security Hub).")

    # ---------- consultas rápidas
    st.subheader("Consultas rápidas al inventario")
    days = st.select_slider("Recursos cambiados en los últimos", [1, 3, 7, 14, 30], value=7, format_func=lambda d: f"{d} días")
    with st.spinner("Consultando el inventario…"):
        fr, errs2 = per_account(c_config_find, profiles, days)
        ec2, _ = per_account(c_ec2, profiles)
    names = {i["id"]: i["nombre"] for i in flat(ec2)}
    sueltos = pd.DataFrame([x for v in fr.values() if v for x in v["sueltos"]])
    cifr = pd.DataFrame([x for v in fr.values() if v for x in v["sin_cifrar"]])
    camb = pd.DataFrame([x for v in fr.values() if v for x in v["cambios"]])
    k = st.columns(3)
    gb_s = sueltos["gb"].sum() if not sueltos.empty else 0
    k[0].markdown(f"<div class='sevcard' style='border-left-color:{NARANJA if len(sueltos) else VERDE}'><div class='sevlbl'>DISCOS EBS SIN USAR</div>"
                  f"<div class='sevnum'>{len(sueltos)}</div><div class='small'>{gb_s:,.0f} GB · ~{usd(gb_s * F.P['gp3'])}/mes desperdiciados</div></div>",
                  unsafe_allow_html=True)
    k[1].markdown(f"<div class='sevcard' style='border-left-color:{ROJO if len(cifr) else VERDE}'><div class='sevlbl'>DISCOS EBS SIN CIFRAR</div>"
                  f"<div class='sevnum'>{len(cifr)}</div><div class='small'>{(cifr['gb'].sum() if not cifr.empty else 0):,.0f} GB de datos sin cifrado en reposo</div></div>",
                  unsafe_allow_html=True)
    k[2].markdown(f"<div class='sevcard' style='border-left-color:{AZUL}'><div class='sevlbl'>RECURSOS CAMBIADOS ({days} D)</div>"
                  f"<div class='sevnum'>{len(camb)}</div><div class='small'>según la última captura de Config</div></div>", unsafe_allow_html=True)
    t1, t2, t3 = st.tabs(["Cambios recientes", "Discos sin cifrar", "Discos sin usar"])
    with t1:
        if camb.empty:
            st.caption("Sin cambios en el periodo.")
        else:
            camb["tipo_corto"] = camb["tipo"].str.replace("AWS::", "", regex=False)
            camb["dia"] = pd.to_datetime(camb["cuando"]).dt.date
            top = camb["tipo_corto"].value_counts().head(8).index
            fig = px.bar(camb[camb["tipo_corto"].isin(top)].groupby(["dia", "tipo_corto"]).size().reset_index(name="n"),
                         x="dia", y="n", color="tipo_corto", height=280, title="Cambios por día y tipo de recurso",
                         color_discrete_sequence=px.colors.qualitative.Safe)
            fig.update_layout(margin=dict(l=0, r=0, t=40, b=0), title_font_size=13, legend_title_text="", xaxis_title="", yaxis_title="Recursos")
            st.plotly_chart(fig, width="stretch")
            st.dataframe(camb[["cuenta", "cuando", "tipo_corto", "recurso", "estado"]], hide_index=True, width="stretch",
                         column_config={"cuando": st.column_config.DatetimeColumn("Cuándo (hora local)", format="YYYY-MM-DD HH:mm"),
                                        "tipo_corto": "Tipo", "recurso": "Recurso", "estado": "Estado del registro", "cuenta": "Cuenta"})
            st.caption("Estado del registro: OK = cambió · ResourceDiscovered = recurso nuevo · ResourceDeleted = eliminado. "
                       "Quién hizo el cambio está en la página Cambios recientes (CloudTrail).")
    with t2:
        if cifr.empty:
            st.success("Todos los discos EBS están cifrados.")
        else:
            cifr["servidor"] = cifr["servidor"].map(lambda x: ", ".join(names.get(i.strip(), i.strip()) for i in str(x).split(",")))
            st.dataframe(cifr, hide_index=True, width="stretch")
            st.caption("Para cifrarlos: snapshot → copia cifrada → volumen nuevo. Activar «cifrado EBS por defecto» en la cuenta evita nuevos casos.")
    with t3:
        if sueltos.empty:
            st.success("No hay discos EBS sin asociar.")
        else:
            st.dataframe(sueltos, hide_index=True, width="stretch")
            st.caption("Siguen cobrándose aunque no estén conectados a un servidor. Snapshot y eliminar si ya no se usan.")


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


# ================================================================== FINOPS
def _cost_dirs() -> list[Path]:
    here = Path(__file__).resolve().parent
    cands = [os.environ.get("AWS_PULSE_COST_DIR", ""), "reportes/costos", here.parent / "reportes/costos",
             here.parent / "scripts/reportes/costos", "~/proyectos/aws/aws-health-check/reportes/costos"]
    return [Path(c).expanduser() for c in cands if c]


def usd(x: float) -> str:
    return f"${x:,.0f}"


DETAIL_COLS = ["servicio", "recurso", "detalle", "cantidad", "precio_ref", "unidad_precio", "costo_lista", "costo_ajustado",
               "pct", "tipo", "nota", "fuente"]
DETAIL_CFG = {"servicio": "Servicio", "recurso": "Recurso", "detalle": "Detalle",
              "cantidad": st.column_config.NumberColumn("Cantidad", format="%.2f"),
              "precio_ref": st.column_config.NumberColumn("Precio de referencia (USD)", format="%.4f"),
              "unidad_precio": "Unidad", "costo_lista": st.column_config.NumberColumn("Lista USD/mes", format="$%.2f"),
              "costo_ajustado": st.column_config.NumberColumn("Ajustado USD/mes", format="$%.2f"),
              "pct": st.column_config.ProgressColumn("% de la cuenta", format="%.1f %%", min_value=0, max_value=100),
              "tipo": "Origen", "nota": "Nota", "fuente": st.column_config.LinkColumn("Fuente del precio", display_text="aws.amazon.com")}


def detail_table(d: pd.DataFrame, height: int | None = None):
    """Detalle de costos de una cuenta, ordenado de mayor a menor, con una fila TOTAL al final."""
    d = d.copy()
    tot_l, tot_a = d["costo_lista"].sum(), d["costo_ajustado"].sum()
    d["pct"] = 100 * d["costo_ajustado"] / max(tot_a, 0.01)
    d = d.sort_values("costo_ajustado", ascending=False)[DETAIL_COLS]
    total = pd.DataFrame([{"servicio": "TOTAL", "recurso": f"{len(d)} líneas", "costo_lista": round(tot_l, 2),
                           "costo_ajustado": round(tot_a, 2), "pct": 100.0, "tipo": "Σ", "nota": "Suma de la cuenta (USD/mes)"}])
    d = pd.concat([d, total], ignore_index=True)
    st.dataframe(d.style.apply(lambda r: ["font-weight:700;background-color:rgba(236,114,17,.16)" if r["servicio"] == "TOTAL" else ""
                                          for _ in r], axis=1),
                 hide_index=True, width="stretch", column_config=DETAIL_CFG, height=height or min(38 + 35 * len(d), 560))


def page_finops():
    st.header("FinOps: costo estimado por cuenta (USD)")
    st.caption(f"Precio de lista público de AWS (us-east-1, on-demand, verificado {F.PRICES_DATE}) × inventario real de cada cuenta. "
               "No reemplaza la factura: sirve para saber cuánto debería costar, dónde se va el dinero y qué se puede ahorrar.")

    # ---------- origen del inventario
    found = next((d for d in _cost_dirs() if d.is_dir() and any(d.glob("inventario_*.tsv"))), None)
    with st.expander("Origen del inventario", expanded=found is None):
        c1, c2 = st.columns(2)
        folder = c1.text_input("Carpeta con inventario_*.tsv", str(found or _cost_dirs()[0]),
                               help="La genera scripts/aws-cost-inventory.sh (solo lectura).")
        ups = c2.file_uploader("…o súbelos aquí", type="tsv", accept_multiple_files=True)
        st.code("ALL_REGIONS=1 ./aws-cost-inventory.sh " + " ".join(profiles), language="bash")
    inv = F.load_uploads(ups) if ups else F.load_dir(folder)
    if inv.empty:
        st.info("No hay inventario todavía. Ejecuta el comando de arriba en la carpeta de scripts y vuelve a esta página.")
        return
    perfiles = sorted(inv["perfil"].unique())
    mtime = max((p.stat().st_mtime for p in Path(folder).expanduser().glob("inventario_*.tsv")), default=None) if not ups else None
    if mtime:
        st.caption(f"Inventario del {pd.Timestamp(mtime, unit='s', tz='UTC').tz_convert(A.LOCAL_TZ):%Y-%m-%d %H:%M} (hora de {A.TZ_NAME}) · "
                   f"cuentas: {', '.join(perfiles)}")

    intro = st.container()  # gráfico de presentación: se dibuja al final, cuando ya está calculada la simulación QA

    # ---------- variables comerciales (plegables)
    with st.expander("Variables comerciales: descuentos, margen del reseller, soporte e IVA", expanded=False):
        v = st.columns(4)
        margen = v[0].number_input("Margen del reseller / consorcio (%)", -30.0, 100.0, 0.0, 1.0,
                                   help="Positivo si el proveedor cobra encima del precio de AWS; negativo si traslada descuento.")
        edp = v[1].number_input("Descuento privado AWS (EDP/PPA) (%)", 0.0, 40.0, 0.0, 1.0,
                                help="Acuerdo de precio privado por compromiso de gasto. Lo negocia el reseller.")
        creditos = v[2].number_input("Créditos promocionales (USD/mes)", 0.0, 100000.0, 0.0, 50.0,
                                     help="Créditos MAP, POC o migración que aplique el reseller.")
        soporte = v[3].selectbox("Plan de soporte", list(F.SUPPORT_PLANS), index=0,
                                 help="Con un reseller el soporte suele venir incluido (Partner-Led Support).")
        v = st.columns(4)
        sp_cov = v[0].slider("Cobertura Savings Plans (cómputo) %", 0, 100, 0, 5, help="Parte de EC2 + Fargate cubierta por un Compute Savings Plan.")
        sp_desc = v[1].slider("Descuento del Savings Plan %", 0, 66, 27, 1, help="1 año sin pago inicial ≈ 27 %; 3 años ≈ 49 %.")
        ri_cov = v[2].slider("Cobertura RDS Reserved %", 0, 100, 0, 5)
        ri_desc = v[3].slider("Descuento RDS Reserved %", 0, 70, 38, 1, help="1 año sin pago inicial ≈ 35-40 %.")
        v = st.columns(4)
        iva_on = v[0].toggle("Incluir IVA", value=True, help="Ecuador grava los servicios digitales importados.")
        iva = v[1].number_input("IVA (%)", 0.0, 30.0, 15.0, 1.0, disabled=not iva_on)
        gov_n = v[2].number_input("Cuentas de gobierno no visibles", 0, 10, 3,
                                  help="Control Tower crea Management, Log Archive y Audit. No las ves, pero se pagan.")
        gov_usd = v[3].number_input("USD/mes por cuenta de gobierno", 0.0, 500.0, 25.0, 5.0)
    st.caption(f"Aplicado: margen {margen:+.0f} % · EDP {edp:.0f} % · Savings Plans {sp_cov} % × {sp_desc} % · "
               f"RDS RI {ri_cov} % × {ri_desc} % · soporte: {soporte} · créditos {usd(creditos)} · "
               f"IVA {f'{iva:.0f} %' if iva_on else 'no'} · {gov_n} cuentas de gobierno × {usd(gov_usd)}")

    # ---------- supuestos de uso (editables)
    with st.expander("Supuestos de uso que el inventario no puede medir (editables por cuenta)"):
        base = pd.DataFrame({p: F.DEFAULT_ASSUMPTIONS for p in perfiles})
        key = "finops_asm_" + "_".join(perfiles)
        ed = st.data_editor(st.session_state.get(key, base), width="stretch", key=key + "_ed")
        st.session_state[key] = ed
        gov_gb = st.number_input("GB en el bucket de logs centralizado (Log Archive)", 0.0, 100000.0, 200.0, 50.0)
        st.caption("Ajusta con datos reales cuando los tengas (p. ej. tráfico WAF desde la página WAF y firewalls).")
    asm = {p: ed[p].to_dict() for p in perfiles}

    k = dict(sp_cov=sp_cov, sp_desc=sp_desc, ri_cov=ri_cov, ri_desc=ri_desc, edp=edp, margen=margen,
             soporte=soporte, creditos=creditos, iva_on=iva_on, iva=iva)
    lines = F.price_lines(inv, asm)
    unseen = F.unseen_lines(perfiles, asm, {"cuentas": gov_n, "usd_cuenta": gov_usd, "logs_gb": gov_gb})
    allc = F.adjust(pd.concat([lines, unseen], ignore_index=True), k)
    t = F.totals(allc, k)
    ops = F.opportunities(inv, lines)
    by_acc = allc.groupby("perfil")[["costo_lista", "costo_ajustado"]].sum().reset_index().sort_values("costo_ajustado", ascending=False)

    # ---------- KPIs
    st.subheader("Resumen mensual")
    c = st.columns(5)
    c[0].metric("Precio de lista AWS", usd(t["lista"]), border=True)
    c[1].metric("Con descuentos y margen", usd(t["neto"]), delta=f"{t['neto'] - t['lista']:+,.0f}" if abs(t['neto'] - t['lista']) >= 1 else None, delta_color="inverse", border=True)
    c[2].metric("Total a pagar (est.)", usd(t["total"]), help=f"Soporte {usd(t['soporte'])} · créditos -{usd(t['creditos'])} · IVA {usd(t['iva'])}", border=True)
    c[3].metric("Proyección anual", usd(t["total"] * 12), border=True)
    c[4].metric("Ahorro posible / mes", usd(ops["ahorro_mes"].sum()) if not ops.empty else "-",
                help="Suma de las oportunidades de abajo, a precio de lista. Algunas se solapan.", border=True)
    medido = allc[allc["tipo"] == "Medido"]["costo_ajustado"].sum()
    st.caption(f"Confianza: {medido / max(t['neto'], 1):.0%} del costo sale de recursos medidos; el resto son supuestos editables.")

    g1, g2 = st.columns([1, 1])
    cat_names = {"compute": "Cómputo", "database": "Bases de datos", "storage": "Almacenamiento", "network": "Red",
                 "security": "Seguridad", "observability": "Observabilidad", "other": "Otros"}
    bc = allc.assign(Categoría=allc["categoria"].map(cat_names).fillna("Otros")) \
             .groupby(["perfil", "Categoría"])["costo_ajustado"].sum().reset_index()
    fig = px.bar(bc, x="perfil", y="costo_ajustado", color="Categoría", height=320, title="¿En qué categoría gasta cada cuenta?",
                 category_orders={"perfil": by_acc["perfil"].tolist()}, color_discrete_sequence=px.colors.qualitative.Safe)
    fig.update_layout(margin=dict(l=0, r=0, t=36, b=0), title_font_size=13, legend_title_text="", xaxis_title="", yaxis_title="USD/mes")
    g1.plotly_chart(fig, width="stretch")
    tm = allc[allc["costo_ajustado"] > 0]
    fig2 = px.treemap(tm, path=["perfil", "servicio"], values="costo_ajustado", height=320, title="¿En qué servicio se va el dinero?",
                      color="categoria", color_discrete_sequence=px.colors.qualitative.Safe)
    fig2.update_traces(texttemplate="%{label}<br>USD %{value:,.0f}")
    fig2.update_layout(margin=dict(l=0, r=0, t=36, b=0), title_font_size=13)
    g2.plotly_chart(fig2, width="stretch")

    # ---------- servicios por cuenta
    services_table(inv, allc, by_acc["perfil"].tolist())

    # ---------- detalle por cuenta
    st.subheader("Detalle por cuenta")
    tabs = st.tabs([*by_acc["perfil"]])
    for tab, p in zip(tabs, by_acc["perfil"]):
        with tab:
            d = allc[allc["perfil"] == p]
            acc = d["cuenta"].dropna().iloc[0] if "cuenta" in d and d["cuenta"].notna().any() else "-"
            m = st.columns([2, 1, 1, 1])
            m[0].markdown(f"**{p}** · cuenta {acc}  \n<span class='small'>{len(d)} líneas · "
                          f"{(d['tipo'] == 'Medido').mean():.0%} medido</span>", unsafe_allow_html=True)
            m[1].metric("Lista AWS / mes", usd(d["costo_lista"].sum()))
            m[2].metric("Ajustado / mes", usd(d["costo_ajustado"].sum()))
            m[3].metric("Ajustado / año", usd(d["costo_ajustado"].sum() * 12))
            detail_table(d)

    # ---------- simulación de cuenta nueva
    sim = page_finops_sim(inv, asm, k, allc, lines)

    # ---------- gráfico de presentación (arriba de la página)
    with intro:
        presentation_chart(by_acc, t, sim)

    # ---------- oportunidades
    st.subheader("Oportunidades de ahorro")
    if ops.empty:
        st.success("Sin oportunidades evidentes con las reglas actuales.")
    else:
        tot = ops["ahorro_mes"].sum()
        with st.expander(f"{len(ops)} oportunidades · hasta {usd(tot)}/mes ({usd(tot * 12)}/año) a precio de lista", expanded=False):
            by = ops.groupby("perfil")["ahorro_mes"].sum().sort_values(ascending=False)
            m = st.columns(min(len(by), 4) or 1)
            for col, (p, v) in zip(m, by.items()):
                col.metric(p, f"{usd(v)}/mes", border=True)
            esf = st.segmented_control("Esfuerzo", ["Todos", "Bajo", "Medio"], default="Todos", key="ops_esf")
            vv = ops if esf in (None, "Todos") else ops[ops["esfuerzo"] == esf]
            st.dataframe(vv, hide_index=True, width="stretch",
                         column_config={"perfil": "Cuenta", "oportunidad": "Oportunidad", "por_que": st.column_config.TextColumn("Por qué", width="large"),
                                        "ahorro_mes": st.column_config.NumberColumn("Ahorro USD/mes", format="$%.0f"), "esfuerzo": "Esfuerzo"})
            st.caption("Algunas se solapan (p. ej. Savings Plan y horario de oficina sobre la misma instancia): no sumes todo como ahorro seguro.")
    st.download_button("Descargar detalle (CSV)", allc.to_csv(index=False).encode("utf-8"), "finops_detalle.csv", "text/csv")
    with st.expander("Cómo se calcula y qué no incluye"):
        st.markdown(f"""
- **Medido:** recursos que el script encontró (EC2, EBS, RDS, Fargate, VPN, TGW, ALB/NLB, IPv4, WAF, FMS…) × precio de lista × {F.H} h/mes.
- **Estimado:** uso que no se ve sin Cost Explorer (transferencia, requests, eventos de GuardDuty, ítems de Config, chequeos de Security Hub). Edita los supuestos.
- **Cuentas de gobierno:** Control Tower no cobra, pero las cuentas Management, Log Archive y Audit pagan Config, CloudTrail, GuardDuty, Security Hub y S3.
- **No incluye:** impuestos distintos al IVA, Marketplace, licencias BYOL, picos puntuales, capa gratuita ni redondeos del reseller. Backup y DynamoDB aún no tienen precio en el catálogo.
- **Orden de los ajustes:** lista → Savings Plans/RI (solo cómputo y RDS) → descuento privado → margen del reseller → + soporte → − créditos → + IVA.
- **Simulación QA:** copia los componentes elegidos de la cuenta origen y aplica el % de capacidad: cada duplicación sube un tamaño de instancia (EC2 y RDS; al bajar del mínimo pasa a la familia t3/t3a), escala vCPU/memoria de Fargate y el almacenamiento. Con Aurora se cobran instancias writer/reader + almacenamiento de clúster + E/S. Los componentes agregados a mano no se escalan.
- Precios: [EC2]({F.SRC['ec2']}) · [RDS]({F.SRC['rds_mariadb']}) · [Aurora]({F.SRC['rds_aurora']}) · [Fargate]({F.SRC['fargate']}) · [VPC]({F.SRC['vpc']}) · [WAF]({F.SRC['waf']}) · [Firewall Manager]({F.SRC['fms']}) · [Savings Plans]({F.SRC['sp']}) · [Soporte]({F.SRC['support']})
""")


def presentation_chart(by_acc: pd.DataFrame, t: dict, sim: dict | None):
    """Barra por cuenta con su costo mensual ajustado; la cuenta simulada aparece aparte, rayada y sin sumar al total."""
    d = by_acc[["perfil", "costo_ajustado"]].copy()
    d["tipo"] = ["Gobierno (estimado)" if "gobierno" in p else "Cuenta actual" for p in d["perfil"]]
    if sim:
        d = pd.concat([d, pd.DataFrame([{"perfil": sim["nombre"] + " (simulada)", "costo_ajustado": sim["neto"],
                                         "tipo": "Simulada (no suma)"}])], ignore_index=True)
    color = {"Cuenta actual": AZUL, "Gobierno (estimado)": GRIS, "Simulada (no suma)": NARANJA}
    fig = go.Figure()
    for tp, g in d.groupby("tipo", sort=False):
        fig.add_bar(x=g["perfil"], y=g["costo_ajustado"], name=tp, marker_color=color[tp],
                    marker_pattern_shape="/" if tp.startswith("Simulada") else "",
                    text=[usd(x) for x in g["costo_ajustado"]], textposition="outside", cliponaxis=False,
                    hovertemplate="%{x}: USD %{y:,.0f}/mes<extra></extra>")
    fig.update_layout(height=380, margin=dict(l=0, r=0, t=70, b=0), barmode="group", bargap=0.35,
                      title=dict(text=f"Costo mensual por cuenta · total {usd(t['neto'])}/mes sin IVA · "
                                      f"{usd(t['total'])}/mes a pagar · {usd(t['total'] * 12)}/año",
                                 x=0.5, xanchor="center", font_size=16),
                      legend=dict(orientation="h", y=1.06, x=0.5, xanchor="center", title_text=""),
                      yaxis_title="USD/mes", xaxis_title="", uniformtext_minsize=11)
    fig.update_xaxes(categoryorder="array", categoryarray=d["perfil"].tolist())
    st.plotly_chart(fig, width="stretch")


def services_table(inv: pd.DataFrame, allc: pd.DataFrame, cuentas: list[str]):
    """Matriz servicio × cuenta en USD/mes, con qué es cada servicio y en cuántas cuentas está."""
    st.subheader("Servicios por cuenta (USD/mes)")
    svc = allc.groupby(["servicio", "perfil"])["costo_ajustado"].sum().unstack()
    on = inv.assign(on=lambda d: (d["cantidad"] > 0) & ~d["detalle"].isin(["no", "grabando=False", "DISABLED"])) \
            .groupby(["servicio", "perfil"])["on"].any().unstack(fill_value=False)
    services = sorted(set(svc.index) | set(on[on.any(axis=1)].index))
    tbl = pd.DataFrame(index=services)
    for p in cuentas:
        cost = svc[p] if p in svc else pd.Series(dtype=float)
        en = on[p] if p in on else pd.Series(dtype=bool)
        tbl[p] = [c if (c := cost.get(s, 0)) and not pd.isna(c) and c > 0 else (0.0 if en.get(s, False) else float("nan"))
                  for s in services]
    tbl["Total"] = tbl[cuentas].sum(axis=1)
    tbl = tbl[(tbl["Total"] > 0) | tbl[cuentas].notna().any(axis=1)].sort_values("Total", ascending=False)
    gran = tbl["Total"].sum()
    tbl["% del total"] = 100 * tbl["Total"] / max(gran, 0.01)
    tbl["Cuentas"] = [f"{int(n)} de {len(cuentas)}" for n in tbl[cuentas].notna().sum(axis=1)]
    tbl.insert(0, "Qué es", [F.SERVICE_INFO.get(s, "") for s in tbl.index])
    total_row = pd.DataFrame([{"Qué es": "Suma de todos los servicios", **{p: tbl[p].sum() for p in cuentas},
                               "Total": gran, "% del total": 100.0, "Cuentas": ""}], index=["TOTAL"])
    tbl = pd.concat([tbl, total_row]).rename_axis("Servicio").reset_index()
    money = [*cuentas, "Total"]
    vmax = max(tbl.loc[tbl["Servicio"] != "TOTAL", cuentas].max().max() or 1, 1)

    def shade(row):
        if row["Servicio"] == "TOTAL":
            return ["font-weight:700;background-color:rgba(236,114,17,.16)"] * len(row)
        out = []
        for col, val in row.items():
            if col in cuentas and not pd.isna(val) and val > 0:
                out.append(f"background-color:rgba(37,99,235,{0.10 + 0.55 * val / vmax:.2f})")
            else:
                out.append("")
        return out

    fmt = lambda x: "—" if pd.isna(x) else ("activo · $0" if x == 0 else f"${x:,.0f}")
    sty = tbl.style.apply(shade, axis=1).format({**{c: fmt for c in money}, "% del total": "{:.1f} %"})
    st.dataframe(sty, hide_index=True, width="stretch", height=min(40 + 35 * len(tbl), 640),
                 column_config={"Servicio": st.column_config.TextColumn(width="small"),
                                "Qué es": st.column_config.TextColumn(width="medium")})
    st.caption("Cada celda es lo que cuesta ese servicio en esa cuenta, en USD por mes, ya con descuentos y margen (sin IVA). "
               "Más intenso = más caro. «activo · $0» = habilitado pero sin costo propio (capa gratuita o se cobra en otra cuenta). "
               "«—» = no se usa en esa cuenta. «Cuentas» = en cuántas de las cuentas está activo.")


def page_finops_sim(inv, asm, k, allc, lines) -> dict | None:
    """Simula una cuenta nueva (p. ej. ambiente QA) como réplica de una existente, empezando en un % de su capacidad."""
    st.subheader("Simulación: nueva cuenta «ambiente QA»")
    st.caption("Réplica de una cuenta existente para pruebas y desarrollo. Empieza al 25 % de la capacidad de la cuenta origen "
               "y súbela paso a paso. Usa los mismos precios, descuentos e IVA de arriba.")
    perfiles = sorted(inv["perfil"].unique())
    qa_base = os.environ.get("AWS_PULSE_QA_BASE", "").lower()  # cuenta origen por defecto; si no, la más cara
    default = next((p for p in perfiles if qa_base and p.lower() == qa_base),
                   allc.groupby("perfil")["costo_ajustado"].sum().reindex(perfiles).idxmax())
    c = st.columns(4)
    base_p = c[0].selectbox("Cuenta origen (se replica)", perfiles, index=perfiles.index(default))
    nombre = (c[1].text_input("Nombre de la cuenta nueva", "ambiente QA").strip() or "ambiente QA")
    horario = c[2].selectbox("Horario del cómputo", list(F.SCHEDULES), index=0,
                             help="Apagar QA fuera de oficina baja EC2, Fargate y RDS. Para estimar el techo deja 24x7.")
    motor = c[3].radio("Motor de base de datos", ["Igual que origen", "Aurora"], horizontal=True,
                       help="Aurora: el almacenamiento es del clúster (no se duplica por réplica) y se cobra E/S.")
    pct = st.radio(f"Capacidad de {nombre} respecto a {base_p}", F.CAPACITY_LEVELS, index=0, horizontal=True,
                   format_func=lambda x: f"{x} %", key=f"qa_capacidad_{base_p}",
                   help="Haz clic en un porcentaje. Cada duplicación sube un tamaño de instancia: 25 % = dos tamaños menos, "
                        "200 % = uno más. Fargate y el almacenamiento escalan en la misma proporción.")
    cp = F.capacity_params(pct)
    st.caption(f"Con {pct} %: EC2 y RDS {cp['ec2_step']:+d} tamaño(s) · Fargate ×{cp['ecs_size']:g} vCPU/memoria y ×{cp['ecs_mult']:g} tareas · "
               f"almacenamiento ×{cp['storage_mult']:g} · alta disponibilidad: {cp['rds_maz']}.")

    sk = f"qa_{base_p}_{pct}"
    with st.expander("Ajuste fino por servicio (opcional)"):
        col = st.columns(4)
        ec2_step = col[0].slider("EC2: tamaño (pasos)", -3, 3, cp["ec2_step"], key=sk + "e1",
                                 help="+1 = siguiente tamaño de la misma familia (m6a.xlarge → m6a.2xlarge).")
        ec2_mult = col[0].slider("EC2: cantidad (×)", 0.5, 3.0, cp["ec2_mult"], 0.5, key=sk + "e2")
        ecs_size = col[1].select_slider("Fargate: vCPU y memoria (×)", [0.25, 0.5, 1.0, 2.0, 4.0], cp["ecs_size"], key=sk + "f1")
        ecs_mult = col[1].slider("Fargate: tareas por servicio (×)", 0.5, 4.0, cp["ecs_mult"], 0.5, key=sk + "f2")
        rds_step = col[2].slider("Base de datos: tamaño (pasos)", -3, 3, cp["rds_step"], key=sk + "r1")
        rds_maz = col[2].radio("Alta disponibilidad", ["Igual que origen", "Multi-AZ", "Single-AZ"],
                               index=["Igual que origen", "Multi-AZ", "Single-AZ"].index(cp["rds_maz"]), key=sk + "r2")
        storage_mult = col[3].slider("Almacenamiento (×)", 0.25, 4.0, cp["storage_mult"], 0.25, key=sk + "s1")
        readers = col[3].number_input("Readers Aurora adicionales", 0, 5, 0, key=sk + "a1", disabled=motor != "Aurora")
        aio = col[3].number_input("E/S Aurora (millones/mes)", 0.0, 100000.0, 50.0 * pct / 25, 25.0, key=sk + "a2")

    # ---------- componentes: arquitectura del origen + agregados
    st.markdown(f"**Componentes de {nombre}** · parten de la arquitectura de {base_p}; desmarca lo que no necesites o agrega lo que falte")
    base = inv[inv["perfil"] == base_p]
    bl = lines[lines["perfil"] == base_p]
    cost_row = bl.groupby("src_row")["costo_lista"].sum() if "src_row" in bl else pd.Series(dtype=float)
    on = (base["cantidad"] > 0) & ~base["detalle"].isin(["no", "grabando=False", "DISABLED"])
    base = base[on | base.index.isin(cost_row[cost_row > 0].index)]
    ek = f"qa_extra_{base_p}"
    extras = st.session_state.setdefault(ek, [])

    with st.expander("Agregar un componente que no existe en " + base_p):
        a = st.columns(4)
        kind = a[0].selectbox("Tipo", F.COMPONENT_KINDS, key="qa_kind")
        cname = a[1].text_input("Nombre", "QA-NUEVO", key="qa_cname")
        qty = a[2].number_input("Cantidad" + (" (GB)" if "(GB)" in kind else ""), 1.0, 100000.0,
                                100.0 if "(GB)" in kind else 1.0, 1.0, key="qa_qty")
        o = {}
        if kind == "Servidor EC2":
            o["itype"] = a[3].selectbox("Tipo de instancia", sorted(F.EC2), index=sorted(F.EC2).index("t3a.medium"), key="qa_it")
            o["plat"] = a[3].radio("Sistema", ["Linux/UNIX", "Windows"], horizontal=True, key="qa_plat")
        elif kind == "Base de datos RDS / Aurora":
            o["eng"] = a[3].selectbox("Motor", ["mariadb", "mysql", "postgres", "aurora-mysql", "aurora-postgresql"], key="qa_eng")
            clases = sorted({cl for cl, e in F.RDS if e == o["eng"]})
            o["cls"] = a[3].selectbox("Clase", clases, key="qa_cls")
            o["gb"] = a[3].number_input("Almacenamiento (GB)", 20, 65536, 50, key="qa_gb")
            o["maz"] = a[3].toggle("Multi-AZ", key="qa_maz", disabled=o["eng"].startswith("aurora"))
        elif kind == "Servicio ECS Fargate":
            o["vcpu"] = a[3].select_slider("vCPU por tarea", [0.25, 0.5, 1.0, 2.0, 4.0], 0.5, key="qa_vcpu")
            o["gb"] = a[3].select_slider("Memoria por tarea (GB)", [0.5, 1.0, 2.0, 4.0, 8.0, 16.0], 1.0, key="qa_mem")
        b = st.columns([1, 1, 3])
        if b[0].button("Agregar a QA", type="primary"):
            extras.extend(F.new_component(kind, cname, qty, **o))
            st.rerun()
        if extras and b[1].button("Quitar todos los agregados"):
            st.session_state[ek] = []
            st.session_state.pop(f"qa_comp_{base_p}", None)
            st.rerun()

    comp = pd.DataFrame({"Incluir": [s not in F.ORG_SERVICES for s in base["servicio"]], "Origen": base_p,
                         "Servicio": base["servicio"].values, "Componente": base["recurso"].values,
                         "Detalle": base["detalle"].astype(str).values, "Cantidad": base["cantidad"].values, f"USD/mes en {base_p}": [cost_row.get(i, 0.0) for i in base.index]},
                        index=[f"g{i}" for i in base.index])
    if extras:
        ex = pd.DataFrame(extras)
        comp = pd.concat([comp, pd.DataFrame({"Incluir": True, "Origen": "Agregado", "Servicio": ex["servicio"].values,
                                              "Componente": ex["recurso"].values, "Detalle": ex["detalle"].values,
                                              "Cantidad": ex["cantidad"].values, f"USD/mes en {base_p}": 0.0},
                                             index=[f"x{i}" for i in range(len(ex))])])
    ed = st.data_editor(comp, key=f"qa_comp_{base_p}", width="stretch", hide_index=True,
                        height=min(40 + 35 * len(comp), 420), disabled=["Origen", "Servicio", "Componente", "Detalle", f"USD/mes en {base_p}"],
                        column_config={"Incluir": st.column_config.CheckboxColumn("Incluir", width="small"),
                                       "Cantidad": st.column_config.NumberColumn("Cantidad base", format="%.2f", min_value=0.0,
                                                                                 help="La de la cuenta origen. El % de capacidad se aplica encima (no a los agregados)."),
                                       f"USD/mes en {base_p}": st.column_config.NumberColumn(format="$%.0f")})
    st.caption(f"Desmarcados por defecto: {', '.join(F.ORG_SERVICES)} (se pagan una sola vez en la organización).")

    # ---------- simulación
    prm = dict(ec2_step=ec2_step, ec2_mult=ec2_mult, ecs_mult=ecs_mult, ecs_size=ecs_size, rds_step=rds_step, rds_motor=motor,
               rds_maz=rds_maz, aurora_readers=readers, aurora_io=aio, storage_mult=storage_mult, horario=F.SCHEDULES[horario])
    sel_g = ed[ed.index.str.startswith("g") & ed["Incluir"]]
    src = base.loc[[int(i[1:]) for i in sel_g.index]].copy()
    src["cantidad"] = sel_g["Cantidad"].astype(float).values
    qa_inv, cambios = F.simulate_account(src, prm, nombre)
    off = ed[~ed["Incluir"]]
    if not off.empty:
        cambios = pd.concat([cambios, pd.DataFrame({"servicio": off["Servicio"], "recurso": off["Componente"],
                                                    "origen": off["Cantidad"].map(lambda x: f"{x:g}"), "simulado": "no se incluye"})],
                            ignore_index=True)
    sel_x = ed[ed.index.str.startswith("x") & ed["Incluir"]]
    if not sel_x.empty:
        frac = F.SCHEDULES[horario]
        xr = pd.DataFrame([extras[int(i[1:])] for i in sel_x.index])
        xr["cantidad"] = sel_x["Cantidad"].astype(float).values
        comp_rows = xr["recurso"].isin(["instancia", "servicio"])
        xr.loc[comp_rows, "cantidad"] *= frac
        xr["perfil"], xr["cuenta"] = nombre, "(nueva)"
        if xr["detalle"].str.contains("aurora").any() and not (qa_inv.get("recurso", pd.Series(dtype=str)) == "aurora I/O").any():
            xr = pd.concat([xr, pd.DataFrame([{"servicio": "RDS", "recurso": "aurora I/O", "detalle": "millones de E/S",
                                               "cantidad": aio, "unidad": "M-IO", "perfil": nombre, "cuenta": "(nueva)"}])])
        qa_inv = pd.concat([qa_inv, xr], ignore_index=True)
        cambios = pd.concat([cambios, pd.DataFrame({"servicio": xr["servicio"], "recurso": xr["recurso"], "origen": "—",
                                                    "simulado": "agregado: " + xr["detalle"].astype(str)})], ignore_index=True)
    if qa_inv.empty:
        st.info("No hay componentes incluidos en la simulación.")
        return None
    a_qa = {nombre: asm.get(base_p, F.DEFAULT_ASSUMPTIONS)}
    cost = lambda iv: F.adjust(pd.concat([F.price_lines(iv, a_qa), F.unseen_lines([nombre], a_qa, {})], ignore_index=True), k)
    qa = cost(qa_inv)
    t_qa = F.totals(qa, {**k, "creditos": 0})
    base_adj = allc[allc["perfil"] == base_p]["costo_ajustado"].sum()

    m = st.columns(4)
    m[0].metric(f"{base_p} hoy (ajustado)", usd(base_adj), border=True)
    m[1].metric(f"{nombre} al {pct} %", usd(t_qa["neto"]),
                delta=f"{100 * t_qa['neto'] / max(base_adj, 1):.0f} % de {base_p}", delta_color="off", border=True)
    m[2].metric("Total a pagar / mes (est.)", usd(t_qa["total"]),
                help=f"Ajustado + soporte {usd(t_qa['soporte'])} + IVA {usd(t_qa['iva'])}. Sin créditos.", border=True)
    m[3].metric("Proyección anual", usd(t_qa["total"] * 12), border=True)

    g1, g2 = st.columns([3, 2])
    lbl_qa = f"{nombre} {pct} %"
    cmp_ = pd.concat([allc[allc["perfil"] == base_p].assign(cuenta_=base_p), qa.assign(cuenta_=lbl_qa)]).groupby(["servicio", "cuenta_"])["costo_ajustado"].sum().reset_index()
    order = cmp_.groupby("servicio")["costo_ajustado"].max().sort_values(ascending=False).head(12).index.tolist()
    cmp_ = cmp_[cmp_["servicio"].isin(order)]
    fig = px.bar(cmp_, x="servicio", y="costo_ajustado", color="cuenta_", barmode="group", height=340,
                 category_orders={"servicio": order, "cuenta_": [base_p, lbl_qa]},
                 color_discrete_sequence=[GRIS, NARANJA], title=f"USD/mes por servicio: {base_p} vs {nombre}")
    fig.update_layout(margin=dict(l=0, r=0, t=36, b=0), title_font_size=13, legend_title_text="", xaxis_title="", yaxis_title="")
    g1.plotly_chart(fig, width="stretch")
    with g2:
        st.markdown("**Cambios aplicados**")
        if cambios.empty:
            st.caption("Sin cambios: réplica exacta.")
        else:
            st.dataframe(cambios.rename(columns={"servicio": "Servicio", "recurso": "Recurso", "origen": f"En {base_p}",
                                                 "simulado": f"En {nombre}"}),
                         hide_index=True, width="stretch", height=300)
    with st.expander(f"Detalle de costos de «{nombre}»", expanded=False):
        detail_table(qa)
        st.download_button(f"Descargar detalle de {nombre} (CSV)", qa.to_csv(index=False).encode("utf-8"),
                           "finops_simulacion_qa.csv", "text/csv")
    sin = qa[qa["tipo"] == "Sin precio"]
    if not sin.empty:
        st.warning("Sin precio en el catálogo (cuentan 0): " + ", ".join(sin["detalle"].astype(str).str.split("|").str[0].unique()))
    st.caption("Supuestos de uso (tráfico, logs, WAF…) = los de la cuenta origen. Precios de lista on-demand; "
               "en QA conviene horario de oficina y Savings Plans solo si el ambiente será permanente.")
    return {"nombre": nombre, "neto": t_qa["neto"], "pct": pct}


PAGES = {"Sesión": page_session, "Resumen": page_summary, "Salud y VPN": page_health,
         "Bases de datos (RDS)": page_rds, "WAF y firewalls": page_waf, "Security Hub": page_sh, "AWS Config": page_config,
         "Cambios recientes": page_changes, "FinOps": page_finops}
PAGES[page]()
