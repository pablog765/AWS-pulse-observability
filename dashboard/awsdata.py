"""awsdata.py - Consultas de solo lectura a AWS mediante AWS CLI (usa el login SSO del usuario).

Cada función devuelve datos ya procesados (listas de dict / DataFrames) para el dashboard.
Todas las llamadas usan `aws ... --output json`; no se requiere boto3.
"""
from __future__ import annotations

import configparser
import datetime as dt
import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

REGION = os.environ.get("AWS_REGION", "us-east-1")
UTC = dt.timezone.utc
# Zona horaria de presentación: AWS entrega todo en UTC; aquí se convierte a la hora local del negocio.
TZ_NAME = os.environ.get("AWS_PULSE_TZ", "America/Guayaquil")
try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo(TZ_NAME)
except Exception:  # sin tzdata: UTC-5 fijo (Ecuador no tiene horario de verano)
    LOCAL_TZ = dt.timezone(dt.timedelta(hours=-5), "UTC-05")


class SessionExpired(Exception):
    """La sesión SSO no existe o caducó."""


class AwsError(Exception):
    """Error de AWS CLI (permiso negado, servicio no habilitado, etc.)."""


# --------------------------------------------------------------------- base
def aws(profile: str | None, *args: str, region: str | None = None, timeout: int = 90):
    cmd = ["aws", *args, "--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    if region is not False:
        cmd += ["--region", region or REGION]
    env = {**os.environ, "AWS_PAGER": ""}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except FileNotFoundError as e:
        raise AwsError("AWS CLI no está instalado o no está en el PATH") from e
    except subprocess.TimeoutExpired as e:
        raise AwsError(f"Tiempo de espera agotado: {' '.join(args[:2])}") from e
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip()
        low = err.lower()
        if any(k in low for k in ("token has expired", "sso session", "nocredentials", "unable to locate credentials",
                                  "error loading sso token", "the sso session associated", "refresh failed")):
            raise SessionExpired(err.splitlines()[-1] if err else "Sesión no válida")
        raise AwsError(err.splitlines()[-1] if err else f"Error en {' '.join(args[:2])}")
    out = r.stdout.strip()
    return json.loads(out) if out else {}


def try_aws(profile, *args, default=None, **kw):
    """Igual que aws() pero devuelve `default` en errores que no son de sesión."""
    try:
        return aws(profile, *args, **kw)
    except AwsError:
        return default


def parallel(fn, items, workers: int = 6):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, items))


def iso(t: dt.datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


def local_now() -> pd.Timestamp:
    """Hora actual en la zona local del negocio, sin tz (misma base que to_local)."""
    return pd.Timestamp.now(tz=LOCAL_TZ).tz_localize(None)


def to_local(ts) -> pd.Timestamp | None:
    if ts in (None, "", "None"):
        return None
    t = pd.to_datetime(ts, utc=True, errors="coerce")
    if pd.isna(t):
        return None
    return t.tz_convert(LOCAL_TZ).tz_localize(None)


def tag(tags, key="Name", default="-"):
    for t in tags or []:
        if t.get("Key") == key:
            return t.get("Value") or default
    return default


# ------------------------------------------------------------- configuración
def read_aws_config() -> tuple[list[str], list[str]]:
    """Devuelve (sesiones SSO, perfiles) leídos de ~/.aws/config."""
    p = Path(os.environ.get("AWS_CONFIG_FILE", Path.home() / ".aws" / "config"))
    cp = configparser.ConfigParser()
    try:
        cp.read(p)
    except configparser.Error:
        return [], []
    sessions = [s.split(" ", 1)[1] for s in cp.sections() if s.startswith("sso-session ")]
    profiles = [s.split(" ", 1)[1] for s in cp.sections() if s.startswith("profile ")]
    return sessions, profiles


def config_account_ids() -> dict[str, str]:
    """ID de cuenta -> perfil, según sso_account_id en ~/.aws/config (sin llamar a AWS)."""
    p = Path(os.environ.get("AWS_CONFIG_FILE", Path.home() / ".aws" / "config"))
    cp = configparser.ConfigParser()
    try:
        cp.read(p)
    except configparser.Error:
        return {}
    out = {}
    for sec in cp.sections():
        if sec.startswith("profile ") and cp.has_option(sec, "sso_account_id"):
            out.setdefault(cp.get(sec, "sso_account_id").strip(), sec.split(" ", 1)[1])
    return out


def account_names(profiles: list[str]) -> dict[str, str]:
    """ID -> nombre legible. Primero los nombres de AWS Organizations (si algún perfil puede listarlos: cuenta de
    gestión o administrador delegado), luego el perfil de ~/.aws/config."""
    names = {}
    for p in profiles:
        d = try_aws(p, "organizations", "list-accounts", region=False, default=None)
        if d and d.get("Accounts"):
            names = {a["Id"]: a.get("Name") or a["Id"] for a in d["Accounts"]}
            break
    for acc, prof in config_account_ids().items():
        names[acc] = f"{names[acc]} (perfil {prof})" if acc in names and names[acc] != prof else prof
    return names


def identity(profile: str) -> dict:
    try:
        d = aws(profile, "sts", "get-caller-identity", region=False, timeout=30)
        arn = d.get("Arn", "")
        return {"perfil": profile, "estado": "OK", "cuenta": d.get("Account"),
                "rol": arn.split("/")[1] if "/" in arn else arn, "usuario": arn.split("/")[-1], "detalle": ""}
    except SessionExpired as e:
        return {"perfil": profile, "estado": "Sin sesión", "cuenta": "-", "rol": "-", "usuario": "-", "detalle": str(e)}
    except AwsError as e:
        return {"perfil": profile, "estado": "Error", "cuenta": "-", "rol": "-", "usuario": "-", "detalle": str(e)}


# ------------------------------------------------------------- salud y VPN
def ec2_instances(profile: str) -> list[dict]:
    d = aws(profile, "ec2", "describe-instances")
    out = []
    for r in d.get("Reservations", []):
        for i in r.get("Instances", []):
            out.append({"cuenta": profile, "nombre": tag(i.get("Tags")), "id": i["InstanceId"],
                        "estado": i["State"]["Name"], "tipo": i.get("InstanceType"),
                        "ip_privada": i.get("PrivateIpAddress", "-"), "ip_publica": i.get("PublicIpAddress", "-"),
                        "so": i.get("PlatformDetails", "-"),
                        "imdsv2": "Sí" if i.get("MetadataOptions", {}).get("HttpTokens") == "required" else "No",
                        "encendida": to_local(i.get("LaunchTime"))})
    return out


def instance_status(profile: str) -> list[dict]:
    d = aws(profile, "ec2", "describe-instance-status")
    out = []
    for s in d.get("InstanceStatuses", []):
        ist, sst = s.get("InstanceStatus", {}).get("Status"), s.get("SystemStatus", {}).get("Status")
        ev = s.get("Events") or []
        if ist != "ok" or sst != "ok" or ev:
            out.append({"cuenta": profile, "id": s["InstanceId"], "instancia": ist, "sistema": sst,
                        "evento": ev[0].get("Code") if ev else "-",
                        "fecha_evento": to_local(ev[0].get("NotBefore")) if ev else None})
    return out


def alarms(profile: str, state: str | None = "ALARM") -> list[dict]:
    args = ["cloudwatch", "describe-alarms"] + (["--state-value", state] if state else [])
    d = aws(profile, *args)
    return [{"cuenta": profile, "alarma": a["AlarmName"], "estado": a["StateValue"],
             "desde": to_local(a.get("StateUpdatedTimestamp")), "metrica": a.get("MetricName", "-"),
             "umbral": a.get("Threshold"), "motivo": (a.get("StateReason") or "")[:160]}
            for a in d.get("MetricAlarms", [])]


def vpn_tunnels(profile: str) -> list[dict]:
    d = aws(profile, "ec2", "describe-vpn-connections")
    vpns = [v for v in d.get("VpnConnections", []) if v.get("State") != "deleted"]
    if not vpns:
        return []
    cg = {c["CustomerGatewayId"]: c for c in try_aws(profile, "ec2", "describe-customer-gateways",
                                                       default={}).get("CustomerGateways", [])}
    end, start = now(), now() - dt.timedelta(hours=24)
    rows = []
    for v in vpns:
        c = cg.get(v.get("CustomerGatewayId"), {})
        for t in v.get("VgwTelemetry", []):
            ip = t.get("OutsideIpAddress")
            m = try_aws(profile, "cloudwatch", "get-metric-statistics", "--namespace", "AWS/VPN",
                        "--metric-name", "TunnelState", "--dimensions", f"Name=TunnelIpAddress,Value={ip}",
                        "--start-time", iso(start), "--end-time", iso(end), "--period", "3600",
                        "--statistics", "Minimum", default={})
            dps = m.get("Datapoints", []) if m else []
            down_h = sum(1 for p in dps if p.get("Minimum", 1) < 1) if dps else None
            mb = None  # tráfico de las últimas 24 h (entrada + salida) para detectar túneles sin uso
            for metric in ("TunnelDataIn", "TunnelDataOut"):
                md = try_aws(profile, "cloudwatch", "get-metric-statistics", "--namespace", "AWS/VPN",
                             "--metric-name", metric, "--dimensions", f"Name=TunnelIpAddress,Value={ip}",
                             "--start-time", iso(start), "--end-time", iso(end), "--period", "86400",
                             "--statistics", "Sum", default={})
                pts = (md or {}).get("Datapoints", [])
                if md:
                    mb = (mb or 0) + sum(p.get("Sum", 0) for p in pts) / 1024 ** 2
            changed = to_local(t.get("LastStatusChange"))
            rows.append({"cuenta": profile, "vpn": tag(v.get("Tags"), default=v["VpnConnectionId"]),
                         "vpn_id": v["VpnConnectionId"], "par_remoto": c.get("IpAddress", "-"),
                         "nombre_par": tag(c.get("Tags"), default=v.get("CustomerGatewayId", "-")),
                         "tunel_aws": ip, "estado": t.get("Status"), "desde": changed,
                         "horas_en_estado": round((local_now() - changed).total_seconds() / 3600, 1) if changed is not None else None,
                         "rutas": t.get("AcceptedRouteCount", 0),
                         "ruteo": "Estático" if v.get("Options", {}).get("StaticRoutesOnly") else "BGP",
                         "horas_caido_24h": down_h, "trafico_24h_mb": round(mb, 1) if mb is not None else None, "detalle": t.get("StatusMessage") or "-"})
    return rows


# ----------------------------------------------------------------------- RDS
RDS_METRICS = [
    ("cpu", "CPUUtilization", "Average", "CPU (%)"),
    ("mem", "FreeableMemory", "Average", "Memoria libre (GB)"),
    ("conn", "DatabaseConnections", "Average", "Conexiones"),
]


def rds_instances(profile: str) -> list[dict]:
    d = aws(profile, "rds", "describe-db-instances")
    cl = try_aws(profile, "rds", "describe-db-clusters", default={}) or {}
    writer = {}
    for c in cl.get("DBClusters", []):
        for m in c.get("DBClusterMembers", []):
            writer[m["DBInstanceIdentifier"]] = m.get("IsClusterWriter", False)
    out = []
    for i in d.get("DBInstances", []):
        iid = i["DBInstanceIdentifier"]
        if iid in writer:
            rol = "Escritor" if writer[iid] else "Lector"
        elif i.get("ReadReplicaSourceDBInstanceIdentifier"):
            rol = "Lector (réplica)"
        else:
            rol = "Principal"
        out.append({"cuenta": profile, "id": iid, "motor": f"{i.get('Engine')} {i.get('EngineVersion', '')}".strip(),
                    "clase": i.get("DBInstanceClass"), "rol": rol, "estado": i.get("DBInstanceStatus"),
                    "multi_az": "Sí" if i.get("MultiAZ") else "No", "cluster": i.get("DBClusterIdentifier") or "-",
                    "aurora": str(i.get("Engine", "")).startswith("aurora"),
                    "cifrada": "Sí" if i.get("StorageEncrypted") else "No",
                    "respaldo_dias": i.get("BackupRetentionPeriod", 0),
                    "asignado_gb": i.get("AllocatedStorage"), "max_autoescala_gb": i.get("MaxAllocatedStorage"),
                    "tipo_disco": i.get("StorageType", "-"),
                    "publica": "Sí" if i.get("PubliclyAccessible") else "No"})
    return out


def instance_memory_gb(profile: str, db_class: str) -> float | None:
    if not db_class or not db_class.startswith("db.") or "serverless" in db_class:
        return None
    d = try_aws(profile, "ec2", "describe-instance-types", "--instance-types", db_class[3:], default=None)
    try:
        return d["InstanceTypes"][0]["MemoryInfo"]["SizeInMiB"] / 1024
    except (TypeError, KeyError, IndexError):
        return None


def rds_metrics(profile: str, db: dict, hours: int) -> pd.DataFrame:
    period = 60 if hours <= 3 else 300 if hours <= 24 else 3600
    q = []
    for key, name, stat, _ in RDS_METRICS:
        q.append({"Id": key, "MetricStat": {"Metric": {"Namespace": "AWS/RDS", "MetricName": name,
                  "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": db["id"]}]}, "Period": period, "Stat": stat}})
    lag_name = "AuroraReplicaLag" if db["aurora"] else "ReplicaLag"
    if db["rol"].startswith("Lector"):
        q.append({"Id": "lag", "MetricStat": {"Metric": {"Namespace": "AWS/RDS", "MetricName": lag_name,
                  "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": db["id"]}]}, "Period": period, "Stat": "Maximum"}})
    end = now()
    d = aws(profile, "cloudwatch", "get-metric-data", "--metric-data-queries", json.dumps(q),
            "--start-time", iso(end - dt.timedelta(hours=hours)), "--end-time", iso(end))
    frames = []
    for r in d.get("MetricDataResults", []):
        if not r.get("Timestamps"):
            continue
        s = pd.Series(r["Values"], index=[to_local(t) for t in r["Timestamps"]], name=r["Id"])
        frames.append(s)
    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, axis=1).sort_index()
    if "mem" in df:
        df["mem"] = df["mem"] / 1024 ** 3
    if "lag" in df:
        # AuroraReplicaLag viene en milisegundos; ReplicaLag en segundos -> todo a segundos
        df["lag"] = df["lag"] / 1000 if db["aurora"] else df["lag"]
    return df


def rds_storage_history(profile: str, db: dict, since: dt.datetime) -> pd.DataFrame:
    """Espacio diario desde `since`. RDS: FreeStorageSpace por instancia (usado = asignado - libre).
    Aurora: VolumeBytesUsed del clúster (no hay espacio libre: crece solo hasta 128 TiB)."""
    if db["aurora"]:
        metric, dim = "VolumeBytesUsed", {"Name": "DBClusterIdentifier", "Value": db["cluster"]}
    else:
        metric, dim = "FreeStorageSpace", {"Name": "DBInstanceIdentifier", "Value": db["id"]}
    q = [{"Id": "s", "MetricStat": {"Metric": {"Namespace": "AWS/RDS", "MetricName": metric, "Dimensions": [dim]},
                                    "Period": 86400, "Stat": "Minimum" if metric == "FreeStorageSpace" else "Maximum"}}]
    d = aws(profile, "cloudwatch", "get-metric-data", "--metric-data-queries", json.dumps(q),
            "--start-time", iso(since), "--end-time", iso(now()))
    r = next((x for x in d.get("MetricDataResults", []) if x.get("Timestamps")), None)
    if not r:
        return pd.DataFrame()
    s = pd.Series(r["Values"], index=[to_local(t) for t in r["Timestamps"]]).sort_index() / 1024 ** 3
    df = pd.DataFrame(index=s.index)
    if metric == "FreeStorageSpace":
        alloc = float(db.get("asignado_gb") or 0)
        df["libre_gb"] = s
        df["usado_gb"] = (alloc - s).clip(lower=0) if alloc else None
        df["asignado_gb"] = alloc or None
    else:
        df["usado_gb"] = s
        df["libre_gb"] = None
        df["asignado_gb"] = None
    return df


def storage_growth(df: pd.DataFrame, window_days: int = 90) -> tuple[pd.DataFrame, float | None]:
    """Uso al cierre de cada mes y tendencia lineal en GB/mes (regresión sobre los últimos `window_days` días).
    Lineal y no compuesta: el espacio de una base suele crecer por GB constantes, y un % compuesto calculado
    desde un inicio pequeño exagera la proyección."""
    u = df["usado_gb"].dropna()
    if u.empty:
        return pd.DataFrame(), None
    m = u.groupby(u.index.tz_localize(None).to_period("M")).last()
    out = pd.DataFrame({"mes": m.index.astype(str), "usado_gb": m.values.round(1)})
    out["crecimiento_gb"] = out["usado_gb"].diff().round(1)
    out["crecimiento_pct"] = (100 * out["usado_gb"].pct_change()).round(2)
    w = u[u.index >= u.index[-1] - pd.Timedelta(days=window_days)]
    if len(w) < 10:
        return out, None
    x = (w.index - w.index[0]).total_seconds() / 86400
    slope = float(np.polyfit(x, w.values, 1)[0])  # GB por día
    return out, slope * 30.44


# ----------------------------------------------------------------------- WAF
def _effective_action(rule: dict) -> tuple[str, int, int]:
    """Devuelve (accion efectiva, reglas forzadas a Count, total de overrides)."""
    a = rule.get("Action") or rule.get("OverrideAction") or {}
    k = next(iter(a), "-")
    st = rule.get("Statement") or rule.get("FirewallManagerStatement") or {}
    m = st.get("ManagedRuleGroupStatement") or {}
    ov = m.get("RuleActionOverrides") or []
    cnt = sum(1 for x in ov if "Count" in (x.get("ActionToUse") or {}))
    if k == "Count":
        return "Count (solo monitorea)", cnt, len(ov)
    if k == "None" and cnt:
        return f"{cnt} reglas forzadas a Count (no bloquean)", cnt, len(ov)
    if k == "None":
        return "Aplica las acciones del grupo", 0, 0
    return k, cnt, len(ov)


def _stmt_desc(st: dict) -> tuple[str, str]:
    if "ManagedRuleGroupStatement" in st:
        m = st["ManagedRuleGroupStatement"]
        return "Grupo administrado", f"{m.get('VendorName')}/{m.get('Name')}"
    if "RuleGroupReferenceStatement" in st:
        return "Grupo propio", st["RuleGroupReferenceStatement"]["ARN"].split("/")[-2]
    if "RateBasedStatement" in st:
        return "Límite de tasa", f"{st['RateBasedStatement'].get('Limit')} sol./5 min por IP"
    if "IPSetReferenceStatement" in st:
        return "Lista de IP", st["IPSetReferenceStatement"]["ARN"].split("/")[-2]
    if "GeoMatchStatement" in st:
        return "País", ",".join(st["GeoMatchStatement"].get("CountryCodes", []))
    return "Regla propia", ",".join(st.keys())


def waf_acls(profile: str) -> list[dict]:
    lst = try_aws(profile, "wafv2", "list-web-acls", "--scope", "REGIONAL", default={}) or {}
    out = []
    for acl in lst.get("WebACLs", []):
        w = aws(profile, "wafv2", "get-web-acl", "--scope", "REGIONAL", "--name", acl["Name"], "--id", acl["Id"])["WebACL"]
        rules = []
        for fase, key in (("1 FMS pre", "PreProcessFirewallManagerRuleGroups"), ("2 Cuenta", "Rules"),
                          ("3 FMS post", "PostProcessFirewallManagerRuleGroups")):
            for r in sorted(w.get(key, []), key=lambda x: x.get("Priority", 0)):
                st = r.get("FirewallManagerStatement") or r.get("Statement") or {}
                tipo, det = _stmt_desc(st)
                accion, cnt, tot = _effective_action(r)
                rules.append({"fase": fase, "prioridad": r.get("Priority"), "regla": r.get("Name"), "tipo": tipo,
                              "detalle": det, "accion_efectiva": accion, "reglas_en_count": cnt, "overrides": tot,
                              "metrica": (r.get("VisibilityConfig") or {}).get("MetricName")})
        logging = try_aws(profile, "wafv2", "get-logging-configuration", "--resource-arn", acl["ARN"], default=None)
        res = []
        for rt in ("APPLICATION_LOAD_BALANCER", "API_GATEWAY"):
            rr = try_aws(profile, "wafv2", "list-resources-for-web-acl", "--web-acl-arn", acl["ARN"],
                         "--resource-type", rt, default={}) or {}
            res += [f"{rt.split('_')[0].title()}: {'/'.join(a.split('/')[-3:-1]) if 'loadbalancer' in a else a.split('/')[-1]}"
                    for a in rr.get("ResourceArns", [])]
        blocking = sum(1 for r in rules if not r["accion_efectiva"].startswith("Count") and r["reglas_en_count"] == 0)
        out.append({"cuenta": profile, "nombre": acl["Name"], "arn": acl["ARN"],
                    "accion_defecto": next(iter(w.get("DefaultAction", {})), "-"),
                    "logging": bool(logging and logging.get("LoggingConfiguration")),
                    "recursos": res, "reglas": rules, "grupos": len(rules),
                    "grupos_bloqueando": blocking,
                    "reglas_count_total": sum(r["reglas_en_count"] for r in rules)})
    return out


def waf_traffic(profile: str, acl_name: str, days: int = 7) -> pd.DataFrame:
    end = now()
    q = [{"Id": k.lower(), "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": f"{k}Requests",
          "Dimensions": [{"Name": "WebACL", "Value": acl_name}, {"Name": "Region", "Value": REGION},
                         {"Name": "Rule", "Value": "ALL"}]}, "Period": 86400, "Stat": "Sum"}}
         for k in ("Allowed", "Blocked", "Counted")]
    d = aws(profile, "cloudwatch", "get-metric-data", "--metric-data-queries", json.dumps(q),
            "--start-time", iso(end - dt.timedelta(days=days)), "--end-time", iso(end))
    frames = [pd.Series(r["Values"], index=[to_local(t).date() for t in r["Timestamps"]], name=r["Id"])
              for r in d.get("MetricDataResults", []) if r.get("Timestamps")]
    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, axis=1).fillna(0).sort_index()
    df.index.name = "dia"
    return df.rename(columns={"allowed": "Permitidas", "blocked": "Bloqueadas", "counted": "Detectadas (Count)"})


def waf_counted_by_rule(profile: str, days: int = 7) -> pd.DataFrame:
    ms = try_aws(profile, "cloudwatch", "list-metrics", "--namespace", "AWS/WAFV2",
                 "--metric-name", "CountedRequests", default={}) or {}
    metrics = [m for m in ms.get("Metrics", []) if dict((x["Name"], x["Value"]) for x in m["Dimensions"]).get("Rule") != "ALL"]
    if not metrics:
        return pd.DataFrame(columns=["regla", "grupo", "solicitudes"])
    end = now()
    rows = []
    for i in range(0, len(metrics), 400):
        chunk = metrics[i:i + 400]
        q = [{"Id": f"m{j}", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CountedRequests",
              "Dimensions": m["Dimensions"]}, "Period": 86400, "Stat": "Sum"}} for j, m in enumerate(chunk)]
        d = aws(profile, "cloudwatch", "get-metric-data", "--metric-data-queries", json.dumps(q),
                "--start-time", iso(end - dt.timedelta(days=days)), "--end-time", iso(end))
        for r in d.get("MetricDataResults", []):
            m = chunk[int(r["Id"][1:])]
            dims = {x["Name"]: x["Value"] for x in m["Dimensions"]}
            total = sum(r.get("Values", []))
            if total:
                rows.append({"regla": dims.get("Rule", "-"), "grupo": dims.get("RuleGroup", "-"), "solicitudes": int(total)})
    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=["regla", "grupo", "solicitudes"])
    return df.groupby("regla", as_index=False).agg(solicitudes=("solicitudes", "max"), grupo=("grupo", "first")) \
             .sort_values("solicitudes", ascending=False)


def network_firewalls(profile: str) -> list[str]:
    d = try_aws(profile, "network-firewall", "list-firewalls", default={}) or {}
    return [f["FirewallName"] for f in d.get("Firewalls", [])]


def fms_policies(profile: str) -> tuple[str | None, list[dict]]:
    admin = (try_aws(profile, "fms", "get-admin-account", default={}) or {}).get("AdminAccount")
    pols = []
    if not admin:
        return None, pols
    lst = try_aws(profile, "fms", "list-policies", default=None)
    if not lst:
        return admin, pols
    for p in lst.get("PolicyList", []):
        full = (try_aws(profile, "fms", "get-policy", "--policy-id", p["PolicyId"], default={}) or {}).get("Policy", {})
        comp = (try_aws(profile, "fms", "list-compliance-status", "--policy-id", p["PolicyId"], default={}) or {})
        msd = {}
        try:
            msd = json.loads(full.get("SecurityServicePolicyData", {}).get("ManagedServiceData") or "{}")
        except json.JSONDecodeError:
            pass
        inc = (full.get("IncludeMap") or {})
        groups = []
        for fase, key in (("Antes de las reglas de la cuenta", "preProcessRuleGroups"), ("Después de las reglas de la cuenta", "postProcessRuleGroups")):
            for g in msd.get(key) or []:
                ident = g.get("managedRuleGroupIdentifier") or {}
                name = ident.get("managedRuleGroupName") or g.get("ruleGroupArn", "-").split("/")[-2:][0]
                ov = g.get("ruleActionOverrides") or []
                n_count = sum(1 for o in ov if "count" in str(o.get("actionToUse", "")).lower()) + len(g.get("excludeRules") or [])
                mode = (g.get("overrideAction") or {}).get("type", "NONE")
                groups.append({"grupo": name, "fase": fase,
                               "accion": "Solo cuenta (no bloquea)" if mode == "COUNT" else
                                         f"Bloquea, salvo {n_count} regla(s) en modo conteo" if n_count else "Bloquea"})
        pols.append({"politica": p["PolicyName"], "tipo": p.get("SecurityServiceType"),
                     "aplica_a": p.get("ResourceType"), "auto_remedia": "Sí" if p.get("RemediationEnabled") else "No",
                     "alcance": ", ".join((inc.get("ACCOUNT") or []) + (inc.get("ORG_UNIT") or [])) or "Toda la organización",
                     "solo_tags": ", ".join(f"{t['Key']}={t.get('Value', '')}" for t in full.get("ResourceTags", [])) or "-",
                     "logging": "Sí" if msd.get("loggingConfiguration") else "No", "grupos": groups,
                     "accion_defecto": (msd.get("defaultAction") or {}).get("type", "-"),
                     "excluye": ", ".join((full.get("ExcludeMap") or {}).get("ACCOUNT") or []) or "-",
                     "cumplimiento": [{"cuenta": c.get("MemberAccount"),
                                       "estado": (c.get("EvaluationResults") or [{}])[0].get("ComplianceStatus"),
                                       "violaciones": (c.get("EvaluationResults") or [{}])[0].get("ViolatorCount")}
                                      for c in comp.get("PolicyComplianceStatusList", []) if c.get("MemberAccount")]})
    return admin, pols


# --------------------------------------------------------------- Security Hub
CONTROLES = {
    "EC2.2": "El Security Group por defecto de la VPC permite tráfico; debería estar vacío",
    "EC2.8": "La instancia acepta IMDSv1; forzar IMDSv2 evita robo de credenciales vía SSRF",
    "EC2.9": "Instancia EC2 con IP pública directa",
    "EC2.13": "Security Group abre SSH (22) a todo Internet",
    "EC2.14": "Security Group abre RDP (3389) a todo Internet",
    "EC2.18": "Security Group abre a Internet (0.0.0.0/0) puertos no autorizados",
    "EC2.19": "Security Group abre a Internet puertos de alto riesgo (SSH, RDP, BD, etc.)",
    "EC2.182": "Block Public Access de snapshots EBS desactivado",
    "ECS.5": "Contenedores ECS con sistema de archivos raíz escribible",
    "IAM.6": "Usuario root sin MFA por hardware",
    "IAM.9": "Usuario root sin MFA",
    "S3.1": "Block Public Access de S3 a nivel de cuenta desactivado",
    "S3.8": "Bucket S3 sin Block Public Access",
    "SSM.1": "Instancia no gestionada por Systems Manager",
    "KMS.4": "Rotación automática de llaves KMS desactivada",
    "RDS.3": "Base de datos RDS sin cifrado",
    "CloudTrail.1": "No hay CloudTrail multirregión con eventos de lectura y escritura",
    "GuardDuty.1": "GuardDuty no habilitado",
}


def securityhub_findings(profile: str, max_items: int = 1500) -> pd.DataFrame:
    filt = {"SeverityLabel": [{"Value": s, "Comparison": "EQUALS"} for s in ("CRITICAL", "HIGH", "MEDIUM")],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
    q = ("Findings[].{sev:Severity.Label,titulo:Title,control:Compliance.SecurityControlId,producto:ProductName,"
         "recurso:Resources[0].Id,tipo_recurso:Resources[0].Type,actualizado:UpdatedAt,"
         "remediacion:Remediation.Recommendation.Url}")
    d = aws(profile, "securityhub", "get-findings", "--filters", json.dumps(filt), "--page-size", "100",
            "--max-items", str(max_items), "--query", q, timeout=240)
    df = pd.DataFrame(d if isinstance(d, list) else [])
    if df.empty:
        return df
    df.insert(0, "cuenta", profile)

    def categoria(r):
        t = str(r["titulo"])
        if r["control"] and r["control"] != "None":
            return "Configuración insegura"
        if re.match(r"^KB\d+", t):
            return "Parche de Windows"
        if t.startswith("CVE-"):
            return "Vulnerabilidad de software"
        return "Otro"

    df["control"] = df["control"].fillna("")
    df["categoria"] = df.apply(categoria, axis=1)
    df["que_significa"] = df.apply(lambda r: CONTROLES.get(r["control"], r["titulo"]), axis=1)
    is_vuln = df["categoria"] == "Vulnerabilidad de software"
    pkg = df["titulo"].str.extract(r"CVE-[\d-]+ - (.+)$", expand=False)
    df["paquete"] = pkg.where(is_vuln, "-").fillna("Sistema operativo")
    df["recurso_corto"] = df["recurso"].fillna("").map(_short_resource)
    df["actualizado"] = df["actualizado"].map(to_local)
    return df


def _short_resource(arn: str) -> str:
    if ":repository/" in arn:
        parts = arn.split("/")
        return f"imagen:{parts[1]}" if len(parts) > 1 else arn
    return arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]


# ------------------------------------------------------------- AWS Config
def config_query(profile: str, expr: str, max_items: int = 500) -> list[dict]:
    """Consulta avanzada (SQL) sobre el inventario de Config. Solo lectura."""
    d = try_aws(profile, "configservice", "select-resource-config", "--expression", expr,
                "--max-items", str(max_items), default=None) or {}
    out = []
    for r in d.get("Results", []):
        try:
            out.append(json.loads(r))
        except (TypeError, json.JSONDecodeError):
            pass
    return out


def _rule_origin(created_by: str, name: str) -> str:
    cb = (created_by or "").lower()
    if "securityhub" in cb:
        return "Security Hub"
    if "fms" in cb:
        return "Firewall Manager"
    if "config-conforms" in cb:
        return "Conformance pack"
    if "controltower" in cb or name.startswith("AWSControlTower"):
        return "Control Tower"
    return "Propia de la cuenta"


def config_status(profile: str) -> dict:
    """Estado de AWS Config en una cuenta: grabador, inventario, reglas y su cumplimiento."""
    rec = (try_aws(profile, "configservice", "describe-configuration-recorder-status", default={}) or {}).get("ConfigurationRecordersStatus", [])
    r0 = rec[0] if rec else {}
    counts = try_aws(profile, "configservice", "get-discovered-resource-counts", default={}) or {}
    rules = (try_aws(profile, "configservice", "describe-config-rules", default={}) or {}).get("ConfigRules", [])
    comp = (try_aws(profile, "configservice", "describe-compliance-by-config-rule", default={}) or {}).get("ComplianceByConfigRules", [])
    cmap = {c["ConfigRuleName"]: c.get("Compliance", {}) for c in comp}
    packs = (try_aws(profile, "configservice", "describe-conformance-packs", default={}) or {}).get("ConformancePackDetails", [])
    reglas = []
    for r in rules:
        c = cmap.get(r["ConfigRuleName"], {})
        n = (c.get("ComplianceContributorCount") or {}).get("CappedCount")
        reglas.append({"cuenta": profile, "regla": r["ConfigRuleName"], "origen": _rule_origin(r.get("CreatedBy", ""), r["ConfigRuleName"]),
                       "control_aws": (r.get("Source") or {}).get("SourceIdentifier", "-"),
                       "estado": c.get("ComplianceType", "Sin evaluación propia"), "recursos_no_cumplen": n,
                       "descripcion": r.get("Description", "")})
    name = r0.get("name", "")
    return {"cuenta": profile, "grabando": bool(r0.get("recording")), "ultimo_estado": r0.get("lastStatus", "-"),
            "grabador": "Control Tower" if "controltower" in name else (name or "No configurado"),
            "desde": to_local(r0.get("lastStartTime")), "recursos": counts.get("totalDiscoveredResources", 0),
            "por_tipo": [{"cuenta": profile, "tipo": x["resourceType"], "cantidad": x["count"]} for x in counts.get("resourceCounts", [])],
            "reglas": reglas, "packs": [p_["ConformancePackName"] for p_ in packs]}


def config_findings(profile: str, days: int) -> dict:
    """Consultas rápidas al inventario: discos sueltos, discos sin cifrar y recursos cambiados en los últimos días."""
    since = (now() - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sueltos = config_query(profile, "SELECT resourceId, resourceName, configuration.size "
                                    "WHERE resourceType = 'AWS::EC2::Volume' AND configuration.state.value = 'available'")
    sin_cifrar = config_query(profile, "SELECT resourceId, resourceName, configuration.size, configuration.state.value, configuration.attachments "
                                       "WHERE resourceType = 'AWS::EC2::Volume' AND configuration.encrypted = false")
    cambios = config_query(profile, "SELECT resourceType, resourceId, resourceName, configurationItemCaptureTime, configurationItemStatus "
                                    f"WHERE configurationItemCaptureTime >= '{since}' ORDER BY configurationItemCaptureTime DESC", 1000)
    vol = lambda r: {"cuenta": profile, "volumen": r.get("resourceId"), "nombre": r.get("resourceName") or "-",
                     "gb": (r.get("configuration") or {}).get("size"),
                     "servidor": ", ".join(a.get("instanceId", "") for a in (r.get("configuration") or {}).get("attachments") or []) or "-",
                     "estado": ((r.get("configuration") or {}).get("state") or {}).get("value", "-")}
    return {"sueltos": [vol(r) for r in sueltos], "sin_cifrar": [vol(r) for r in sin_cifrar],
            "cambios": [{"cuenta": profile, "tipo": r.get("resourceType"), "recurso": r.get("resourceName") or r.get("resourceId"),
                         "cuando": to_local(r.get("configurationItemCaptureTime")), "estado": r.get("configurationItemStatus")}
                        for r in cambios]}


# ------------------------------------------------------------- CloudTrail
NOISE = re.compile(r"^(CreateTags|DeleteTags|CreateNetworkInterface|DeleteNetworkInterface|AttachNetworkInterface|"
                   r"DetachNetworkInterface|AssignPrivateIpAddresses|UnassignPrivateIpAddresses|ModifyNetworkInterfaceAttribute|"
                   r"CreateNetworkInterfacePermission|SubmitTaskStateChange|SubmitContainerStateChange|SubmitAttachmentStateChanges|"
                   r"RegisterContainerInstance|UpdateContainerAgent|CreateLogStream|CreateLogGroup|PutRetentionPolicy|CreateGrant|"
                   r"RetireGrant|SendCommand|UpdateInstanceInformation|PutInventory|PutComplianceItems|UpdateInstanceAssociationStatus|"
                   r"PutEvaluations|PutConfigurePackageResult|PutConfigurationAggregator|BatchPutResourceConfig)$")
SENSIBLES = re.compile(r"^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors|DeleteDetector|UpdateDetector|DisableSecurityHub|"
                       r"DeleteConfigurationRecorder|StopConfigurationRecorder|DeleteFlowLogs|CreateUser|DeleteUser|CreateAccessKey|"
                       r"CreateLoginProfile|UpdateLoginProfile|AttachUserPolicy|PutUserPolicy|AttachRolePolicy|PutRolePolicy|CreateRole|"
                       r"UpdateAssumeRolePolicy|DeactivateMFADevice|AuthorizeSecurityGroupIngress|ModifySecurityGroupRules|"
                       r"CreateNetworkAclEntry|ReplaceNetworkAclEntry|PutBucketPolicy|PutBucketAcl|DeletePublicAccessBlock|"
                       r"PutPublicAccessBlock|ModifySnapshotAttribute|ModifyImageAttribute|ModifyDBInstance|ModifyDBSnapshotAttribute|"
                       r"DisassociateWebACL|DeleteWebACL|DeleteFirewall|ScheduleKeyDeletion|DisableKey|DeleteSecret|AllocateAddress|"
                       r"AssociateAddress|UpdateWebACL)$")
SIGNIFICADO = {
    "RunInstances": "Lanzó instancia EC2", "StartInstances": "Encendió instancia", "StopInstances": "Apagó instancia",
    "RebootInstances": "Reinició instancia", "TerminateInstances": "ELIMINÓ instancia",
    "ModifyInstanceAttribute": "Cambió atributo de instancia", "CreateImage": "Creó AMI", "DeregisterImage": "Eliminó AMI",
    "CreateSnapshot": "Creó snapshot EBS", "DeleteSnapshot": "Eliminó snapshot EBS",
    "AuthorizeSecurityGroupIngress": "ABRIÓ regla de ENTRADA en SG", "RevokeSecurityGroupIngress": "Quitó regla de entrada en SG",
    "AuthorizeSecurityGroupEgress": "Abrió regla de salida en SG", "ModifySecurityGroupRules": "Modificó reglas de SG",
    "CreateSecurityGroup": "Creó Security Group", "DeleteSecurityGroup": "Eliminó Security Group",
    "CreateRoute": "Agregó ruta", "ReplaceRoute": "Cambió ruta", "DeleteRoute": "Eliminó ruta",
    "CreateNetworkAclEntry": "Agregó regla NACL", "ReplaceNetworkAclEntry": "Cambió regla NACL",
    "AllocateAddress": "Reservó Elastic IP", "AssociateAddress": "Asoció Elastic IP",
    "CreateVpnConnection": "Creó VPN", "DeleteVpnConnection": "Eliminó VPN", "ModifyVpnTunnelOptions": "Cambió túnel VPN",
    "CreateTransitGatewayRoute": "Agregó ruta en TGW", "DeleteTransitGatewayRoute": "Eliminó ruta en TGW",
    "ModifyDBInstance": "Modificó base RDS", "RebootDBInstance": "Reinició base RDS", "DeleteDBInstance": "ELIMINÓ base RDS",
    "CreateDBSnapshot": "Creó snapshot RDS", "ModifyListener": "Modificó listener de ALB", "ModifyRule": "Modificó regla de ALB",
    "RegisterTargets": "Agregó destinos al target group", "DeregisterTargets": "Sacó destinos del target group",
    "UpdateService": "Deploy o escalado de ECS", "RegisterTaskDefinition": "Nueva versión de task definition",
    "UpdateWebACL": "Modificó reglas WAF", "AssociateWebACL": "Asoció WAF a recurso", "DisassociateWebACL": "DESASOCIÓ WAF",
    "UpdateFunctionCode": "Subió código a Lambda", "UpdateFunctionConfiguration": "Cambió config de Lambda",
    "ChangeResourceRecordSets": "Cambió registros DNS", "CreateUser": "Creó usuario IAM", "CreateAccessKey": "CREÓ ACCESS KEY",
    "CreateRole": "Creó rol IAM", "AttachRolePolicy": "Agregó permisos a rol", "PutRolePolicy": "Política inline en rol",
    "StopLogging": "DETUVO CLOUDTRAIL", "DeleteFlowLogs": "ELIMINÓ FLOW LOGS", "PutBucketPolicy": "Cambió política de bucket",
    "DeletePublicAccessBlock": "QUITÓ bloqueo público de S3", "ScheduleKeyDeletion": "PROGRAMÓ BORRADO DE LLAVE KMS",
    "StartAutomationExecution": "Ejecutó automatización SSM", "StartSession": "Abrió sesión SSM",
}


def cloudtrail_changes(profile: str, days: int = 7, max_items: int = 3000) -> pd.DataFrame:
    q = "Events[].{fecha:EventTime,fuente:EventSource,accion:EventName,usuario:Username,recurso:Resources[0].ResourceName}"
    d = aws(profile, "cloudtrail", "lookup-events", "--start-time", iso(now() - dt.timedelta(days=days)),
            "--lookup-attributes", "AttributeKey=ReadOnly,AttributeValue=false", "--max-items", str(max_items),
            "--query", q, timeout=300)
    df = pd.DataFrame(d if isinstance(d, list) else [])
    if df.empty:
        return df
    df["accion"] = df["accion"].fillna("")
    df = df[~df["accion"].str.match(NOISE)].copy()
    df.insert(0, "cuenta", profile)
    df["fecha"] = df["fecha"].map(to_local)
    df["servicio"] = df["fuente"].str.replace(".amazonaws.com", "", regex=False)
    df["usuario"] = df["usuario"].fillna("(servicio AWS)").str.replace(r"@.*", "", regex=True)
    df["recurso"] = df["recurso"].fillna("-").map(lambda r: r.split("/")[-1])
    base = df["accion"].str.replace(r"20\d{6}[v\d]*$", "", regex=True)
    df["sensible"] = base.str.match(SENSIBLES)
    df["que_significa"] = base.map(SIGNIFICADO).fillna("-")
    return df.drop(columns=["fuente"]).sort_values("fecha", ascending=False)
