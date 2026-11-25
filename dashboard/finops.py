"""FinOps de AWS Pulse: costo estimado por cuenta a partir del inventario (scripts/aws-cost-inventory.sh).

No usa Cost Explorer (muchas organizaciones con reseller lo bloquean). Multiplica cada recurso por el
precio de lista público de AWS y aplica los ajustes que el usuario indique (descuentos, Savings Plans,
margen del reseller, soporte, IVA). Todo precio lleva su fuente para poder auditarlo.
"""
from __future__ import annotations

import csv
import io
import re
from pathlib import Path

import pandas as pd

H = 730  # horas por mes que usa AWS en sus calculadoras
PRICES_DATE = "2026-11"  # mes en que se verificaron los precios (us-east-1, on-demand)

SRC = {
    "ec2": "https://aws.amazon.com/ec2/pricing/on-demand/",
    "ebs": "https://aws.amazon.com/ebs/pricing/",
    "vpc": "https://aws.amazon.com/vpc/pricing/",
    "vpn": "https://aws.amazon.com/vpn/pricing/",
    "tgw": "https://aws.amazon.com/transit-gateway/pricing/",
    "elb": "https://aws.amazon.com/elasticloadbalancing/pricing/",
    "rds_mariadb": "https://aws.amazon.com/rds/mariadb/pricing/",
    "rds_postgres": "https://aws.amazon.com/rds/postgresql/pricing/",
    "rds_mysql": "https://aws.amazon.com/rds/mysql/pricing/",
    "fargate": "https://aws.amazon.com/fargate/pricing/",
    "lambda": "https://aws.amazon.com/lambda/pricing/",
    "apigw": "https://aws.amazon.com/api-gateway/pricing/",
    "ecr": "https://aws.amazon.com/ecr/pricing/",
    "s3": "https://aws.amazon.com/s3/pricing/",
    "efs": "https://aws.amazon.com/efs/pricing/",
    "cw": "https://aws.amazon.com/cloudwatch/pricing/",
    "trail": "https://aws.amazon.com/cloudtrail/pricing/",
    "config": "https://aws.amazon.com/config/pricing/",
    "sh": "https://aws.amazon.com/security-hub/pricing/",
    "gd": "https://aws.amazon.com/guardduty/pricing/",
    "insp": "https://aws.amazon.com/inspector/pricing/",
    "kms": "https://aws.amazon.com/kms/pricing/",
    "sm": "https://aws.amazon.com/secrets-manager/pricing/",
    "waf": "https://aws.amazon.com/waf/pricing/",
    "fms": "https://aws.amazon.com/firewall-manager/pricing/",
    "nfw": "https://aws.amazon.com/network-firewall/pricing/",
    "shield": "https://aws.amazon.com/shield/pricing/",
    "r53": "https://aws.amazon.com/route53/pricing/",
    "dt": "https://aws.amazon.com/ec2/pricing/on-demand/#Data_Transfer",
    "ct": "https://aws.amazon.com/controltower/pricing/",
    "support": "https://aws.amazon.com/premiumsupport/pricing/",
    "sp": "https://aws.amazon.com/savingsplans/compute-pricing/",
}

# EC2 Linux on-demand USD/hora en us-east-1 (vCPU para calcular licencia Windows)
EC2 = {
    "t3.nano": (0.0052, 2), "t3.micro": (0.0104, 2), "t3.small": (0.0208, 2), "t3.medium": (0.0416, 2),
    "t3.large": (0.0832, 2), "t3.xlarge": (0.1664, 4), "t3.2xlarge": (0.3328, 8),
    "t3a.nano": (0.0047, 2), "t3a.micro": (0.0094, 2), "t3a.small": (0.0188, 2), "t3a.medium": (0.0376, 2),
    "t3a.large": (0.0752, 2), "t3a.xlarge": (0.1504, 4), "t3a.2xlarge": (0.3008, 8),
    "m5.large": (0.096, 2), "m5.xlarge": (0.192, 4), "m5.2xlarge": (0.384, 8),
    "m5a.large": (0.086, 2), "m5a.xlarge": (0.172, 4), "m5a.2xlarge": (0.344, 8),
    "m6a.large": (0.0864, 2), "m6a.xlarge": (0.1728, 4), "m6a.2xlarge": (0.3456, 8), "m6a.4xlarge": (0.6912, 16),
    "m6i.large": (0.096, 2), "m6i.xlarge": (0.192, 4), "m6i.2xlarge": (0.384, 8),
    "r6a.large": (0.1134, 2), "r6a.xlarge": (0.2268, 4), "r6a.2xlarge": (0.4536, 8),
    "c6a.large": (0.0765, 2), "c6a.xlarge": (0.153, 4), "c6a.2xlarge": (0.306, 8),
}
WIN_PER_VCPU = 0.046        # licencia Windows incluida, USD por vCPU-hora
WIN_SPECIAL = {"t3.micro": 0.0196, "t3.nano": 0.0098, "t3a.micro": 0.0186}

# RDS single-AZ USD/hora (Multi-AZ = x2)
RDS = {
    ("db.t3.micro", "mariadb"): 0.017, ("db.t3.small", "mariadb"): 0.034, ("db.t3.medium", "mariadb"): 0.068,
    ("db.t3.large", "mariadb"): 0.136, ("db.m6g.large", "mariadb"): 0.152, ("db.m6g.xlarge", "mariadb"): 0.304,
    ("db.t3.micro", "postgres"): 0.018, ("db.t3.small", "postgres"): 0.036, ("db.t3.medium", "postgres"): 0.072,
    ("db.t3.large", "postgres"): 0.145, ("db.m6g.large", "postgres"): 0.159, ("db.m6g.xlarge", "postgres"): 0.318,
    ("db.t3.medium", "mysql"): 0.068, ("db.m6g.large", "mysql"): 0.152, ("db.m6g.xlarge", "mysql"): 0.304,
}

P = {  # precios unitarios simples
    "gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io1_iops": 0.065, "st1": 0.045, "sc1": 0.015,
    "gp3_iops": 0.005, "gp3_tput": 0.04, "snap": 0.05,
    "ipv4": 0.005, "nat_h": 0.045, "nat_gb": 0.045, "vpce_h": 0.01, "vpn_h": 0.05,
    "tgw_h": 0.05, "tgw_gb": 0.02, "cvpn_h": 0.10,
    "alb_h": 0.0225, "alb_lcu": 0.008, "nlb_h": 0.0225, "nlb_lcu": 0.006, "clb_h": 0.025,
    "rds_gp3": 0.115, "rds_gp2": 0.115, "rds_io1": 0.125, "rds_snap": 0.095,
    "fg_vcpu": 0.04048, "fg_gb": 0.004445,
    "ecr": 0.10, "s3": 0.023, "efs": 0.30,
    "cw_store": 0.03, "cw_ingest": 0.50, "cw_alarm": 0.10, "cw_dash": 3.00,
    "config_item": 0.003, "sh_check": 0.001, "insp_ec2": 1.2585, "insp_lambda": 0.30,
    "kms": 1.00, "secret": 0.40, "r53_zone": 0.50,
    "waf_acl": 5.00, "waf_rule": 1.00, "waf_m": 0.60, "fms_policy": 100.0,
    "nfw_h": 0.395, "shield": 3000.0, "dt_out": 0.09, "dt_az": 0.01, "apigw_m": 3.50,
}

# Supuestos por defecto para lo que el inventario no puede medir (editables en el dashboard)
DEFAULT_ASSUMPTIONS = {
    "Salida a Internet (GB/mes)": 100.0,
    "Tráfico entre AZ (GB/mes)": 50.0,
    "Logs ingeridos CloudWatch (GB/mes)": 5.0,
    "Ítems de AWS Config / mes": 2000.0,
    "Chequeos Security Hub / mes": 15000.0,
    "GuardDuty (USD/mes)": 15.0,
    "Requests WAF (millones/mes)": 10.0,
    "Reglas por web ACL": 6.0,
    "LCU promedio por balanceador": 1.0,
    "Requests API Gateway (millones/mes)": 1.0,
    "Snapshots: % real del tamaño origen": 35.0,
}


# ------------------------------------------------------------------ lectura
def read_inventory(text: str, profile: str) -> pd.DataFrame:
    """Lee un TSV del inventario. Tolera filas partidas por saltos de línea dentro de un campo."""
    rows, buf = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        buf += line.split("\t")
        if len(buf) >= 6:
            rows.append(buf[:5] + ["\t".join(buf[5:])])
            buf = []
    if not rows:
        return pd.DataFrame()
    head, data = rows[0], rows[1:]
    if head[0] != "cuenta":
        data = rows
    df = pd.DataFrame(data, columns=["cuenta", "servicio", "recurso", "detalle", "cantidad", "unidad"])

    def num(x):
        m = re.search(r"-?\d+(\.\d+)?", str(x))
        return float(m.group()) if m else 0.0

    df["cantidad"] = df["cantidad"].map(num)
    df["perfil"] = profile
    return df


def load_dir(folder: str | Path) -> pd.DataFrame:
    folder = Path(folder).expanduser()
    frames = [read_inventory(f.read_text(encoding="utf-8", errors="replace"), f.stem.replace("inventario_", ""))
              for f in sorted(folder.glob("inventario_*.tsv"))]
    frames = [f for f in frames if not f.empty]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def load_uploads(files) -> pd.DataFrame:
    frames = [read_inventory(io.TextIOWrapper(f, encoding="utf-8", errors="replace").read(),
                             Path(f.name).stem.replace("inventario_", "")) for f in files]
    frames = [f for f in frames if not f.empty]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


# ------------------------------------------------------------------ cálculo
def _ec2_price(itype: str, platform: str) -> float | None:
    if itype not in EC2:
        return None
    lin, vcpu = EC2[itype]
    if "windows" in platform.lower():
        return WIN_SPECIAL.get(itype, lin + WIN_PER_VCPU * vcpu)
    return lin


def _item(r, precio, unidad_precio, costo, cat, fuente, tipo="Medido", nota=""):
    return {"perfil": r["perfil"], "cuenta": r["cuenta"], "servicio": r["servicio"], "recurso": r["recurso"],
            "detalle": r["detalle"], "cantidad": r["cantidad"], "precio_ref": precio, "unidad_precio": unidad_precio,
            "costo_lista": round(costo, 2), "categoria": cat, "tipo": tipo, "fuente": SRC.get(fuente, fuente), "nota": nota}


def price_lines(inv: pd.DataFrame, asm: dict[str, dict]) -> pd.DataFrame:
    """Convierte el inventario en líneas de costo mensual a precio de lista. asm = supuestos por perfil."""
    out = []
    for _, r in inv.iterrows():
        s, rec, det, q = r["servicio"], r["recurso"], str(r["detalle"]), float(r["cantidad"])
        a = asm.get(r["perfil"], DEFAULT_ASSUMPTIONS)
        add = lambda *x, **k: out.append(_item(r, *x, **k))
        if s == "EC2" and rec == "instancia":
            itype, plat = (det.split("|") + ["", ""])[:2]
            p = _ec2_price(itype, plat)
            if p is None:
                add(None, "USD/h", 0, "compute", "ec2", "Sin precio", f"Agregar {itype} al catálogo")
            else:
                add(p, "USD/h", p * H * q, "compute", "ec2")
        elif s == "EBS" and rec == "volumen":
            vt = det.split("|")[0]
            iops = float(re.search(r"iops=(\d+)", det).group(1)) if "iops=" in det else 0
            tput = float(re.search(r"tput=(\d+)", det).group(1)) if "tput=" in det else 0
            base = P.get(vt, 0.08)
            extra = 0.0
            if vt == "gp3":
                extra = max(0, iops - 3000) * P["gp3_iops"] + max(0, tput - 125) * P["gp3_tput"]
            elif vt in ("io1", "io2"):
                extra = iops * P["io1_iops"]
            add(base, "USD/GB-mes", base * q + extra, "storage", "ebs")
        elif s == "EBS" and rec == "snapshots":
            pct = a["Snapshots: % real del tamaño origen"] / 100
            add(P["snap"], "USD/GB-mes", P["snap"] * q * pct, "storage", "ebs", "Estimado",
                f"Se asume {pct:.0%} del tamaño origen (son incrementales)")
        elif s == "VPC" and rec in ("IPv4 pública en uso", "Elastic IP sin asociar"):
            add(P["ipv4"], "USD/h por IP", P["ipv4"] * H * q, "network", "vpc")
        elif s == "VPC" and rec == "NAT Gateway":
            add(P["nat_h"], "USD/h", P["nat_h"] * H * q, "network", "vpc")
        elif s == "VPC" and rec == "NAT datos procesados":
            add(P["nat_gb"], "USD/GB", P["nat_gb"] * q, "network", "vpc")
        elif s == "VPC" and rec == "Interface endpoints":
            add(P["vpce_h"], "USD/h por AZ", P["vpce_h"] * H * q, "network", "vpc")
        elif s == "VPN" and rec == "Site-to-Site VPN":
            add(P["vpn_h"], "USD/h", P["vpn_h"] * H * q, "network", "vpn")
        elif s == "VPN" and rec == "Client VPN":
            add(P["cvpn_h"], "USD/h", P["cvpn_h"] * H * q, "network", "vpn", nota="más conexiones activas")
        elif s == "TGW" and rec == "attachments vistos":
            add(P["tgw_h"], "USD/h", P["tgw_h"] * H * q, "network", "tgw", nota="VPC compartidas por RAM: se cobran al dueño")
        elif s == "TGW" and rec == "datos procesados":
            add(P["tgw_gb"], "USD/GB", P["tgw_gb"] * q, "network", "tgw")
        elif s == "ELB":
            lcu = a["LCU promedio por balanceador"]
            if rec == "application":
                add(P["alb_h"], "USD/h + LCU", (P["alb_h"] + P["alb_lcu"] * lcu) * H * q, "network", "elb", nota=f"{lcu:g} LCU supuesto")
            elif rec == "network":
                add(P["nlb_h"], "USD/h + NLCU", (P["nlb_h"] + P["nlb_lcu"] * lcu) * H * q, "network", "elb", nota=f"{lcu:g} NLCU supuesto")
            else:
                add(P["clb_h"], "USD/h", P["clb_h"] * H * q, "network", "elb")
        elif s == "RDS" and rec == "instancia":
            cls, eng = (det.split("|") + ["", ""])[:2]
            maz = "multiAZ=True" in det
            p = RDS.get((cls, eng))
            src = {"mariadb": "rds_mariadb", "postgres": "rds_postgres"}.get(eng, "rds_mysql")
            if p is None:
                add(None, "USD/h", 0, "database", src, "Sin precio", f"Agregar {cls}/{eng} al catálogo")
            else:
                add(p * (2 if maz else 1), "USD/h" + (" (Multi-AZ x2)" if maz else ""), p * (2 if maz else 1) * H * q, "database", src)
        elif s == "RDS" and rec == "almacenamiento":
            st = det.split("|")[0]
            maz = "multiAZ=True" in det
            p = P.get(f"rds_{st}", 0.115) * (2 if maz else 1)
            add(p, "USD/GB-mes" + (" (Multi-AZ x2)" if maz else ""), p * q, "storage", "rds_mysql")
        elif s == "RDS" and rec == "snapshots manuales":
            add(P["rds_snap"], "USD/GB-mes", P["rds_snap"] * q, "storage", "rds_mysql", "Estimado", "Tamaño asignado; el real puede ser menor")
        elif s == "ECS" and rec == "servicio":
            m = re.search(r"cpu,mem=(\d+),(\d+)", det)
            vcpu, gb = (int(m.group(1)) / 1024, int(m.group(2)) / 1024) if m else (0.25, 0.5)
            p = vcpu * P["fg_vcpu"] + gb * P["fg_gb"]
            if "FARGATE" in det:
                add(round(p, 5), "USD/h por tarea", p * H * q, "compute", "fargate", nota=f"{vcpu:g} vCPU, {gb:g} GB")
            else:
                add(0, "-", 0, "compute", "fargate", nota="Corre en EC2: ya está en EC2")
        elif s == "Lambda":
            add(0, "por uso", 0, "other", "lambda", "Estimado", "Normalmente dentro de la capa gratuita")
        elif s == "APIGW":
            m = a["Requests API Gateway (millones/mes)"]
            add(P["apigw_m"], "USD/millón", P["apigw_m"] * m * q, "other", "apigw", "Estimado", f"{m:g} M req/mes por API supuesto")
        elif s == "ECR":
            add(P["ecr"], "USD/GB-mes", P["ecr"] * q, "storage", "ecr")
        elif s == "S3":
            add(P["s3"], "USD/GB-mes", P["s3"] * q, "storage", "s3", nota="Sin requests ni otras clases")
        elif s == "EFS":
            add(P["efs"], "USD/GB-mes", P["efs"] * q, "storage", "efs", nota="Clase Standard")
        elif s == "CloudWatch":
            if rec == "logs almacenados":
                add(P["cw_store"], "USD/GB-mes", P["cw_store"] * q, "observability", "cw")
            elif rec == "logs ingeridos":
                g = q if q > 0 else a["Logs ingeridos CloudWatch (GB/mes)"]
                add(P["cw_ingest"], "USD/GB", P["cw_ingest"] * g, "observability", "cw",
                    "Medido" if q > 0 else "Estimado", "" if q > 0 else f"{g:g} GB/mes supuesto")
            elif rec == "alarmas":
                add(P["cw_alarm"], "USD/alarma-mes", P["cw_alarm"] * max(0, q - 10), "observability", "cw", nota="10 gratis")
            elif rec == "dashboards":
                add(P["cw_dash"], "USD/dashboard-mes", P["cw_dash"] * max(0, q - 3), "observability", "cw", nota="3 gratis")
        elif s == "CloudTrail":
            add(0, "-", 0, "observability", "trail", nota="El primer trail de gestión es gratis")
        elif s == "Config" and "True" in det:
            n = a["Ítems de AWS Config / mes"]
            add(P["config_item"], "USD/ítem", P["config_item"] * n, "security", "config", "Estimado", f"{n:,.0f} ítems/mes supuesto")
        elif s == "SecurityHub" and det == "si":
            n = a["Chequeos Security Hub / mes"]
            add(P["sh_check"], "USD/chequeo", P["sh_check"] * n, "security", "sh", "Estimado", f"{n:,.0f} chequeos/mes supuesto")
        elif s == "GuardDuty" and det == "si":
            v = a["GuardDuty (USD/mes)"]
            add(v, "USD/mes", v, "security", "gd", "Estimado", "Depende del volumen de eventos y flujos")
        elif s == "Inspector" and det.upper() == "ENABLED":
            n_ec2 = inv[(inv["perfil"] == r["perfil"]) & (inv["servicio"] == "EC2") & (inv["recurso"] == "instancia")]["cantidad"].sum()
            n_fn = inv[(inv["perfil"] == r["perfil"]) & (inv["servicio"] == "Lambda")]["cantidad"].sum()
            add(P["insp_ec2"], "USD/EC2-mes", P["insp_ec2"] * n_ec2 + P["insp_lambda"] * n_fn, "security", "insp",
                nota=f"{n_ec2:g} EC2 + {n_fn:g} Lambda")
        elif s == "KMS":
            add(P["kms"], "USD/clave-mes", P["kms"] * q, "security", "kms")
        elif s == "SecretsManager":
            add(P["secret"], "USD/secreto-mes", P["secret"] * q, "security", "sm")
        elif s == "WAF" and rec == "web ACLs":
            rules = a["Reglas por web ACL"]
            add(P["waf_acl"], "USD/ACL + USD 1/regla", (P["waf_acl"] + P["waf_rule"] * rules) * q, "security", "waf",
                nota=f"{rules:g} reglas/grupos por ACL supuesto")
            if q > 0:
                m = a["Requests WAF (millones/mes)"]
                out.append({**_item(r, P["waf_m"], "USD/millón", P["waf_m"] * m, "security", "waf", "Estimado",
                                    f"{m:g} M req/mes supuesto"), "recurso": "requests inspeccionados"})
        elif s == "FirewallManager":
            add(P["fms_policy"], "USD/política-región", P["fms_policy"] * q, "security", "fms", nota="Se cobra en la cuenta admin")
        elif s == "NetworkFirewall":
            add(P["nfw_h"], "USD/h por endpoint", P["nfw_h"] * H * q, "security", "nfw")
        elif s == "ShieldAdvanced" and det == "si":
            add(P["shield"], "USD/mes (org)", P["shield"], "security", "shield")
        elif s == "Route53":
            add(P["r53_zone"], "USD/zona-mes", P["r53_zone"] * q, "network", "r53")
    df = pd.DataFrame(out)
    if df.empty:
        return df
    # Quitar duplicado de "requests WAF" medido=0 del inventario (se reemplaza por el supuesto)
    df = df[~((df["servicio"] == "WAF") & (df["recurso"] == "requests inspeccionados") & (df["tipo"] == "Medido"))]
    return df.reset_index(drop=True)


def unseen_lines(profiles: list[str], asm: dict[str, dict], gov: dict) -> pd.DataFrame:
    """Costos que el inventario no ve: transferencia de datos y cuentas de gobierno (Control Tower)."""
    out = []
    for p in profiles:
        a = asm.get(p, DEFAULT_ASSUMPTIONS)
        g = a["Salida a Internet (GB/mes)"]
        z = a["Tráfico entre AZ (GB/mes)"]
        out.append({"perfil": p, "servicio": "DataTransfer", "recurso": "Salida a Internet", "detalle": f"{g:g} GB/mes",
                    "cantidad": g, "precio_ref": P["dt_out"], "unidad_precio": "USD/GB", "costo_lista": round(g * P["dt_out"], 2),
                    "categoria": "network", "tipo": "Estimado", "fuente": SRC["dt"], "nota": "Los primeros 100 GB/mes de la org son gratis"})
        out.append({"perfil": p, "servicio": "DataTransfer", "recurso": "Entre zonas (AZ)", "detalle": f"{z:g} GB/mes",
                    "cantidad": z, "precio_ref": P["dt_az"] * 2, "unidad_precio": "USD/GB (ida+vuelta)", "costo_lista": round(z * P["dt_az"] * 2, 2),
                    "categoria": "network", "tipo": "Estimado", "fuente": SRC["dt"], "nota": "Réplicas, Multi-AZ, ALB entre AZ"})
    if gov.get("cuentas", 0):
        n, base, gb = gov["cuentas"], gov["usd_cuenta"], gov["logs_gb"]
        out.append({"perfil": "gobierno (no visible)", "servicio": "ControlTower", "recurso": "Cuentas de gestión, Log Archive y Audit",
                    "detalle": f"{n} cuentas x USD {base:g} (Config, CloudTrail org, GuardDuty, Security Hub)", "cantidad": n,
                    "precio_ref": base, "unidad_precio": "USD/cuenta-mes", "costo_lista": round(n * base, 2), "categoria": "security",
                    "tipo": "Estimado", "fuente": SRC["ct"], "nota": "Control Tower no cobra; cobran los servicios que despliega"})
        out.append({"perfil": "gobierno (no visible)", "servicio": "S3", "recurso": "Bucket de logs centralizados",
                    "detalle": f"{gb:g} GB", "cantidad": gb, "precio_ref": P["s3"], "unidad_precio": "USD/GB-mes",
                    "costo_lista": round(gb * P["s3"], 2), "categoria": "storage", "tipo": "Estimado", "fuente": SRC["s3"],
                    "nota": "CloudTrail y Config de toda la organización"})
    return pd.DataFrame(out)


SUPPORT_PLANS = {
    "Incluido por el reseller": None,
    "Basic (gratis)": (0, []),
    "Developer": (29, [(float("inf"), 0.03)]),
    "Business": (100, [(10_000, 0.10), (80_000, 0.07), (250_000, 0.05), (float("inf"), 0.03)]),
    "Enterprise On-Ramp": (5_500, [(float("inf"), 0.10)]),
    "Enterprise": (15_000, [(150_000, 0.10), (500_000, 0.07), (1_000_000, 0.05), (float("inf"), 0.03)]),
}


def support_cost(plan: str, aws_spend: float) -> float:
    spec = SUPPORT_PLANS.get(plan)
    if not spec:
        return 0.0
    minimum, tiers = spec
    cost, prev = 0.0, 0.0
    for top, rate in tiers:
        if aws_spend > prev:
            cost += (min(aws_spend, top) - prev) * rate
        prev = top
    return max(minimum, cost)


def adjust(lines: pd.DataFrame, k: dict) -> pd.DataFrame:
    """Aplica descuentos y recargos línea por línea. k = parámetros del panel."""
    d = lines.copy()
    f = pd.Series(1.0, index=d.index)
    comp = d["categoria"] == "compute"
    db = (d["categoria"] == "database")
    f[comp] *= 1 - k["sp_cov"] / 100 * k["sp_desc"] / 100
    f[db] *= 1 - k["ri_cov"] / 100 * k["ri_desc"] / 100
    f *= 1 - k["edp"] / 100
    f *= 1 + k["margen"] / 100
    d["costo_ajustado"] = (d["costo_lista"] * f).round(2)
    return d


def totals(adj: pd.DataFrame, k: dict) -> dict:
    lista = adj["costo_lista"].sum()
    neto = adj["costo_ajustado"].sum()
    soporte = support_cost(k["soporte"], neto)
    sub = max(0.0, neto + soporte - k["creditos"])
    iva = sub * (k["iva"] / 100) if k["iva_on"] else 0.0
    return {"lista": lista, "neto": neto, "soporte": soporte, "creditos": k["creditos"], "iva": iva, "total": sub + iva}


def opportunities(inv: pd.DataFrame, lines: pd.DataFrame) -> pd.DataFrame:
    """Reglas simples de ahorro, con el ahorro mensual estimado a precio de lista."""
    ops = []

    def add(perfil, que, por_que, ahorro, esfuerzo):
        ops.append({"perfil": perfil, "oportunidad": que, "por_que": por_que, "ahorro_mes": round(ahorro, 2), "esfuerzo": esfuerzo})

    for _, l in lines.iterrows():
        det = str(l["detalle"]).lower()
        if l["servicio"] == "RDS" and l["recurso"] == "instancia" and re.search(r"viej|old|legacy|backup|temp", det):
            stor = lines[(lines["perfil"] == l["perfil"]) & (lines["recurso"] == "almacenamiento") &
                         lines["detalle"].str.contains(str(l["detalle"]).split("|")[-1], regex=False)]["costo_lista"].sum()
            add(l["perfil"], f"Apagar o eliminar {str(l['detalle']).split('|')[-1]}",
                "Por su nombre parece una base reemplazada que sigue encendida (y en Multi-AZ). Validar, tomar snapshot final y eliminar.",
                l["costo_lista"] + stor, "Bajo")
        if l["servicio"] == "EC2" and l["recurso"] == "instancia" and re.search(r"\bdev\b|-dev|test|qa|jmeter", det):
            add(l["perfil"], f"Horario de oficina para {str(l['detalle']).split('|')[-1]}",
                "Entorno de desarrollo encendido 24x7. Apagarlo fuera de 07:00-19:00 L-V ahorra cerca de 64 %.",
                l["costo_lista"] * 0.64, "Bajo")
        if l["servicio"] == "EBS" and str(l["detalle"]).startswith("gp2"):
            add(l["perfil"], "Migrar volúmenes gp2 a gp3", "gp3 cuesta 20 % menos y da 3000 IOPS base. Cambio en caliente, sin downtime.",
                l["costo_lista"] * 0.20, "Bajo")
        if l["servicio"] == "EBS" and l["recurso"] == "snapshots" and l["cantidad"] > 500:
            add(l["perfil"], "Política de retención de snapshots EBS",
                f"{str(l['detalle']).split(' ')[0]} snapshots ({l['cantidad']:,.0f} GB de origen). Con Data Lifecycle Manager se conservan solo los necesarios.",
                l["costo_lista"] * 0.5, "Bajo")
        if l["servicio"] == "VPC" and l["recurso"] == "Elastic IP sin asociar" and l["cantidad"] > 0:
            add(l["perfil"], "Liberar Elastic IP sin uso", "Se cobran aunque no estén asociadas.", l["costo_lista"], "Bajo")
    for p, g in lines.groupby("perfil"):
        comp = g[g["categoria"] == "compute"]["costo_lista"].sum()
        if comp > 50:
            add(p, "Compute Savings Plan 1 año sin pago inicial", "Cubre EC2 y Fargate 24x7 estables. Descuento típico 27 % (hasta 49 % a 3 años).",
                comp * 0.27, "Medio")
        db = g[g["categoria"] == "database"]["costo_lista"].sum()
        if db > 50:
            add(p, "Reserved Instances de RDS 1 año", "Bases productivas 24x7. Descuento típico 35-40 % frente a on-demand.", db * 0.38, "Medio")
    stopped = inv[(inv["servicio"] == "EC2") & (inv["recurso"] == "instancias detenidas") & (inv["cantidad"] > 0)]
    for _, s in stopped.iterrows():
        add(s["perfil"], f"Revisar {int(s['cantidad'])} instancia(s) detenida(s)",
            "No pagan cómputo pero sí sus discos. Si ya no se usan, snapshot y eliminar.", 0, "Bajo")
    return pd.DataFrame(ops).sort_values("ahorro_mes", ascending=False) if ops else pd.DataFrame()
