"""FinOps de AWS Pulse: costo estimado por cuenta a partir del inventario (scripts/aws-cost-inventory.sh).

No usa Cost Explorer (muchas organizaciones con reseller lo bloquean). Multiplica cada recurso por el
precio de lista público de AWS y aplica los ajustes que el usuario indique (descuentos, Savings Plans,
margen del reseller, soporte, IVA). Todo precio lleva su fuente para poder auditarlo.
"""
from __future__ import annotations

import csv
import math
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
    "rds_aurora": "https://aws.amazon.com/rds/aurora/pricing/",
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
    "m5.large": (0.096, 2), "m5.xlarge": (0.192, 4), "m5.2xlarge": (0.384, 8), "m5.4xlarge": (0.768, 16),
    "m5a.large": (0.086, 2), "m5a.xlarge": (0.172, 4), "m5a.2xlarge": (0.344, 8), "m5a.4xlarge": (0.688, 16),
    "m6a.large": (0.0864, 2), "m6a.xlarge": (0.1728, 4), "m6a.2xlarge": (0.3456, 8), "m6a.4xlarge": (0.6912, 16),
    "m6a.8xlarge": (1.3824, 32),
    "m6i.large": (0.096, 2), "m6i.xlarge": (0.192, 4), "m6i.2xlarge": (0.384, 8), "m6i.4xlarge": (0.768, 16),
    "r6a.large": (0.1134, 2), "r6a.xlarge": (0.2268, 4), "r6a.2xlarge": (0.4536, 8), "r6a.4xlarge": (0.9072, 16),
    "c6a.large": (0.0765, 2), "c6a.xlarge": (0.153, 4), "c6a.2xlarge": (0.306, 8), "c6a.4xlarge": (0.612, 16),
}
SIZES = ["nano", "micro", "small", "medium", "large", "xlarge", "2xlarge", "4xlarge", "8xlarge"]
WIN_PER_VCPU = 0.046        # licencia Windows incluida, USD por vCPU-hora
WIN_SPECIAL = {"t3.micro": 0.0196, "t3.nano": 0.0098, "t3a.micro": 0.0186}

# RDS single-AZ USD/hora (Multi-AZ = x2). MariaDB y MySQL tienen el mismo precio.
_MY = {"db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068, "db.t3.large": 0.136, "db.t3.xlarge": 0.272,
       "db.t3.2xlarge": 0.544, "db.m6g.large": 0.152, "db.m6g.xlarge": 0.304, "db.m6g.2xlarge": 0.608, "db.m6g.4xlarge": 1.216,
       "db.r6g.large": 0.225, "db.r6g.xlarge": 0.45, "db.r6g.2xlarge": 0.90, "db.r6g.4xlarge": 1.80}
_PG = {"db.t3.micro": 0.018, "db.t3.small": 0.036, "db.t3.medium": 0.072, "db.t3.large": 0.145, "db.t3.xlarge": 0.29,
       "db.t3.2xlarge": 0.579, "db.m6g.large": 0.159, "db.m6g.xlarge": 0.318, "db.m6g.2xlarge": 0.636, "db.m6g.4xlarge": 1.272,
       "db.r6g.large": 0.24, "db.r6g.xlarge": 0.48, "db.r6g.2xlarge": 0.96, "db.r6g.4xlarge": 1.92}
# Aurora Standard USD/hora por instancia (writer o reader); el almacenamiento es del clúster y no se duplica
_AU = {"db.t3.medium": 0.082, "db.t3.large": 0.164, "db.r6g.large": 0.26, "db.r6g.xlarge": 0.52,
       "db.r6g.2xlarge": 1.04, "db.r6g.4xlarge": 2.08, "db.r6g.8xlarge": 4.16}
RDS = {**{(c, "mariadb"): v for c, v in _MY.items()}, **{(c, "mysql"): v for c, v in _MY.items()},
       **{(c, "postgres"): v for c, v in _PG.items()},
       **{(c, "aurora-mysql"): v for c, v in _AU.items()}, **{(c, "aurora-postgresql"): v for c, v in _AU.items()}}

P = {  # precios unitarios simples
    "gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io1_iops": 0.065, "st1": 0.045, "sc1": 0.015,
    "gp3_iops": 0.005, "gp3_tput": 0.04, "snap": 0.05,
    "ipv4": 0.005, "nat_h": 0.045, "nat_gb": 0.045, "vpce_h": 0.01, "vpn_h": 0.05,
    "tgw_h": 0.05, "tgw_gb": 0.02, "cvpn_h": 0.10,
    "alb_h": 0.0225, "alb_lcu": 0.008, "nlb_h": 0.0225, "nlb_lcu": 0.006, "clb_h": 0.025,
    "aurora_gb": 0.10, "aurora_io": 0.20,
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
            "costo_lista": round(costo, 2), "categoria": cat, "tipo": tipo, "fuente": SRC.get(fuente, fuente), "nota": nota,
            "src_row": r.name}


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
            src = "rds_aurora" if eng.startswith("aurora") else {"mariadb": "rds_mariadb", "postgres": "rds_postgres"}.get(eng, "rds_mysql")
            if p is None:
                add(None, "USD/h", 0, "database", src, "Sin precio", f"Agregar {cls}/{eng} al catálogo")
            else:
                add(p * (2 if maz else 1), "USD/h" + (" (Multi-AZ x2)" if maz else ""), p * (2 if maz else 1) * H * q, "database", src)
        elif s == "RDS" and rec == "almacenamiento" and det.startswith("aurora"):
            add(P["aurora_gb"], "USD/GB-mes (clúster)", P["aurora_gb"] * q, "storage", "rds_aurora",
                nota="Aurora: 6 copias en 3 AZ incluidas, no se duplica por réplica")
        elif s == "RDS" and rec == "aurora I/O":
            add(P["aurora_io"], "USD/millón de I/O", P["aurora_io"] * q, "storage", "rds_aurora", "Estimado",
                f"{q:g} M de operaciones de E/S al mes supuesto")
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


# ------------------------------------------------------------------ simulación de una cuenta nueva
SCHEDULES = {  # fracción de horas al mes que el cómputo queda encendido
    "24x7 (siempre encendido)": 1.0,
    "Extendido 07:00-22:00 L-S": 15 * 6 / 168,
    "Oficina 07:00-19:00 L-V": 12 * 5 / 168,
}
ORG_SERVICES = ["FirewallManager", "ShieldAdvanced", "NetworkFirewall"]  # se pagan una vez por organización
# Para la tabla de servicios por cuenta: qué es cada servicio en pocas palabras
SERVICE_INFO = {
    "EC2": "Servidores virtuales", "EBS": "Discos de los servidores y snapshots", "RDS": "Bases de datos administradas",
    "ECS": "Contenedores (Fargate)", "ELB": "Balanceadores de carga", "VPC": "Red: IPs públicas, NAT, endpoints",
    "VPN": "Túneles a oficinas o socios", "TGW": "Transit Gateway: une VPC y cuentas", "WAF": "Firewall web (capa 7)",
    "FirewallManager": "Políticas de firewall centralizadas", "NetworkFirewall": "Firewall de red administrado",
    "ShieldAdvanced": "Protección DDoS avanzada", "GuardDuty": "Detección de amenazas", "SecurityHub": "Postura de seguridad",
    "Config": "Registro de cambios de configuración", "Inspector": "Escaneo de vulnerabilidades", "KMS": "Claves de cifrado",
    "SecretsManager": "Contraseñas y secretos", "CloudWatch": "Logs, métricas y alarmas", "CloudTrail": "Auditoría de API",
    "S3": "Almacenamiento de objetos", "EFS": "Disco compartido NFS", "ECR": "Imágenes de contenedores",
    "Lambda": "Funciones sin servidor", "APIGW": "API Gateway", "Route53": "DNS", "DataTransfer": "Transferencia de datos",
    "ControlTower": "Cuentas de gobierno de la organización", "Backup": "Copias de seguridad", "DynamoDB": "Base NoSQL",
}
FARGATE_CPU = [256, 512, 1024, 2048, 4096, 8192, 16384]
AURORA_FAMILY = {"db.t3": "db.t3", "db.m6g": "db.r6g", "db.r6g": "db.r6g"}


FALLBACK = {"m5": "t3", "m6i": "t3", "m5a": "t3a", "m6a": "t3a", "r6a": "t3a", "c6a": "t3a",
            "db.m6g": "db.t3", "db.r6g": "db.t3"}  # al bajar del tamaño mínimo de la familia


def _ladder(pre: str, catalog) -> list[str]:
    return [f"{pre}.{z}" for z in SIZES if f"{pre}.{z}" in catalog]


def _step_size(cls: str, step: int, catalog) -> str:
    """Sube o baja `step` tamaños dentro de la misma familia (m6a.xlarge +1 -> m6a.2xlarge). Si baja del tamaño
    mínimo pasa a la familia burstable equivalente (m6a.large -1 -> t3a.medium). Se detiene en los extremos."""
    pre, _, size = cls.rpartition(".")
    ladder = _ladder(pre, catalog)
    if step == 0 or cls not in ladder:
        return cls
    i = ladder.index(cls) + step
    if i < 0 and FALLBACK.get(pre):
        fl = _ladder(FALLBACK[pre], catalog)
        anchor = fl.index(f"{FALLBACK[pre]}.large") if f"{FALLBACK[pre]}.large" in fl else len(fl) - 1
        return fl[max(0, anchor + i)] if fl else cls
    return ladder[max(0, min(len(ladder) - 1, i))]


CAPACITY_LEVELS = [25, 50, 100, 200, 400]  # % de la cuenta origen; cada duplicación = un tamaño de instancia


def capacity_params(pct: int) -> dict:
    """Traduce '% de capacidad respecto al origen' a cambios concretos por servicio."""
    f = pct / 100
    step = int(round(math.log2(f)))
    return dict(ec2_step=step, ec2_mult=1.0, ecs_size=min(4.0, max(0.25, f)), ecs_mult=1.0, rds_step=step,
                storage_mult=min(3.0, max(0.25, f)),
                rds_maz="Single-AZ" if pct < 100 else "Multi-AZ" if pct > 100 else "Igual que origen")


def _to_aurora(cls: str) -> str:
    pre, _, size = cls.rpartition(".")
    fam = AURORA_FAMILY.get(pre, "db.r6g")
    if fam == "db.t3":
        return "db.t3.large" if size in ("large", "xlarge", "2xlarge") else "db.t3.medium"
    return f"{fam}.{size}" if f"{fam}.{size}" in _AU else "db.r6g.large"


def simulate_account(base: pd.DataFrame, prm: dict, name: str = "ambiente QA") -> tuple[pd.DataFrame, pd.DataFrame]:
    """Crea el inventario de una cuenta nueva a partir de otra (réplica) con los cambios de `prm`.

    prm: ec2_step, ec2_mult, ecs_mult, ecs_size, rds_step, rds_motor ("Igual que origen" | "Aurora"),
         rds_maz ("Igual que origen" | "Multi-AZ" | "Single-AZ"), aurora_readers, aurora_io,
         storage_mult, horario (fracción 0-1), excluir (lista de servicios).
    Devuelve (inventario simulado, tabla de cambios origen -> simulado)."""
    rows, chg = [], []
    frac = prm.get("horario", 1.0)
    aurora = prm.get("rds_motor") == "Aurora"
    log = lambda s, r, a, b: chg.append({"servicio": s, "recurso": r, "origen": a, "simulado": b})
    for _, r in base.iterrows():
        r = r.copy()
        s, rec, det, q = r["servicio"], r["recurso"], str(r["detalle"]), float(r["cantidad"])
        if s in prm.get("excluir", []):
            log(s, rec, f"{q:g}", "no se replica")
            continue
        if s == "EC2" and rec == "instancia":
            itype, plat, nm = (det.split("|") + ["", "", ""])[:3]
            new = _step_size(itype, prm.get("ec2_step", 0), EC2)
            n = max(1 if q >= 1 else 0, math.ceil(q * prm.get("ec2_mult", 1.0)))
            r["detalle"] = f"{new}|{plat}|QA-{nm}"
            r["cantidad"] = n * frac
            tope = " (límite del catálogo)" if new == itype and prm.get("ec2_step", 0) != 0 else ""
            log(s, nm, f"{q:g} × {itype}", f"{n} × {new}{tope}")
        elif s == "ECS" and rec == "servicio" and "FARGATE" in det:
            m = re.search(r"cpu,mem=(\d+),(\d+)", det)
            cpu, mem = (int(m.group(1)), int(m.group(2))) if m else (256, 512)
            f = prm.get("ecs_size", 1.0)
            ncpu = min((c for c in FARGATE_CPU if c >= cpu * f), default=FARGATE_CPU[-1])
            nmem = int(min(mem * ncpu / cpu, 122880))
            n = max(1, math.ceil(q * prm.get("ecs_mult", 1.0)))
            r["detalle"] = re.sub(r"cpu,mem=\d+,\d+", f"cpu,mem={ncpu},{nmem}", det) if m else f"{det}|cpu,mem={ncpu},{nmem}"
            r["cantidad"] = n * frac
            log(s, det.split("|")[0], f"{q:g} tareas × {cpu / 1024:g} vCPU/{mem / 1024:g} GB",
                f"{n} tareas × {ncpu / 1024:g} vCPU/{nmem / 1024:g} GB")
        elif s == "RDS" and rec == "instancia":
            cls, eng, *rest = det.split("|") + [""]
            maz_src = "multiAZ=True" in det
            nm = next((x for x in rest if x and not x.startswith("multiAZ")), "db")
            maz = {"Multi-AZ": True, "Single-AZ": False}.get(prm.get("rds_maz"), maz_src)
            if aurora:
                ncls = _step_size(_to_aurora(cls), prm.get("rds_step", 0), _AU)
                neng = "aurora-postgresql" if "postgres" in eng else "aurora-mysql"
                role = "reader" if re.search(r"reader|replica", nm, re.I) else "writer"
                n_inst = 1 + (1 if maz and role == "writer" else 0)
                r["detalle"] = f"{ncls}|{neng}|multiAZ=False|qa-{nm}"
                r["cantidad"] = n_inst * q * frac
                log(s, nm, f"{cls} {eng}{' Multi-AZ' if maz_src else ''}",
                    f"{n_inst} × {ncls} {neng} ({'writer + reader' if n_inst == 2 else role})")
            else:
                ncls = _step_size(cls, prm.get("rds_step", 0), _PG if "postgres" in eng else _MY)
                r["detalle"] = f"{ncls}|{eng}|multiAZ={maz}|qa-{nm}"
                r["cantidad"] = q * frac
                log(s, nm, f"{cls}{' Multi-AZ' if maz_src else ''}", f"{ncls}{' Multi-AZ' if maz else ''}")
        elif s == "RDS" and rec == "almacenamiento":
            st, *rest = det.split("|")
            nm = rest[-1] if rest else "db"
            gb = q * prm.get("storage_mult", 1.0)
            if aurora:
                if re.search(r"reader|replica", nm, re.I):
                    log(s, f"almacenamiento {nm}", f"{q:g} GB", "compartido con el writer (Aurora)")
                    continue
                r["detalle"] = f"aurora|qa-{nm}"
            else:
                maz = {"Multi-AZ": True, "Single-AZ": False}.get(prm.get("rds_maz"), "multiAZ=True" in det)
                r["detalle"] = re.sub(r"multiAZ=\w+", f"multiAZ={maz}", det)
            r["cantidad"] = gb
        elif (s == "EBS" and rec == "volumen") or s in ("S3", "EFS"):
            r["cantidad"] = q * prm.get("storage_mult", 1.0)
        rows.append(r)
    out = pd.DataFrame(rows)
    if out.empty:
        return out, pd.DataFrame(chg)
    if aurora and (out["servicio"] == "RDS").any():
        tmpl = out[out["servicio"] == "RDS"].iloc[0].copy()
        extra = int(prm.get("aurora_readers", 0))
        if extra:
            w = out[(out["servicio"] == "RDS") & (out["recurso"] == "instancia")]
            if not w.empty:
                rd = w.iloc[0].copy()
                rd["detalle"] = rd["detalle"].rsplit("|", 1)[0] + "|qa-readers-adicionales"
                rd["cantidad"] = extra * frac
                rows.append(rd)
                log("RDS", "réplicas Aurora", "-", f"+{extra} reader(s) {rd['detalle'].split('|')[0]}")
        tmpl["recurso"], tmpl["detalle"], tmpl["cantidad"], tmpl["unidad"] = "aurora I/O", "millones de E/S", prm.get("aurora_io", 0), "M-IO"
        rows.append(tmpl)
        out = pd.DataFrame(rows)
    out["perfil"] = name
    out["cuenta"] = "(nueva)"
    return out.reset_index(drop=True), pd.DataFrame(chg)


COMPONENT_KINDS = ["Servidor EC2", "Base de datos RDS / Aurora", "Servicio ECS Fargate", "Balanceador ALB", "Balanceador NLB",
                   "NAT Gateway", "VPN Site-to-Site", "Volumen EBS gp3 (GB)", "Bucket S3 (GB)", "Secretos (Secrets Manager)",
                   "Web ACL de WAF"]


def new_component(kind: str, name: str, qty: float, **o) -> list[dict]:
    """Filas de inventario para un componente agregado a mano en la simulación (mismo formato que el TSV)."""
    row = lambda s, r, d, q, u="": {"servicio": s, "recurso": r, "detalle": d, "cantidad": float(q), "unidad": u}
    if kind == "Servidor EC2":
        return [row("EC2", "instancia", f"{o['itype']}|{o['plat']}|{name}", qty, "instancia-24x7")]
    if kind == "Base de datos RDS / Aurora":
        eng, maz, gb = o["eng"], o.get("maz", False), o.get("gb", 20)
        inst = row("RDS", "instancia", f"{o['cls']}|{eng}|multiAZ={maz and not eng.startswith('aurora')}|{name}", qty, "instancia-24x7")
        if eng.startswith("aurora"):
            return [inst, row("RDS", "almacenamiento", f"aurora|{name}", gb, "GB-mes")]
        return [inst, row("RDS", "almacenamiento", f"gp3|iops=3000|multiAZ={maz}|{name}", gb * qty, "GB-mes")]
    if kind == "Servicio ECS Fargate":
        return [row("ECS", "servicio", f"{name}|FARGATE|cpu,mem={int(o['vcpu'] * 1024)},{int(o['gb'] * 1024)}", qty, "tarea-24x7")]
    simple = {"Balanceador ALB": ("ELB", "application", "load balancer"), "Balanceador NLB": ("ELB", "network", "load balancer"),
              "NAT Gateway": ("VPC", "NAT Gateway", name), "VPN Site-to-Site": ("VPN", "Site-to-Site VPN", "conexión"),
              "Volumen EBS gp3 (GB)": ("EBS", "volumen", "gp3|iops=3000|tput=125|in-use"),
              "Bucket S3 (GB)": ("S3", "buckets", name), "Secretos (Secrets Manager)": ("SecretsManager", "secretos", name),
              "Web ACL de WAF": ("WAF", "web ACLs", "regional=1")}
    s, r, d = simple[kind]
    return [row(s, r, d, qty)]
