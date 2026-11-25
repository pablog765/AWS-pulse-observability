#!/usr/bin/env bash
# aws-health-check.sh - Resumen de salud y seguridad por cuenta (rol read-only)
# Uso:  aws sso login --sso-session <tu-sesion> --use-device-code
#       ./aws-health-check.sh                 # todas las cuentas
#       ./aws-health-check.sh prod dev       # solo las que indiques

export AWS_PAGER=""
# Sin argumentos usa $AWS_PULSE_PROFILES o, si no existe, todos los perfiles de ~/.aws/config
PROFILES=${@:-${AWS_PULSE_PROFILES:-$(aws configure list-profiles 2>/dev/null | tr '\n' ' ')}}
SINCE=$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)

sec() { printf '\n--- %s ---\n' "$1"; }
NOW=$(date +%s)
TAB=$(printf '\t')

# Fecha ISO-8601 con offset (2026-10-23T15:00:00+00:00 o ...Z) -> epoch, en Linux y Mac
to_epoch() {
  [ -z "$1" ] || [ "$1" = "None" ] && return
  date -d "$1" +%s 2>/dev/null && return
  b=${1%%.*}; b=${b%Z}; off=0
  case "$1" in *[+-][0-9][0-9]:[0-9][0-9])
    o=${1: -6}; b=${b%"$o"}; off=$(( 10#${o:1:2}*3600 + 10#${o:4:2}*60 )); [ "${o:0:1}" = "-" ] && off=$(( -off )) ;;
  esac
  e=$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "${b:0:19}" +%s 2>/dev/null) && echo $(( e - off ))
}
# epoch -> hora local legible
local_time() { date -d "@$1" '+%F %H:%M' 2>/dev/null || date -r "$1" '+%F %H:%M'; }
# segundos -> "3d 4h" / "5h 12m" / "8m"
ago() { s=$1; d=$((s/86400)); h=$(((s%86400)/3600)); m=$(((s%3600)/60))
  if [ $d -gt 0 ]; then echo "${d}d ${h}h"; elif [ $h -gt 0 ]; then echo "${h}h ${m}m"; else echo "${m}m"; fi; }
tab() {
  if command -v column >/dev/null 2>&1; then column -t -s "$TAB" | sed 's/^/  /'
  else awk -F'\t' '{for(i=1;i<=NF;i++){c[NR,i]=$i; if(length($i)>w[i])w[i]=length($i)} if(NF>nf)nf=NF}
    END{for(r=1;r<=NR;r++){l="  "; for(i=1;i<=nf;i++) l=l sprintf("%-" w[i] "s  ",c[r,i]); print l}}'; fi
}

# Estado de VPN Site-to-Site: una fila por tunel, con peer, estado, desde cuando, rutas y caidas en 24 h
vpn_status() {
  A=$1; T=$(mktemp -d)
  aws ec2 describe-vpn-connections $A --output text --query \
    'VpnConnections[?State!=`deleted`].[VpnConnectionId,Tags[?Key==`Name`]|[0].Value,CustomerGatewayId,TransitGatewayId||VpnGatewayId||`-`,State,Options.StaticRoutesOnly,VgwTelemetry[0].OutsideIpAddress,VgwTelemetry[0].Status,VgwTelemetry[0].LastStatusChange,VgwTelemetry[0].AcceptedRouteCount,VgwTelemetry[0].StatusMessage,VgwTelemetry[1].OutsideIpAddress,VgwTelemetry[1].Status,VgwTelemetry[1].LastStatusChange,VgwTelemetry[1].AcceptedRouteCount,VgwTelemetry[1].StatusMessage]' \
    2>/dev/null | tr -d '\r' \
    | awk -F'\t' -v OFS='\t' '{for(i=1;i<=NF;i++) if($i=="") $i="None"; print}' > "$T/vpn"
  if ! grep -q . "$T/vpn"; then echo "  Sin VPN Site-to-Site en esta cuenta"; rm -rf "$T"; return; fi
  aws ec2 describe-customer-gateways $A --output text \
    --query 'CustomerGateways[].[CustomerGatewayId,IpAddress,Tags[?Key==`Name`]|[0].Value]' 2>/dev/null | tr -d '\r' > "$T/cgw"
  END_T=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  {
    printf 'VPN\tPEER (IP REMOTA)\tTUNEL AWS\tESTADO\tDESDE (HORA LOCAL)\tHACE\tRUTAS\tCAIDAS 24H\tDETALLE\n'
    while IFS="$TAB" read -r vid vname cgw gw st static ip1 s1 c1 r1 m1 ip2 s2 c2 r2 m2; do
      peer=$(awk -F'\t' -v id="$cgw" '$1==id{n=($3=="None"||$3=="")?"":" ("$3")"; print $2 n}' "$T/cgw")
      [ "$vname" = "None" ] && vname=$vid
      [ "$static" = "True" ] && rt="estaticas" || rt="BGP"
      for t in 1 2; do
        if [ $t = 1 ]; then ip=$ip1; ts=$s1; ch=$c1; rc=$r1; msg=$m1; else ip=$ip2; ts=$s2; ch=$c2; rc=$r2; msg=$m2; fi
        [ -z "$ip" ] || [ "$ip" = "None" ] && continue
        e=$(to_epoch "$ch")
        if [ -n "$e" ]; then desde=$(local_time "$e"); hace=$(ago $(( NOW - e ))); else desde="-"; hace="-"; fi
        # Horas de las ultimas 24 en que el tunel estuvo caido (CloudWatch AWS/VPN TunnelState minimo = 0)
        caidas=$(aws cloudwatch get-metric-statistics $A --namespace AWS/VPN --metric-name TunnelState \
          --dimensions Name=TunnelIpAddress,Value="$ip" --start-time "$SINCE" --end-time "$END_T" \
          --period 3600 --statistics Minimum --output text --query 'length(Datapoints[?Minimum<`1`])' </dev/null 2>/dev/null)
        case "$caidas" in ''|None) caidas="-" ;; 0) caidas="0" ;; *) caidas="$caidas h con caida" ;; esac
        [ "$ts" = "UP" ] && estado="UP" || estado="DOWN (!)"
        [ "$msg" = "None" ] || [ -z "$msg" ] && msg="-"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s %s\t%s\t%s\n' "$vname" "${peer:-$cgw}" "$ip" "$estado" "$desde" "$hace" "$rc" "$rt" "$caidas" "$msg"
      done
    done < "$T/vpn"
  } | tab
  # Lectura rapida por VPN
  awk -F'\t' '{up=0; if($8=="UP")up++; if($13=="UP")up++; n=($2=="None")?$1:$2
    if(up==2) r="OK: ambos tuneles arriba (redundancia completa)"
    else if(up==1) r="ATENCION: solo 1 tunel arriba, sin redundancia (normal si el peer es activo/pasivo)"
    else r="CAIDA: ningun tunel arriba"
    printf "  %-30s %s\n", n, r}' "$T/vpn"
  rm -rf "$T"
}

# Traduccion de controles de Security Hub a lenguaje claro (fallback: titulo original)
desc_control() {
  case "$1" in
    EC2.2)   echo "El Security Group por defecto de la VPC permite trafico; deberia estar vacio" ;;
    EC2.8)   echo "La instancia acepta IMDSv1; forzar IMDSv2 evita robo de credenciales via SSRF" ;;
    EC2.9)   echo "Instancia EC2 con IP publica directa" ;;
    EC2.13)  echo "Security Group abre SSH (22) a todo Internet" ;;
    EC2.14)  echo "Security Group abre RDP (3389) a todo Internet" ;;
    EC2.18)  echo "Security Group abre a Internet (0.0.0.0/0) puertos no autorizados" ;;
    EC2.19)  echo "Security Group abre a Internet puertos de alto riesgo (SSH, RDP, BD, etc.)" ;;
    EC2.182) echo "Block Public Access de snapshots EBS desactivado: podrian compartirse publicamente" ;;
    ECS.5)   echo "Contenedores ECS con root filesystem escribible; deberia ser solo lectura" ;;
    IAM.6)   echo "Usuario root sin MFA por hardware" ;;
    IAM.9)   echo "Usuario root sin MFA" ;;
    S3.1)    echo "Block Public Access de S3 a nivel de cuenta desactivado" ;;
    S3.8)    echo "Bucket S3 sin Block Public Access" ;;
    SSM.1)   echo "Instancia no gestionada por Systems Manager" ;;
    KMS.4)   echo "Rotacion automatica de llaves KMS desactivada" ;;
    RDS.3)   echo "Base de datos RDS sin cifrado" ;;
    CloudTrail.1) echo "No hay CloudTrail multi-region con eventos de lectura y escritura" ;;
    GuardDuty.1)  echo "GuardDuty no habilitado" ;;
    *)       echo "$2" ;;
  esac
}

for p in $PROFILES; do
  A="--profile $p"
  ACCT=$(aws sts get-caller-identity $A --query Account --output text 2>/dev/null) || { echo "[$p] sin sesion: corre aws sso login"; continue; }
  printf '\n==================== %s (%s) ====================\n' "$p" "$ACCT"

  sec "Inventario EC2"
  aws ec2 describe-instances $A \
    --query 'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceId,State.Name,InstanceType,PrivateIpAddress,PublicIpAddress,PlatformDetails]' \
    --output table

  sec "Alarmas en ALARM (desde cuando)"
  aws cloudwatch describe-alarms $A --state-value ALARM \
    --query 'MetricAlarms[].[AlarmName,StateUpdatedTimestamp,MetricName,Threshold]' --output table

  sec "Status checks distintos de ok"
  aws ec2 describe-instance-status $A \
    --query 'InstanceStatuses[?InstanceStatus.Status!=`ok` || SystemStatus.Status!=`ok`].[InstanceId,InstanceStatus.Status,SystemStatus.Status]' --output table

  sec "Mantenimientos programados por AWS"
  aws ec2 describe-instance-status $A \
    --query 'InstanceStatuses[?Events].[InstanceId,Events[0].Code,Events[0].NotBefore]' --output table

  sec "VPN Site-to-Site (estado por tunel)"
  vpn_status "$A"

  # Una sola descarga (paginas de 100) y luego se procesa localmente
  SH=$(mktemp); NM=$(mktemp)
  aws ec2 describe-instances $A \
    --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`]|[0].Value]' --output text > "$NM"
  aws securityhub get-findings $A --page-size 100 \
    --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"},{"Value":"HIGH","Comparison":"EQUALS"},{"Value":"MEDIUM","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
    --query 'Findings[].[Severity.Label,ProductName,Compliance.SecurityControlId,Title,Resources[0].Id]' \
    --output text 2>/dev/null > "$SH"

  sec "Security Hub: hallazgos activos y nuevos por severidad"
  if [ -s "$SH" ]; then
    cut -f1 "$SH" | sort | uniq -c | sort -rn
  else
    echo "Sin hallazgos o Security Hub no habilitado"
  fi

  sec "1) Configuracion insegura (CRITICAL/HIGH): cantidad, severidad, control, que significa"
  awk -F'\t' '($1=="CRITICAL"||$1=="HIGH") && $3!="None" {c[$3]++; s[$3]=$1; t[$3]=$4}
    END{for(k in c) printf "%d\t%s\t%s\t%s\n", c[k], s[k], k, t[k]}' "$SH" | sort -rn |
  while IFS=$'\t' read -r n sev ctrl title; do
    printf '%4s  %-8s %-8s %s\n' "$n" "$sev" "$ctrl" "$(desc_control "$ctrl" "$title")"
  done

  sec "2) Parches de Windows faltantes por instancia (CRITICAL/HIGH, detectado por Inspector)"
  awk -F'\t' 'FILENAME==ARGV[1]{nm[$1]=$2; next}
    ($1=="CRITICAL"||$1=="HIGH") && $4 ~ /^KB[0-9]+/ {
      k=split($5,a,"/"); id=a[k]; name=(id in nm)?nm[id]:id; c[name]++; l[name]=l[name]" "$4 }
    END{for(n in c) printf "  %-22s %3d parches faltantes:%s\n", n, c[n], l[n]}' "$NM" "$SH"

  sec "3) Vulnerabilidades de software por paquete (CRITICAL/HIGH, top 15)"
  awk -F'\t' 'FILENAME==ARGV[1]{nm[$1]=$2; next}
    ($1=="CRITICAL"||$1=="HIGH") && $4 ~ /^CVE-/ {
      i=index($4," - "); pkg=(i>0)?substr($4,i+3):"Sistema operativo";
      k=split($5,a,"/"); id=a[k]; name=(id in nm)?nm[id]:id; if(id ~ /^sha256:/) name="imagen:" a[k-1];
      c[pkg]++; r=($1=="CRITICAL")?2:1; if(r>m[pkg]) m[pkg]=r;
      if(index(h[pkg],name)==0) h[pkg]=h[pkg]" "name }
    END{for(p in c) printf "%d\t%s\t%s\t%s\n", c[p], (m[p]==2?"CRITICAL":"HIGH"), p, h[p]}' "$NM" "$SH" |
  sort -rn | head -15 |
  while IFS=$'\t' read -r n sev pkg hosts; do
    printf '%4s CVEs  %-8s %-38s en:%s\n' "$n" "$sev" "$pkg" "$hosts"
  done
  rm -f "$SH" "$NM"

  sec "GuardDuty: hallazgos severidad >= 7"
  DET=$(aws guardduty list-detectors $A --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ -n "$DET" ] && [ "$DET" != "None" ]; then
    aws guardduty list-findings $A --detector-id "$DET" \
      --finding-criteria '{"Criterion":{"severity":{"Gte":7},"service.archived":{"Eq":["false"]}}}' \
      --query 'length(FindingIds)' --output text
  else
    echo "GuardDuty no habilitado"
  fi

  sec "Config: reglas NON_COMPLIANT"
  aws configservice describe-compliance-by-config-rule $A --compliance-types NON_COMPLIANT \
    --query 'ComplianceByConfigRules[].ConfigRuleName' --output text 2>/dev/null | tr '\t' '\n'

  sec "Logins a consola ultimas 24 h (usuario, cantidad)"
  aws cloudtrail lookup-events $A --start-time "$SINCE" \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --query 'Events[].Username' --output text | tr '\t' '\n' | sort | uniq -c | sort -rn
done
