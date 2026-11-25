#!/usr/bin/env bash
# aws-changes.sh - Que cambio y que esta pasando en cada cuenta (solo lectura)
# Fuente de cambios: CloudTrail Event History (eventos de escritura, hasta 90 dias)
#
# Uso:  aws sso login --sso-session <tu-sesion>
#       ./aws-changes.sh                    # todas las cuentas, ultimos 7 dias
#       DAYS=2 ./aws-changes.sh prod         # ultimos 2 dias
#       CONSOLE=1 ./aws-changes.sh prod      # agrega la consola de cada EC2
#       LOGTOP=10 LOGLINES=8 ./aws-changes.sh dev
# Guarda cada reporte en ./reportes/cambios-<perfil>-<fecha>.txt
# Compatible con macOS (bash 3.2), Linux y WSL/Git Bash. Todas las horas en hora local.

export AWS_PAGER=""
# Sin argumentos usa $AWS_PULSE_PROFILES o, si no existe, todos los perfiles de ~/.aws/config
PROFILES=${@:-${AWS_PULSE_PROFILES:-$(aws configure list-profiles 2>/dev/null | tr '\n' ' ')}}
DAYS=${DAYS:-7}             # ventana de cambios
MAXEVENTS=${MAXEVENTS:-3000}
TOPN=${TOPN:-25}            # filas maximas por tabla de eventos
LOGTOP=${LOGTOP:-8}         # log groups mas recientes a mostrar
LOGLINES=${LOGLINES:-6}     # lineas por log group / consola
MAXGROUPS=${MAXGROUPS:-80}  # log groups a revisar como maximo
CONSOLE=${CONSOLE:-0}
OUTDIR=${OUTDIR:-./reportes}; mkdir -p "$OUTDIR"; DAY=$(date +%F)
SINCE=$(date -u -v-"${DAYS}"d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "$DAYS days ago" +%Y-%m-%dT%H:%M:%SZ)
NOW=$(date +%s)
TAB=$(printf '\t')

# Offset de la zona horaria local en segundos (ej. -0500 -> -18000)
TZOFF=$(date +%z); TZSEC=$(( 10#${TZOFF:1:2}*3600 + 10#${TZOFF:3:2}*60 )); [ "${TZOFF:0:1}" = "-" ] && TZSEC=$(( -TZSEC ))

SRC='["ec2.amazonaws.com","rds.amazonaws.com","elasticloadbalancing.amazonaws.com","ecs.amazonaws.com","apigateway.amazonaws.com","network-firewall.amazonaws.com","wafv2.amazonaws.com","lambda.amazonaws.com","autoscaling.amazonaws.com","cloudfront.amazonaws.com","route53.amazonaws.com","iam.amazonaws.com","s3.amazonaws.com","kms.amazonaws.com","cloudtrail.amazonaws.com","guardduty.amazonaws.com","securityhub.amazonaws.com","config.amazonaws.com","fms.amazonaws.com","logs.amazonaws.com","ssm.amazonaws.com","secretsmanager.amazonaws.com"]'

# Eventos automaticos que generan ruido (ECS/Lambda crean y borran ENIs todo el tiempo)
NOISE=${NOISE:-'^(CreateTags|DeleteTags|CreateNetworkInterface|DeleteNetworkInterface|AttachNetworkInterface|DetachNetworkInterface|AssignPrivateIpAddresses|UnassignPrivateIpAddresses|ModifyNetworkInterfaceAttribute|CreateNetworkInterfacePermission|SubmitTaskStateChange|SubmitContainerStateChange|SubmitAttachmentStateChanges|RegisterContainerInstance|UpdateContainerAgent|CreateLogStream|CreateLogGroup|PutRetentionPolicy|CreateGrant|RetireGrant|SendCommand|UpdateInstanceInformation|PutInventory|PutComplianceItems|UpdateInstanceAssociationStatus|PutEvaluations|PutConfigurePackageResult|PutConfigurationAggregator|BatchPutResourceConfig)$'}

SENSITIVE='^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors|DeleteDetector|UpdateDetector|DisableSecurityHub|DeleteConfigurationRecorder|StopConfigurationRecorder|DeleteFlowLogs|CreateUser|DeleteUser|CreateAccessKey|CreateLoginProfile|UpdateLoginProfile|AttachUserPolicy|PutUserPolicy|AttachRolePolicy|PutRolePolicy|CreateRole|UpdateAssumeRolePolicy|DeactivateMFADevice|AuthorizeSecurityGroupIngress|ModifySecurityGroupRules|CreateNetworkAclEntry|ReplaceNetworkAclEntry|PutBucketPolicy|PutBucketAcl|DeletePublicAccessBlock|PutPublicAccessBlock|ModifySnapshotAttribute|ModifyImageAttribute|ModifyDBInstance|ModifyDBSnapshotAttribute|DisassociateWebACL|DeleteWebACL|DeleteFirewall|ScheduleKeyDeletion|DisableKey|DeleteSecret|AllocateAddress|AssociateAddress)$'

NETSEC='SecurityGroup|NetworkAcl|Route|Address|Vpn|CustomerGateway|TransitGateway|InternetGateway|NatGateway|VpcPeering|VpcEndpoint|WebACL|IPSet|RuleGroup|FirewallPolicy|Firewall|FlowLogs|Listener|LoadBalancer'

# ---------------------------------------------------------------- utilidades
sec() { printf '\n=========== %s ===========\n' "$1"; }
sub() { printf '\n  > %s\n' "$1"; }

# Alinea columnas separadas por tab (column si existe; si no, awk)
tab() {
  if command -v column >/dev/null 2>&1; then column -t -s "$TAB" | sed 's/^/    /'
  else awk -F'\t' '{for(i=1;i<=NF;i++){c[NR,i]=$i; if(length($i)>w[i])w[i]=length($i)} if(NF>nf)nf=NF}
    END{for(r=1;r<=NR;r++){l="    "; for(i=1;i<=nf;i++) l=l sprintf("%-" w[i] "s  ",c[r,i]); print l}}'; fi
}

# ISO-8601 UTC (2026-06-18T13:02:11+00:00) -> epoch, en Mac y Linux
to_epoch() { d=${1%%+*}; d=${d%Z}; d=${d%%.*}; [ -z "$d" ] && return
  date -u -d "$d" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%S" "$d" +%s 2>/dev/null; }
# Fecha RFC (Thu, 18 Jun 2026 13:02:30 +0000) -> epoch
rfc_epoch() { date -u -d "$1" +%s 2>/dev/null || LC_ALL=C date -u -j -f "%a, %d %b %Y %H:%M:%S %z" "$1" +%s 2>/dev/null; }

# Funciones awk: epoch -> "AAAA-MM-DD HH:MM:SS" (sin depender de gawk) y uptime legible
DATEFN='function fmt(e,  days,r,z,era,doe,yoe,y,doy,mp,d,m){ days=int(e/86400); r=e-days*86400; z=days+719468
  era=int(z/146097); doe=z-era*146097; yoe=int((doe-int(doe/1460)+int(doe/36524)-int(doe/146096))/365)
  y=yoe+era*400; doy=doe-(365*yoe+int(yoe/4)-int(yoe/100)); mp=int((5*doy+2)/153)
  d=doy-int((153*mp+2)/5)+1; m=(mp<10)?mp+3:mp-9; if(m<=2) y++
  return sprintf("%04d-%02d-%02d %02d:%02d:%02d",y,m,d,int(r/3600),int((r%3600)/60),r%60) }
function civ(y,m,d,  era,yoe,doy,doe){ if(m<=2) y--; era=int(y/400); yoe=y-era*400
  doy=int((153*(m>2?m-3:m+9)+2)/5)+d-1; doe=yoe*365+int(yoe/4)-int(yoe/100)+doy; return era*146097+doe-719468 }
function up(u,  d,r){ d=int(u/86400); r=int(u)-d*86400; return sprintf("uptime %dd %02d:%02d:%02d",d,int(r/3600),int((r%3600)/60),r%60) }'
fmt_epoch() { awk -v e="$1" -v o="$TZSEC" "$DATEFN"' BEGIN{ print substr(fmt(e+o),1,16) }'; }

# Eventos CloudTrail (TSV) -> filas con significado en espanol
EVAWK=$(mktemp)
cat > "$EVAWK" <<'AWK'
BEGIN{FS="\t"; OFS="\t"
 d["RunInstances"]="Lanzo instancia EC2"; d["StartInstances"]="Encendio instancia"; d["StopInstances"]="Apago instancia"
 d["RebootInstances"]="Reinicio instancia"; d["TerminateInstances"]="ELIMINO instancia"; d["ModifyInstanceAttribute"]="Cambio atributo de instancia"
 d["ModifyInstanceMetadataOptions"]="Cambio config IMDS"; d["CreateImage"]="Creo AMI"; d["CreateSnapshot"]="Creo snapshot EBS"
 d["CreateVolume"]="Creo volumen EBS"; d["AttachVolume"]="Conecto volumen EBS"; d["ModifyVolume"]="Modifico volumen EBS"; d["DeleteVolume"]="Elimino volumen EBS"
 d["AuthorizeSecurityGroupIngress"]="ABRIO regla de ENTRADA en SG"; d["AuthorizeSecurityGroupEgress"]="Abrio regla de salida en SG"
 d["RevokeSecurityGroupIngress"]="Quito regla de entrada en SG"; d["RevokeSecurityGroupEgress"]="Quito regla de salida en SG"
 d["ModifySecurityGroupRules"]="Modifico reglas de SG"; d["CreateSecurityGroup"]="Creo Security Group"; d["DeleteSecurityGroup"]="Elimino Security Group"
 d["UpdateSecurityGroupRuleDescriptionsIngress"]="Cambio descripcion de regla SG"
 d["CreateRoute"]="Agrego ruta"; d["ReplaceRoute"]="Cambio ruta"; d["DeleteRoute"]="Elimino ruta"
 d["CreateNetworkAclEntry"]="Agrego regla NACL"; d["ReplaceNetworkAclEntry"]="Cambio regla NACL"; d["DeleteNetworkAclEntry"]="Elimino regla NACL"
 d["AllocateAddress"]="Reservo Elastic IP"; d["AssociateAddress"]="Asocio Elastic IP"; d["DisassociateAddress"]="Desasocio Elastic IP"; d["ReleaseAddress"]="Libero Elastic IP"
 d["CreateVpnConnection"]="Creo VPN"; d["DeleteVpnConnection"]="Elimino VPN"; d["ModifyVpnTunnelOptions"]="Cambio opciones de tunel VPN"
 d["CreateTransitGatewayRoute"]="Agrego ruta en TGW"; d["DeleteTransitGatewayRoute"]="Elimino ruta en TGW"
 d["CreateDBInstance"]="Creo base RDS"; d["ModifyDBInstance"]="Modifico base RDS"; d["RebootDBInstance"]="Reinicio base RDS"
 d["StopDBInstance"]="Apago base RDS"; d["StartDBInstance"]="Encendio base RDS"; d["DeleteDBInstance"]="ELIMINO base RDS"; d["CreateDBSnapshot"]="Creo snapshot RDS"
 d["CreateLoadBalancer"]="Creo balanceador"; d["DeleteLoadBalancer"]="Elimino balanceador"; d["CreateListener"]="Creo listener"; d["ModifyListener"]="Modifico listener"
 d["DeleteListener"]="Elimino listener"; d["CreateRule"]="Creo regla de ALB"; d["ModifyRule"]="Modifico regla de ALB"; d["DeleteRule"]="Elimino regla de ALB"
 d["CreateTargetGroup"]="Creo target group"; d["ModifyTargetGroup"]="Modifico target group"; d["RegisterTargets"]="Agrego destinos al TG"; d["DeregisterTargets"]="Saco destinos del TG"
 d["UpdateService"]="Deploy o escalado de ECS"; d["CreateService"]="Creo servicio ECS"; d["DeleteService"]="Elimino servicio ECS"
 d["RegisterTaskDefinition"]="Nueva version de task definition"; d["RunTask"]="Ejecuto tarea ECS"; d["StopTask"]="Detuvo tarea ECS"
 d["CreateDeployment"]="Desplego API"; d["UpdateStage"]="Modifico stage de API"; d["CreateStage"]="Creo stage de API"; d["PutIntegration"]="Cambio integracion de API"
 d["UpdateRestApi"]="Modifico API REST"; d["ImportRestApi"]="Importo API REST"; d["PutRestApi"]="Reemplazo definicion de API"; d["UpdateApi"]="Modifico API HTTP"
 d["UpdateWebACL"]="Modifico reglas WAF"; d["CreateWebACL"]="Creo Web ACL WAF"; d["DeleteWebACL"]="ELIMINO Web ACL WAF"; d["AssociateWebACL"]="Asocio WAF a recurso"
 d["DisassociateWebACL"]="DESASOCIO WAF de recurso"; d["UpdateIPSet"]="Modifico IP set de WAF"; d["UpdateRuleGroup"]="Modifico grupo de reglas"
 d["UpdateFirewallPolicy"]="Modifico politica de Network Firewall"; d["DeleteFirewall"]="ELIMINO Network Firewall"
 d["UpdateFunctionCode"]="Subio codigo nuevo a Lambda"; d["UpdateFunctionConfiguration"]="Cambio config de Lambda"; d["CreateFunction"]="Creo Lambda"; d["DeleteFunction"]="Elimino Lambda"
 d["UpdateAutoScalingGroup"]="Cambio capacidad de Auto Scaling"; d["SetDesiredCapacity"]="Cambio capacidad deseada"
 d["ChangeResourceRecordSets"]="Cambio registros DNS"
 d["CreateUser"]="Creo usuario IAM"; d["DeleteUser"]="Elimino usuario IAM"; d["CreateAccessKey"]="CREO ACCESS KEY"; d["CreateRole"]="Creo rol IAM"
 d["AttachRolePolicy"]="Agrego permisos a rol"; d["PutRolePolicy"]="Agrego politica inline a rol"; d["AttachUserPolicy"]="Agrego permisos a usuario"
 d["UpdateAssumeRolePolicy"]="Cambio quien puede asumir el rol"; d["CreateLoginProfile"]="Habilito consola a usuario"
 d["StopLogging"]="DETUVO CLOUDTRAIL"; d["DeleteTrail"]="ELIMINO TRAIL"; d["UpdateTrail"]="Modifico trail"
 d["DeleteFlowLogs"]="ELIMINO FLOW LOGS"; d["CreateFlowLogs"]="Creo flow logs"
 d["PutBucketPolicy"]="Cambio politica de bucket S3"; d["PutBucketAcl"]="Cambio ACL de bucket S3"; d["DeletePublicAccessBlock"]="QUITO bloqueo publico de S3"
 d["ModifySnapshotAttribute"]="Cambio permisos de snapshot"; d["ScheduleKeyDeletion"]="PROGRAMO BORRADO DE LLAVE KMS"
 d["PutSecretValue"]="Cambio valor de secreto"; d["DeleteSecret"]="Elimino secreto"; d["StartSession"]="Abrio sesion SSM"
 d["DeregisterImage"]="Elimino AMI"; d["DeleteSnapshot"]="Elimino snapshot EBS"; d["CopySnapshot"]="Copio snapshot EBS"; d["CopyImage"]="Copio AMI"
 d["StartAutomationExecution"]="Ejecuto automatizacion SSM"; d["StartBackupJob"]="Inicio backup"; d["CreateAssociation"]="Creo asociacion SSM"
 d["PutParameter"]="Cambio parametro SSM"; d["DeleteParameter"]="Elimino parametro SSM"
 if (hdr) print "FECHA","SERVICIO","USUARIO","ACCION","RECURSO","QUE SIGNIFICA"
}
function desc(e,  k){ k=e; sub(/20[0-9][0-9][0-9][0-9][0-9][0-9][v0-9]*$/,"",k); return (k in d)?d[k]:"-" }
NF>=3 { t=$1; sub(/T/," ",t); t=substr(t,1,16); s=$2; sub(/\.amazonaws\.com$/,"",s)
  if(s=="elasticloadbalancing") s="elb"; else if(s=="network-firewall") s="netfw"
  u=$4; sub(/@.*/,"",u); if(u==""||u=="None") u="(servicio AWS)"
  r=$5; if(r==""||r=="None") r="-"; n=split(r,a,"/"); r=a[n]
  m=desc($3); if(sens!="" && $3 ~ sens) m="(!) " m
  print t, s, substr(u,1,24), substr($3,1,36), substr(r,1,30), m }
AWK

# Pinta una tabla de eventos (TSV de CloudTrail en stdin)
events() { awk -v hdr=1 -v sens="$SENSITIVE" -f "$EVAWK" | tab; }
# Solo el significado de una accion
meaning() { printf -- '-\t-\t%s\t-\t-\n' "$1" | awk -v hdr=0 -v sens="$SENSITIVE" -f "$EVAWK" | cut -f6; }

# ---------------------------------------------------------------- por cuenta
account() {
  p=$1; A="--profile $p"
  ACCT=$(aws sts get-caller-identity $A --query Account --output text 2>/dev/null) \
    || { echo "[$p] sin sesion: corre aws sso login --sso-session <tu-sesion>"; return; }
  T=$(mktemp -d)
  printf '\n################ %s (%s) | ultimos %s dias (desde %s) ################\n' \
    "$p" "$ACCT" "$DAYS" "$(fmt_epoch "$(to_epoch "$SINCE")")"

  aws cloudtrail lookup-events $A --start-time "$SINCE" --max-items "$MAXEVENTS" \
    --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false --output text \
    --query "Events[?contains(\`$SRC\`, EventSource)].[EventTime,EventSource,EventName,Username,Resources[0].ResourceName]" \
    | tr -d '\r' > "$T/all"
  awk -F'\t' -v re="$NOISE" 'NF>=3 && $3 !~ re' "$T/all" | sort -r > "$T/ev"
  total=$(grep -c . "$T/all"); util=$(grep -c . "$T/ev")

  # ---- 1. RESUMEN
  sec "1. RESUMEN: $util cambios relevantes ($total eventos de escritura, sin contar ruido automatico)"
  if [ "$util" -gt 0 ]; then
    sub "Por servicio"
    { printf 'SERVICIO\tCAMBIOS\n'
      awk -F'\t' '{s=$2; sub(/\.amazonaws\.com$/,"",s); c[s]++} END{for(k in c) printf "%s\t%d\n",k,c[k]}' "$T/ev" \
        | sort -t "$TAB" -k2,2nr; } | tab
    sub "Por usuario"
    { printf 'USUARIO\tCAMBIOS\tULTIMO CAMBIO\n'
      awk -F'\t' '{u=$4; if(u==""||u=="None") u="(servicio AWS)"; c[u]++; if(!(u in l)){t=$1; sub(/T/," ",t); l[u]=substr(t,1,16)}}
        END{for(k in c) printf "%s\t%d\t%s\n",k,c[k],l[k]}' "$T/ev" | sort -t "$TAB" -k2,2nr | head -10; } | tab
    sub "Acciones mas frecuentes"
    { printf 'VECES\tACCION\tQUE SIGNIFICA\n'
      cut -f3 "$T/ev" | sort | uniq -c | sort -rn | head -10 | while read -r c a; do
        printf '%s\t%s\t%s\n' "$c" "$a" "$(meaning "$a")"; done; } | tab
  else
    echo "    Sin cambios en el periodo"
  fi

  # ---- 2. SENSIBLES
  sec "2. EVENTOS SENSIBLES (seguridad, permisos, exposicion)"
  awk -F'\t' -v re="$SENSITIVE" '$3 ~ re' "$T/ev" | head -"$TOPN" > "$T/x"
  if [ -s "$T/x" ]; then events < "$T/x"; else echo "    Ninguno"; fi

  # ---- 3. RED Y PERIMETRO
  sec "3. CAMBIOS DE RED Y PERIMETRO (SG, NACL, rutas, EIP, VPN, TGW, WAF, firewall, ALB)"
  awk -F'\t' -v re="$NETSEC" '$3 ~ re' "$T/ev" | head -"$TOPN" > "$T/x"
  if [ -s "$T/x" ]; then events < "$T/x"; else echo "    Ninguno"; fi

  # ---- 4. POR SERVICIO
  sec "4. ULTIMOS CAMBIOS POR SERVICIO (mas recientes primero, max 15 por servicio)"
  found=0
  for s in ec2 rds elasticloadbalancing ecs apigateway lambda autoscaling wafv2 network-firewall iam route53 s3 kms secretsmanager cloudtrail; do
    awk -F'\t' -v s="$s.amazonaws.com" '$2==s' "$T/ev" > "$T/s"
    [ -s "$T/s" ] || continue
    found=1; sub "$s: $(grep -c . "$T/s") cambios"
    head -15 "$T/s" | events
  done
  [ "$found" = "0" ] && echo "    Sin cambios"

  # ---- 5. LOGS
  sec "5. ULTIMOS LOGS (log groups con actividad mas reciente)"
  aws logs describe-log-groups $A --query 'logGroups[].logGroupName' --output text 2>/dev/null \
    | tr '\t' '\n' | grep . | head -"$MAXGROUPS" > "$T/lg"
  : > "$T/lgts"
  while IFS= read -r g; do
    aws logs describe-log-streams $A --log-group-name "$g" --order-by LastEventTime --descending \
      --limit 1 --no-paginate --output text --query 'logStreams[0].[lastEventTimestamp,logStreamName]' </dev/null 2>/dev/null \
      | awk -F'\t' -v g="$g" '$1 ~ /^[0-9]+$/ {printf "%s\t%s\t%s\n",$1,g,$2}' >> "$T/lgts"
  done < "$T/lg"
  sort -rn "$T/lgts" | head -"$LOGTOP" > "$T/top"
  if [ -s "$T/top" ]; then
    sub "Resumen"
    { printf 'ULTIMO EVENTO\tLOG GROUP\tSTREAM\n'
      awk -F'\t' -v o="$TZSEC" "$DATEFN"' {printf "%s\t%s\t%s\n", substr(fmt(int($1/1000)+o),1,16), $2, substr($3,1,50)}' "$T/top"; } | tab
    while IFS="$TAB" read -r ts g st; do
      sub "$g (ultimas $LOGLINES lineas)"
      aws logs get-log-events $A --log-group-name "$g" --log-stream-name "$st" --limit "$LOGLINES" \
        --no-start-from-head --output text --query 'events[].[timestamp,message]' </dev/null 2>/dev/null \
        | tr -d '\r' | awk -F'\t' -v o="$TZSEC" "$DATEFN"'
          $1 ~ /^[0-9]+$/ && length($1)>=12 { m=substr($0,length($1)+2); gsub(/\t/," ",m)
            printf "    %s  %s\n", substr(fmt(int($1/1000)+o),6,14), substr(m,1,180); next }
          NF { gsub(/\t/," "); printf "                      %s\n", substr($0,1,180) }' > "$T/lgl"
      if [ -s "$T/lgl" ]; then cat "$T/lgl"; else echo "    (sin eventos disponibles en ese stream)"; fi
    done < "$T/top"
  else
    echo "    Sin log groups con eventos"
  fi

  # ---- 6. CONSOLA EC2
  if [ "$CONSOLE" = "1" ]; then
    sec "6. CONSOLA DEL SISTEMA OPERATIVO DE CADA EC2 EN EJECUCION"
    aws ec2 describe-instances $A --filters Name=instance-state-name,Values=running --output text \
      --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`]|[0].Value,PlatformDetails,LaunchTime]' > "$T/ec2"
    while IFS="$TAB" read -r id name plat launch; do
      sub "$name | $id | $plat"
      aws ec2 get-console-output $A --instance-id "$id" --latest --output text --query Output </dev/null 2>/dev/null | tr -d '\r' > "$T/con"
      cts=$(aws ec2 get-console-output $A --instance-id "$id" --latest --output text --query Timestamp </dev/null 2>/dev/null)
      lat=1
      if [ ! -s "$T/con" ] || grep -qx None "$T/con"; then
        aws ec2 get-console-output $A --instance-id "$id" --output text --query Output </dev/null 2>/dev/null | tr -d '\r' > "$T/con"; lat=0
      fi
      if ! grep -q '[^[:space:]]' "$T/con" 2>/dev/null || grep -qx None "$T/con"; then echo "    Sin salida de consola disponible"; continue; fi
      console_report "$T/con" "$launch" "$lat" "$id" "${cts:-}"
    done < "$T/ec2"
  fi
  rm -rf "$T"
}

# Analiza la consola de una EC2: $1 archivo, $2 LaunchTime, $3 1=consola en vivo, $4 instance id, $5 hora de captura
# Hora de arranque del SO, de mas a menos precisa:
#   1) boot-times.txt (dato del admin: date -d "$(uptime -s)" +%s)
#   2) reloj registrado en la consola (kernel o cloud-init)
#   3) LaunchTime de EC2, solo si cuadra con el uptime
#   4) cota superior: hora de captura de la consola menos el uptime (se afina en cada corrida y se guarda)
BOOTFILE=${BOOTFILE:-./boot-times.txt}
CACHE="$OUTDIR/.boot-cache"
console_report() {
  con=$1; launch=$2; lat=$3; iid=$4; cts=$5
  last=$(grep -o '^\[ *[0-9]*\.[0-9]*\]' "$con" | tail -1 | tr -d '[] '); last=${last%%.*}
  boot=""; src=""; ub=""
  if [ -n "$last" ]; then
    if [ -f "$BOOTFILE" ]; then
      v=$(awk -v i="$iid" '$1==i{print $2}' "$BOOTFILE" | tail -1)
      [ -n "$v" ] && { boot=$v; src="indicada en boot-times.txt"; }
    fi
    if [ -z "$boot" ]; then
      anchor=$(awk '
        match($0,/^\[ *[0-9]+\.[0-9]+\]/){ u=substr($0,2,RLENGTH-2)+0; if(u<prev) a=""; prev=u
          if ($0 ~ /setting system clock to/ && match($0,/\([0-9]+\)/)) a="rtc\t" u "\t" substr($0,RSTART+1,RLENGTH-2) }
        / at [A-Z][a-z][a-z], [0-9]+ [A-Z][a-z][a-z] [0-9]+ [0-9:]+ [+-][0-9]+\. Up [0-9.]+ seconds/ {
          s=$0; sub(/.* at /,"",s); dt=s; sub(/\. Up .*/,"",dt); v=s; sub(/.*Up /,"",v); sub(/ seconds.*/,"",v)
          a="ci\t" v "\t" dt }
        END{ print a }' "$con")
      if [ -n "$anchor" ]; then
        kind=$(printf '%s' "$anchor" | cut -f1); au=$(printf '%s' "$anchor" | cut -f2); av=$(printf '%s' "$anchor" | cut -f3)
        [ "$kind" = "ci" ] && av=$(rfc_epoch "$av")
        if [ -n "$av" ]; then
          bb=$(( av - ${au%%.*} ))
          [ $(( bb + last )) -le $(( NOW + 600 )) ] && { boot=$bb; src="exacta, reloj registrado en la consola"; }
        fi
      fi
    fi
    lt=$(to_epoch "$launch")
    if [ -z "$boot" ] && [ -n "$lt" ] && [ $(( lt + last )) -le $(( NOW + 600 )) ] && [ $(( NOW - lt - last )) -le 86400 ]; then
      boot=$lt; src="segun LaunchTime de EC2"
    fi
    if [ -z "$boot" ]; then
      ce=$(to_epoch "$cts"); [ -z "$ce" ] && ce=$NOW
      ub=$(( ce - last ))
      if [ -f "$CACHE" ]; then
        prev=$(awk -v i="$iid" '$1==i{print $2" "$3}' "$CACHE" | tail -1)
        pub=${prev% *}; plast=${prev#* }
        if [ -n "$prev" ] && [ "$last" -ge "$plast" ] && [ "$pub" -lt "$ub" ]; then ub=$pub; fi
        grep -v "^$iid " "$CACHE" > "$CACHE.tmp" 2>/dev/null; mv "$CACHE.tmp" "$CACHE"
      fi
      echo "$iid $ub $last" >> "$CACHE"
    fi
  fi

  if [ -n "$boot" ]; then
    printf '    Encendido del SO: %s (%s) | lleva %s dias encendido\n' "$(fmt_epoch "$boot")" "$src" "$(( (NOW - boot) / 86400 ))"
  elif [ -n "$ub" ]; then
    printf '    OJO: el SO se reinicio por dentro (EC2 encendida desde %s, pero el SO solo lleva %s dias).\n' \
      "$(fmt_epoch "$lt")" "$(( last / 86400 ))"
    printf '    AWS no registra ese reinicio, asi que la hora exacta no se puede saber desde AWS.\n'
    printf '    Las horas se muestran como "antes de": el evento ocurrio a esa hora o antes.\n'
    printf '    Cada vez que corras el script la estimacion se afina. Para la hora exacta pide al admin:\n'
    printf '      date -d "$(uptime -s)" +%%s     y agrega "%s <resultado>" en boot-times.txt\n' "$iid"
  fi
  [ "$lat" = "0" ] && echo "    (consola del ultimo arranque: la instancia no soporta consola en vivo)"

  awk -v b="${boot:-0}" -v ub="${ub:-0}" -v o="$TZSEC" -v n="$LOGLINES" "$DATEFN"'
    function when(u){ if (b>0) return substr(fmt(b+int(u)+o),1,19)
                      if (ub>0) return "antes de " substr(fmt(ub+int(u)+o),1,16)
                      return up(u) }
    function note(r){
      if (r ~ /unregistering/) return "Contenedor detenido"
      if (r ~ /renamed from veth/) return "Contenedor creado"
      if (r ~ /entered forwarding state/) return "Contenedor conectado a la red"
      if (r ~ /entered disabled state/) return "Contenedor desconectado"
      if (r ~ /[Oo]ut of memory|oom-kill|Killed process/) return "SIN MEMORIA (OOM)"
      if (r ~ /segfault/) return "Proceso fallo (segfault)"
      if (r ~ /[Ii]\/O error|EXT4-fs error|XFS.*error/) return "ERROR DE DISCO"
      if (r ~ /blocked for more than/) return "Proceso bloqueado (I/O lento)"
      if (r ~ /SSM Agent.*running/) return "Agente SSM iniciado"
      if (r ~ /[Ee]rror|[Ff]ail/) return "Error reportado"
      return "-" }
    function winline(l,  y,mo,d,h,mi,se){ y=substr(l,1,4)+0; mo=substr(l,6,2)+0; d=substr(l,9,2)+0
      h=substr(l,12,2)+0; mi=substr(l,15,2)+0; se=substr(l,18,2)+0
      return substr(fmt(civ(y,mo,d)*86400+h*3600+mi*60+se+o),1,19) }
    { line[NR]=$0 }
    match($0,/^\[ *[0-9]+\.[0-9]+\]/){ u=substr($0,2,RLENGTH-2)+0; r=substr($0,RLENGTH+1); sub(/^ +/,"",r); k=note(r)
      if (k!="-") { if (!(k in cnt)) keys[++nk]=k; cnt[k]++; lastk[k]=when(u) } }
    END{
      if (nk>0) {
        print "    Resumen de lo que paso (segun la consola):"
        printf "      %-30s %6s   %s\n", "EVENTO", "VECES", "ULTIMA VEZ"
        for (i=1;i<=nk;i++) printf "      %-30s %6d   %s\n", keys[i], cnt[keys[i]], lastk[keys[i]]
      }
      print "    Ultimas lineas:"
      printf "      %-26s  %-30s  %s\n", "CUANDO", "QUE SIGNIFICA", "MENSAJE ORIGINAL"
      s=0; for(i=NR;i>0 && s<n;i--) if (line[i] ~ /[^[:space:]]/) idx[++s]=i
      for(j=s;j>=1;j--){ l=line[idx[j]]
        if (match(l,/^\[ *[0-9]+\.[0-9]+\]/)) { u=substr(l,2,RLENGTH-2)+0; r=substr(l,RLENGTH+1); sub(/^ +/,"",r)
          printf "      %-26s  %-30s  %s\n", when(u), note(r), substr(r,1,100) }
        else if (l ~ /^[0-9][0-9][0-9][0-9]\/[0-9][0-9]\/[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z:/) {
          r=substr(l,22); sub(/^ +/,"",r)
          printf "      %-26s  %-30s  %s\n", winline(l), note(r), substr(r,1,100) }
        else printf "      %-26s  %-30s  %s\n", "-", note(l), substr(l,1,100) } }' "$con"
}

for p in $PROFILES; do
  account "$p" 2>>"$OUTDIR/errores-$DAY.log" | tee "$OUTDIR/cambios-$p-$DAY.txt"
done
rm -f "$EVAWK"
echo; echo "Reportes guardados en: $OUTDIR/  (errores de permisos o servicios no usados en errores-$DAY.log)"
