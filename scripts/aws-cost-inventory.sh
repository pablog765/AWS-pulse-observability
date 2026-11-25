#!/usr/bin/env bash
# aws-cost-inventory.sh - Inventario facturable por cuenta (SOLO LECTURA)
# Uso:  ./aws-cost-inventory.sh [perfil1 perfil2 ...]
#       ALL_REGIONS=1 ./aws-cost-inventory.sh prod dev   # además barre otras regiones
# Salida: reportes/costos/inventario_<perfil>.tsv  (+ un resumen en pantalla)
# Coste: ~20-40 métricas de CloudWatch por cuenta (< US$0.01 en total).

set -uo pipefail
REGION="${AWS_REGION:-us-east-1}"
if [ $# -gt 0 ]; then PROFILES=("$@"); else read -ra PROFILES <<< "${AWS_PULSE_PROFILES:-$(aws configure list-profiles 2>/dev/null | tr "\n" " ")}"; fi
OUT="reportes/costos"; mkdir -p "$OUT"

START=$(python3 -c 'import datetime as d;print((d.datetime.utcnow()-d.timedelta(days=30)).strftime("%Y-%m-%dT00:00:00Z"))')
END=$(python3 -c 'import datetime as d;print(d.datetime.utcnow().strftime("%Y-%m-%dT00:00:00Z"))')

a() { aws --profile "$P" --region "$REGION" "$@" 2>/dev/null; }
row() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ACC" "$1" "$2" "$3" "$4" "$5" >> "$F"; }
num() { local v="$1"; [[ -z "$v" || "$v" == "None" ]] && v=0; echo "$v"; }

# Suma de una métrica de 30 días usando SEARCH (todas las dimensiones)
metric30() { # $1=namespace,dims  $2=metric  $3=stat
  local q="SUM(SEARCH('{$1} MetricName=\"$2\"', '$3', 2592000))"
  a cloudwatch get-metric-data --start-time "$START" --end-time "$END" \
    --metric-data-queries "[{\"Id\":\"m\",\"Expression\":\"$q\",\"Period\":2592000}]" \
    --query 'sum(MetricDataResults[0].Values)' --output text
}

for P in "${PROFILES[@]}"; do
  ACC=$(a sts get-caller-identity --query Account --output text) || { echo "!! $P sin sesión (aws sso login)"; continue; }
  F="$OUT/inventario_${P}.tsv"
  printf 'cuenta\tservicio\trecurso\tdetalle\tcantidad\tunidad\n' > "$F"
  echo "== $P ($ACC) región $REGION"

  # ---- EC2 instancias (tipo + plataforma) ----
  a ec2 describe-instances --filters Name=instance-state-name,Values=running \
    --query 'Reservations[].Instances[].[InstanceType,PlatformDetails,Tags[?Key==`Name`]|[0].Value]' --output text |
  while IFS=$'\t' read -r t plat name; do row EC2 "instancia" "$t|$plat|${name:-sin-nombre}" 1 "instancia-24x7"; done
  STOP=$(num "$(a ec2 describe-instances --filters Name=instance-state-name,Values=stopped --query 'length(Reservations[].Instances[])' --output text)")
  row EC2 "instancias detenidas" "solo pagan EBS" "$STOP" "instancia"

  # ---- EBS volúmenes y snapshots ----
  a ec2 describe-volumes --query 'Volumes[].[VolumeType,Size,Iops||`0`,Throughput||`0`,State]' --output text |
  while IFS=$'\t' read -r vt sz io th st; do row EBS "volumen" "$vt|iops=$io|tput=$th|$st" "$sz" "GB-mes"; done
  SNAP=$(num "$(a ec2 describe-snapshots --owner-ids self --query 'sum(Snapshots[].VolumeSize)' --output text)")
  SNAPN=$(num "$(a ec2 describe-snapshots --owner-ids self --query 'length(Snapshots)' --output text)")
  row EBS "snapshots" "$SNAPN snapshots (tamaño de origen, real suele ser menor)" "$SNAP" "GB-mes"

  # ---- IPv4 públicas (se cobran todas desde 2024) ----
  IPS=$(num "$(a ec2 describe-network-interfaces --query 'length(NetworkInterfaces[?Association.PublicIp])' --output text)")
  EIPF=$(num "$(a ec2 describe-addresses --query 'length(Addresses[?AssociationId==null])' --output text)")
  row VPC "IPv4 pública en uso" "ENIs con IP pública" "$IPS" "IP-hora-24x7"
  row VPC "Elastic IP sin asociar" "desperdicio" "$EIPF" "IP-hora-24x7"

  # ---- NAT Gateway ----
  NAT=$(num "$(a ec2 describe-nat-gateways --filter Name=state,Values=available --query 'length(NatGateways)' --output text)")
  row VPC "NAT Gateway" "hora" "$NAT" "gateway-24x7"
  if [ "$NAT" != "0" ]; then
    B=$(num "$(metric30 'AWS/NATGateway,NatGatewayId' BytesOutToDestination Sum)")
    B2=$(num "$(metric30 'AWS/NATGateway,NatGatewayId' BytesInFromSource Sum)")
    row VPC "NAT datos procesados" "30 días" "$(python3 -c "print(round(($B+$B2)/1e9,2))")" "GB"
  fi

  # ---- VPC endpoints de interfaz ----
  VPE=$(num "$(a ec2 describe-vpc-endpoints --query 'length(VpcEndpoints[?VpcEndpointType==`Interface`])' --output text)")
  VPEAZ=$(num "$(a ec2 describe-vpc-endpoints --query 'sum(VpcEndpoints[?VpcEndpointType==`Interface`].length(SubnetIds))' --output text)")
  row VPC "Interface endpoints" "$VPE endpoints" "$VPEAZ" "endpoint-AZ-24x7"

  # ---- VPN y Transit Gateway ----
  VPN=$(num "$(a ec2 describe-vpn-connections --query 'length(VpnConnections[?State==`available`])' --output text)")
  row VPN "Site-to-Site VPN" "conexión" "$VPN" "conexion-24x7"
  TGWA=$(num "$(a ec2 describe-transit-gateway-attachments --filters Name=state,Values=available --query 'length(TransitGatewayAttachments)' --output text)")
  row TGW "attachments vistos" "en esta cuenta (cobra al dueño del attachment)" "$TGWA" "attachment-24x7"
  TGWO=$(num "$(a ec2 describe-transit-gateways --query "length(TransitGateways[?OwnerId=='$ACC'])" --output text)")
  if [ "$TGWO" != "0" ]; then
    B=$(num "$(metric30 'AWS/TransitGateway,TransitGateway' BytesIn Sum)")
    row TGW "datos procesados" "30 días (dueño del TGW)" "$(python3 -c "print(round($B/1e9,2))")" "GB"
  fi
  CVPN=$(num "$(a ec2 describe-client-vpn-endpoints --query 'length(ClientVpnEndpoints)' --output text)")
  row VPN "Client VPN" "endpoints" "$CVPN" "endpoint"

  # ---- Balanceadores ----
  a elbv2 describe-load-balancers --query 'LoadBalancers[].Type' --output text | tr '\t' '\n' | sort | uniq -c |
  while read -r n t; do [ -n "$t" ] && row ELB "$t" "load balancer" "$n" "lb-24x7"; done
  CLB=$(num "$(a elb describe-load-balancers --query 'length(LoadBalancerDescriptions)' --output text)")
  row ELB "classic" "load balancer" "$CLB" "lb-24x7"

  # ---- RDS ----
  a rds describe-db-instances --query 'DBInstances[].[DBInstanceClass,Engine,MultiAZ,StorageType,AllocatedStorage,Iops||`0`,DBInstanceIdentifier]' --output text |
  while IFS=$'\t' read -r c e m st sz io id; do
    row RDS "instancia" "$c|$e|multiAZ=$m|$id" 1 "instancia-24x7"
    row RDS "almacenamiento" "$st|iops=$io|multiAZ=$m|$id" "$sz" "GB-mes"
  done
  RSN=$(num "$(a rds describe-db-snapshots --snapshot-type manual --query 'sum(DBSnapshots[].AllocatedStorage)' --output text)")
  row RDS "snapshots manuales" "tamaño asignado" "$RSN" "GB-mes"

  # ---- ECS Fargate ----
  for c in $(a ecs list-clusters --query 'clusterArns[]' --output text); do
    for s in $(a ecs list-services --cluster "$c" --query 'serviceArns[]' --output text); do
      a ecs describe-services --cluster "$c" --services "$s" \
        --query 'services[].[serviceName,launchType||`CAPACITY`,desiredCount,taskDefinition]' --output text |
      while IFS=$'\t' read -r sn lt dc td; do
        cm=$(a ecs describe-task-definition --task-definition "$td" --query 'taskDefinition.[cpu,memory]' --output text)
        row ECS "servicio" "$sn|$lt|cpu,mem=${cm//$'\t'/,}" "$dc" "tarea-24x7"
      done
    done
  done

  # ---- Lambda, API Gateway, ECR, S3, EFS, DynamoDB ----
  row Lambda "funciones" "costo por uso" "$(num "$(a lambda list-functions --query 'length(Functions)' --output text)")" "funcion"
  row APIGW "REST/HTTP APIs" "costo por request" "$(( $(num "$(a apigateway get-rest-apis --query 'length(items)' --output text)") + $(num "$(a apigatewayv2 get-apis --query 'length(Items)' --output text)") ))" "api"
  ECRB=0; for r in $(a ecr describe-repositories --query 'repositories[].repositoryName' --output text); do
    s=$(num "$(a ecr describe-images --repository-name "$r" --query 'sum(imageDetails[].imageSizeInBytes)' --output text)"); ECRB=$((ECRB + ${s%.*})); done
  row ECR "imágenes" "almacenamiento" "$(python3 -c "print(round($ECRB/1e9,2))")" "GB-mes"
  S3N=$(num "$(a s3api list-buckets --query 'length(Buckets)' --output text)")
  S3B=$(num "$(metric30 'AWS/S3,BucketName,StorageType' BucketSizeBytes Average)")
  row S3 "buckets" "$S3N buckets (región $REGION)" "$(python3 -c "print(round($S3B/1e9,2))")" "GB-mes"
  EFS=$(num "$(a efs describe-file-systems --query 'sum(FileSystems[].SizeInBytes.Value)' --output text)")
  row EFS "file systems" "almacenamiento" "$(python3 -c "print(round(${EFS%.*}/1e9,2))")" "GB-mes"
  row DynamoDB "tablas" "" "$(num "$(a dynamodb list-tables --query 'length(TableNames)' --output text)")" "tabla"

  # ---- Observabilidad ----
  LGB=$(num "$(a logs describe-log-groups --query 'sum(logGroups[].storedBytes)' --output text)")
  row CloudWatch "logs almacenados" "total" "$(python3 -c "print(round(${LGB%.*}/1e9,2))")" "GB-mes"
  LIN=$(num "$(metric30 'AWS/Logs,LogGroupName' IncomingBytes Sum)")
  row CloudWatch "logs ingeridos" "30 días" "$(python3 -c "print(round($LIN/1e9,2))")" "GB"
  row CloudWatch "alarmas" "estándar" "$(num "$(a cloudwatch describe-alarms --query 'length(MetricAlarms)' --output text)")" "alarma"
  row CloudWatch "dashboards" "" "$(num "$(a cloudwatch list-dashboards --query 'length(DashboardEntries)' --output text)")" "dashboard"
  row CloudTrail "trails" "el 1.º de gestión es gratis" "$(num "$(a cloudtrail describe-trails --query 'length(trailList)' --output text)")" "trail"
  CFG=$(a configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[0].recording' --output text)
  row Config "recorder" "grabando=$CFG" 1 "info"

  # ---- Seguridad ----
  SH=$(a securityhub describe-hub --query HubArn --output text >/dev/null && echo si || echo no)
  row SecurityHub "habilitado" "$SH" 1 "info"
  GD=$(a guardduty list-detectors --query 'length(DetectorIds)' --output text)
  row GuardDuty "habilitado" "$([ "$(num "$GD")" -gt 0 ] && echo si || echo no)" 1 "info"
  INS=$(a inspector2 batch-get-account-status --query 'accounts[0].state.status' --output text)
  row Inspector "estado" "${INS:-desconocido}" 1 "info"
  row KMS "claves de cliente" "" "$(num "$(a kms list-aliases --query "length(Aliases[?TargetKeyId && !starts_with(AliasName,'alias/aws/')])" --output text)")" "clave-mes"
  row SecretsManager "secretos" "" "$(num "$(a secretsmanager list-secrets --query 'length(SecretList)' --output text)")" "secreto-mes"
  WAFN=$(num "$(a wafv2 list-web-acls --scope REGIONAL --query 'length(WebACLs)' --output text)")
  WAFC=$(num "$(aws --profile "$P" --region us-east-1 wafv2 list-web-acls --scope CLOUDFRONT --query 'length(WebACLs)' --output text 2>/dev/null)")
  row WAF "web ACLs" "regional=$WAFN cloudfront=$WAFC" "$((WAFN + WAFC))" "acl-mes"
  if [ $((WAFN + WAFC)) -gt 0 ]; then
    R=0; for m in AllowedRequests BlockedRequests CountedRequests; do
      v=$(num "$(metric30 'AWS/WAFV2,Region,Rule,WebACL' $m Sum)"); R=$(python3 -c "print($R+$v)"); done
    row WAF "requests inspeccionados" "30 días" "$(python3 -c "print(round($R/1e6,2))")" "millon"
  fi
  NFW=$(num "$(a network-firewall list-firewalls --query 'length(Firewalls)' --output text)")
  row NetworkFirewall "firewalls" "costoso si existe" "$NFW" "endpoint-24x7"
  FMS=$(num "$(a fms list-policies --query 'length(PolicyList)' --output text)")
  row FirewallManager "políticas" "solo visible en cuenta admin" "$FMS" "politica-mes"
  SHA=$(a shield describe-subscription --query 'Subscription.SubscriptionArn' --output text)
  row ShieldAdvanced "suscripción" "$([ -n "$SHA" ] && echo si || echo no)" 1 "info"
  row Route53 "zonas hospedadas" "" "$(num "$(aws --profile "$P" route53 list-hosted-zones --query 'length(HostedZones)' --output text 2>/dev/null)")" "zona-mes"
  row Backup "recovery points" "" "$(num "$(a backup list-recovery-points-by-backup-vault --backup-vault-name Default --query 'length(RecoveryPoints)' --output text)")" "punto"

  # ---- Otras regiones (opcional) ----
  if [ "${ALL_REGIONS:-0}" = "1" ]; then
    for r in $(aws --profile "$P" ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
      [ "$r" = "$REGION" ] && continue
      n=$(num "$(aws --profile "$P" --region "$r" ec2 describe-instances --query 'length(Reservations[].Instances[])' --output text 2>/dev/null)")
      d=$(num "$(aws --profile "$P" --region "$r" rds describe-db-instances --query 'length(DBInstances)' --output text 2>/dev/null)")
      [ "$n" != "0" -o "$d" != "0" ] && row OtraRegion "$r" "EC2=$n RDS=$d" $((n + d)) "recurso"
    done
  fi

  awk -F'\t' 'NR==1 || ($5!="0" && $5!="0.0")' "$F" | column -t -s $'\t' | sed 's/^/  /'
  echo
done
echo "Listo. Archivos en $OUT/  -> súbelos al chat para calcular el costo."
