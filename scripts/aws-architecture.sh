#!/usr/bin/env bash
# aws-architecture.sh - Mapa de arquitectura por cuenta (solo lectura)
# Uso:  aws sso login --sso-session <tu-sesion>
#       ./aws-architecture.sh                  # todas las cuentas
#       ./aws-architecture.sh prod network # solo las indicadas
# Guarda cada reporte en ./reportes/arquitectura-<perfil>-<fecha>.txt
# Compatible con macOS (bash 3.2), Linux y WSL/Git Bash.

export AWS_PAGER=""
# Sin argumentos usa $AWS_PULSE_PROFILES o, si no existe, todos los perfiles de ~/.aws/config
PROFILES=${@:-${AWS_PULSE_PROFILES:-$(aws configure list-profiles 2>/dev/null | tr '\n' ' ')}}
OUTDIR=${OUTDIR:-./reportes}; mkdir -p "$OUTDIR"
DAY=$(date +%F)
SUMMARY="$OUTDIR/resumen-macro-$DAY.txt"
printf 'CUENTA\tID\tVPCs\tSubredes\tEC2_on\tEC2_off\tRDS\tLBs\tECS_svc\tAPIs(REST+HTTP)\tLambda\tWAF_ACLs\tNetFW\tTGW_att\tVPN\n' > "$SUMMARY"

sec() { printf '\n=========== %s ===========\n' "$1"; }
sub() { printf '\n--- %s ---\n' "$1"; }
n()   { v=$("$@" --output text 2>/dev/null) && echo "${v:-0}" || echo "n/a"; }

account() {
  p=$1; A="--profile $p"
  ACCT=$(aws sts get-caller-identity $A --query Account --output text 2>/dev/null) \
    || { echo "[$p] sin sesion: corre aws sso login --sso-session <tu-sesion>"; return; }
  T=$(mktemp -d)
  printf '\n################ %s (%s) - %s ################\n' "$p" "$ACCT" "$DAY"

  # Mapa InstanceId -> Name (se usa en varias secciones)
  aws ec2 describe-instances $A --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`]|[0].Value]' --output text > "$T/nm" 2>/dev/null

  # ------------------------------------------------------------------ RED
  sec "1. RED"
  sub "VPCs"
  aws ec2 describe-vpcs $A --query 'Vpcs[].[Tags[?Key==`Name`]|[0].Value,VpcId,CidrBlock,IsDefault]' --output table

  sub "Subredes y como salen a Internet (segun su route table)"
  aws ec2 describe-route-tables $A --output text --query \
    'RouteTables[].[VpcId,RouteTableId,join(`,`,Associations[?SubnetId].SubnetId),length(Associations[?Main]),Routes[?DestinationCidrBlock==`0.0.0.0/0`]|[0]|[GatewayId||NatGatewayId||TransitGatewayId||NetworkInterfaceId||VpcEndpointId]|[0]]' > "$T/rt"
  aws ec2 describe-subnets $A --output text --query \
    'Subnets[].[VpcId,SubnetId,CidrBlock,AvailabilityZone,Tags[?Key==`Name`]|[0].Value]' > "$T/sn"
  { printf 'VPC\tNOMBRE\tSUBRED\tCIDR\tAZ\tTIPO\n'
    awk -F'\t' 'NR==FNR{ if($4>0) mr[$1]=$5; k=split($3,s,","); for(i=1;i<=k;i++) if(s[i]!="") t[s[i]]=$5; next }
      { g=($2 in t)?t[$2]:mr[$1]
        if(g~/^igw-/) c="PUBLICA (sale por IGW)"; else if(g~/^nat-/) c="PRIVADA (sale por NAT)";
        else if(g~/^tgw-/) c="PRIVADA (sale por TGW)"; else if(g==""||g=="None") c="AISLADA (sin ruta default)";
        else c="PRIVADA (sale por " g ")"
        printf "%s\t%s\t%s\t%s\t%s\t%s\n",$1,($5=="None"?"-":$5),$2,$3,$4,c }' "$T/rt" "$T/sn" | sort
  } | column -t -s $'\t'

  sub "Redes remotas alcanzables por Transit Gateway / VPN (on-prem, otras cuentas)"
  aws ec2 describe-route-tables $A --output text --query \
    'RouteTables[].Routes[?TransitGatewayId||GatewayId!=`local`&&starts_with(GatewayId||`x`,`vgw-`)][].[DestinationCidrBlock,TransitGatewayId||GatewayId]' \
    | sort -u | awk -F'\t' '{printf "  %-20s via %s\n",$1,$2}'

  sub "Internet Gateways y NAT Gateways"
  aws ec2 describe-internet-gateways $A --output text --query 'InternetGateways[].[InternetGatewayId,Attachments[0].VpcId]' | sed 's/^/  IGW  /'
  aws ec2 describe-nat-gateways $A --filter Name=state,Values=available --output text \
    --query 'NatGateways[].[NatGatewayId,VpcId,SubnetId,NatGatewayAddresses[0].PublicIp]' | sed 's/^/  NAT  /'

  sub "Transit Gateway: attachments (quien se conecta con quien)"
  aws ec2 describe-transit-gateway-attachments $A --output table \
    --query 'TransitGatewayAttachments[].[TransitGatewayId,TransitGatewayOwnerId,ResourceType,ResourceId,ResourceOwnerId,State]'

  sub "VPN Site-to-Site y Customer Gateways (peer remoto)"
  aws ec2 describe-customer-gateways $A --output table \
    --query 'CustomerGateways[].[Tags[?Key==`Name`]|[0].Value,CustomerGatewayId,IpAddress,BgpAsn,State]'
  aws ec2 describe-vpn-connections $A --output table \
    --query 'VpnConnections[].[Tags[?Key==`Name`]|[0].Value,VpnConnectionId,CustomerGatewayId,TransitGatewayId||VpnGatewayId,State,join(`/`,VgwTelemetry[].Status)]'

  sub "VPC Peering"
  aws ec2 describe-vpc-peering-connections $A --output table \
    --query 'VpcPeeringConnections[].[VpcPeeringConnectionId,RequesterVpcInfo.OwnerId,RequesterVpcInfo.CidrBlock,AccepterVpcInfo.OwnerId,AccepterVpcInfo.CidrBlock,Status.Code]'

  sub "VPC Endpoints (servicios AWS accedidos en privado)"
  aws ec2 describe-vpc-endpoints $A --output text --query 'VpcEndpoints[].[VpcEndpointType,ServiceName]' \
    | sort | uniq -c | awk '{printf "  %3d  %-12s %s\n",$1,$2,$3}'

  # -------------------------------------------------------------- COMPUTO
  sec "2. COMPUTO"
  sub "EC2"
  aws ec2 describe-instances $A --output table --query \
    'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceId,State.Name,InstanceType,PlatformDetails,PrivateIpAddress,PublicIpAddress,SubnetId,join(`,`,SecurityGroups[].GroupName)]'

  sub "Auto Scaling Groups"
  aws autoscaling describe-auto-scaling-groups $A --output table \
    --query 'AutoScalingGroups[].[AutoScalingGroupName,MinSize,DesiredCapacity,MaxSize,length(Instances)]'

  sub "ECS: clusters y servicios (corriendo/deseado)"
  : > "$T/ecs"
  for c in $(aws ecs list-clusters $A --query 'clusterArns[]' --output text 2>/dev/null); do
    svcs=$(aws ecs list-services $A --cluster "$c" --query 'serviceArns[]' --output text 2>/dev/null | tr '\t' ' ')
    [ -z "$svcs" ] && { printf '%s\t(sin servicios)\t-\t-\t-\n' "${c##*/}" >> "$T/ecs"; continue; }
    echo $svcs | xargs -n 10 aws ecs describe-services $A --cluster "$c" --output text \
      --query 'services[].[serviceName,launchType,desiredCount,runningCount,taskDefinition]' --services 2>/dev/null \
      | awk -F'\t' -v cl="${c##*/}" '{k=split($5,a,"/"); printf "%s\t%s\t%s\t%s/%s\t%s\n",cl,$1,$2,$4,$3,a[k]}' >> "$T/ecs"
  done
  if [ -s "$T/ecs" ]; then { printf 'CLUSTER\tSERVICIO\tTIPO\tRUN/DESIRED\tTASK_DEF\n'; cat "$T/ecs"; } | column -t -s $'\t'; else echo "  Sin ECS"; fi

  sub "Lambda"
  aws lambda list-functions $A --output table --query 'Functions[].[FunctionName,Runtime,VpcConfig.VpcId,LastModified]'

  # ------------------------------------------------- EXPOSICION Y TRAFICO
  sec "3. EXPOSICION: BALANCEADORES, APIS, CDN, DNS"
  sub "Load Balancers"
  aws elbv2 describe-load-balancers $A --output table --query 'LoadBalancers[].[LoadBalancerName,Type,Scheme,VpcId,DNSName]'

  sub "Listeners: puerto -> accion -> target group"
  aws elbv2 describe-load-balancers $A --query 'LoadBalancers[].[LoadBalancerArn,LoadBalancerName]' --output text > "$T/lb" 2>/dev/null
  while IFS=$'\t' read -r arn name; do
    aws elbv2 describe-listeners $A --load-balancer-arn "$arn" --output text </dev/null \
      --query 'Listeners[].[Port,Protocol,DefaultActions[0].Type,DefaultActions[0].TargetGroupArn]' \
      | awk -F'\t' -v lb="$name" '{tg=$4; if(tg!="None"){split(tg,a,"/"); tg=a[2]} else tg="-"; printf "  %-30s :%-5s %-6s %-16s -> %s\n",lb,$1,$2,$3,tg}'
  done < "$T/lb"

  sub "Target groups y salud de sus destinos"
  aws elbv2 describe-target-groups $A --output text \
    --query 'TargetGroups[].[TargetGroupArn,TargetGroupName,Protocol,Port,TargetType]' > "$T/tg" 2>/dev/null
  while IFS=$'\t' read -r arn name proto port type; do
    printf '  %s (%s:%s, %s)\n' "$name" "$proto" "$port" "$type"
    aws elbv2 describe-target-health $A --target-group-arn "$arn" --output text </dev/null \
      --query 'TargetHealthDescriptions[].[Target.Id,Target.Port,TargetHealth.State]' \
      | awk -F'\t' 'NR==FNR{nm[$1]=$2;next}{id=$1; x=(id in nm)?nm[id]" ("id")":id; printf "      %-45s :%-5s %s\n",x,$2,$3}' "$T/nm" -
  done < "$T/tg"

  sub "API Gateway (REST y HTTP/WebSocket)"
  aws apigateway get-rest-apis $A --output table --query 'items[].[name,id,endpointConfiguration.types[0],createdDate]'
  aws apigatewayv2 get-apis $A --output table --query 'Items[].[Name,ApiId,ProtocolType,ApiEndpoint]'

  sub "CloudFront (CDN)"
  aws cloudfront list-distributions $A --output table \
    --query 'DistributionList.Items[].[Id,DomainName,join(`,`,Aliases.Items||`[]`),join(`,`,Origins.Items[].DomainName),Enabled]'

  sub "Route 53: zonas DNS"
  aws route53 list-hosted-zones $A --output table --query 'HostedZones[].[Name,Config.PrivateZone,ResourceRecordSetCount]'

  # ----------------------------------------------------------------- DATOS
  sec "4. DATOS"
  sub "RDS / Aurora"
  aws rds describe-db-instances $A --output table \
    --query 'DBInstances[].[DBInstanceIdentifier,Engine,EngineVersion,DBInstanceClass,MultiAZ,PubliclyAccessible,DBInstanceStatus,DBClusterIdentifier]'
  aws rds describe-db-clusters $A --output table --query 'DBClusters[].[DBClusterIdentifier,Engine,Status,length(DBClusterMembers)]'
  sub "ElastiCache, DynamoDB, EFS, S3"
  aws elasticache describe-cache-clusters $A --output text --query 'CacheClusters[].[CacheClusterId,Engine,CacheNodeType]' | sed 's/^/  ElastiCache  /'
  printf '  DynamoDB tablas: %s\n' "$(n aws dynamodb list-tables $A --query 'length(TableNames)')"
  printf '  EFS file systems: %s\n' "$(n aws efs describe-file-systems $A --query 'length(FileSystems)')"
  printf '  S3 buckets: %s\n' "$(n aws s3api list-buckets $A --query 'length(Buckets)')"
  aws s3api list-buckets $A --output text --query 'Buckets[].Name' 2>/dev/null | tr '\t' '\n' | head -30 | sed 's/^/    /'

  # ---------------------------------------------------- SEGURIDAD PERIMETRAL
  sec "5. SEGURIDAD"
  sub "Security Groups abiertos a Internet (0.0.0.0/0): protocolo:puerto"
  aws ec2 describe-security-groups $A --output text --query \
    'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupName,GroupId,join(`, `,IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]].join(`:`,[IpProtocol,to_string(FromPort)]))]' \
    | sed 's/-1:null/TODO/g' | awk -F'\t' '{printf "  %-35s %-22s %s\n",$1,$2,$3}'
  printf '  Total Security Groups en la cuenta: %s\n' "$(n aws ec2 describe-security-groups $A --query 'length(SecurityGroups)')"

  sub "WAF (regional: ALB / API Gateway)"
  aws wafv2 list-web-acls $A --scope REGIONAL --query 'WebACLs[].[Name,Id,ARN]' --output text > "$T/waf" 2>/dev/null
  [ -s "$T/waf" ] || echo "  Sin Web ACLs regionales"
  while IFS=$'\t' read -r name id arn; do
    echo "  ACL: $name"
    echo "    Reglas: $(aws wafv2 get-web-acl $A --scope REGIONAL --name "$name" --id "$id" --query 'WebACL.Rules[].Name' --output text </dev/null | tr '\t' ',')"
    for rt in APPLICATION_LOAD_BALANCER API_GATEWAY; do
      aws wafv2 list-resources-for-web-acl $A --web-acl-arn "$arn" --resource-type $rt --query 'ResourceArns[]' --output text </dev/null 2>/dev/null \
        | tr '\t' '\n' | grep . | awk -v t=$rt '{k=split($0,a,"/"); printf "    Protege %s: %s\n",t,a[k-1]"/"a[k]}'
    done
  done < "$T/waf"
  sub "WAF (CloudFront)"
  aws wafv2 list-web-acls $A --scope CLOUDFRONT --region us-east-1 --output text --query 'WebACLs[].Name' 2>/dev/null | tr '\t' '\n' | grep . | sed 's/^/  ACL: /' || echo "  Sin Web ACLs de CloudFront"

  sub "AWS Network Firewall"
  fws=$(aws network-firewall list-firewalls $A --query 'Firewalls[].FirewallName' --output text 2>/dev/null)
  if [ -n "$fws" ]; then
    for f in $fws; do
      aws network-firewall describe-firewall $A --firewall-name "$f" --output text \
        --query 'Firewall.[FirewallName,VpcId,join(`,`,SubnetMappings[].SubnetId),FirewallPolicyArn]' | sed 's/^/  /'
    done
  else echo "  Sin Network Firewall en esta cuenta"; fi

  sub "Servicios de seguridad y auditoria"
  printf '  GuardDuty detectores:     %s\n' "$(n aws guardduty list-detectors $A --query 'length(DetectorIds)')"
  printf '  Security Hub:             %s\n' "$(aws securityhub describe-hub $A --query 'SubscribedAt' --output text 2>/dev/null && true || echo 'no habilitado')"
  printf '  Config grabando:          %s\n' "$(n aws configservice describe-configuration-recorder-status $A --query 'ConfigurationRecordersStatus[0].recording')"
  printf '  Firewall Manager admin:   %s\n' "$(n aws fms get-admin-account $A --query 'AdminAccount')"
  echo "  CloudTrail (a donde van los logs de auditoria):"
  aws cloudtrail describe-trails $A --output text --query 'trailList[].[Name,IsMultiRegionTrail,IsOrganizationTrail,S3BucketName,HomeRegion]' | sed 's/^/    /'
  echo "  VPC Flow Logs:"
  aws ec2 describe-flow-logs $A --output text --query 'FlowLogs[].[ResourceId,TrafficType,LogDestinationType,LogGroupName||LogDestination]' | sed 's/^/    /'

  # --------------------------------------------------------- OBSERVABILIDAD
  sec "6. OBSERVABILIDAD"
  sub "Alarmas de CloudWatch por estado"
  aws cloudwatch describe-alarms $A --query 'MetricAlarms[].StateValue' --output text 2>/dev/null | tr '\t' '\n' | grep . | sort | uniq -c | sed 's/^/  /'
  sub "Log groups mas grandes (MB, retencion en dias; None = nunca expira)"
  aws logs describe-log-groups $A --output text --query 'logGroups[].[storedBytes,retentionInDays,logGroupName]' 2>/dev/null \
    | sort -rn | head -15 | awk -F'\t' '{printf "  %10.1f MB  ret:%-5s %s\n",$1/1048576,$2,$3}'
  printf '  Total log groups: %s\n' "$(n aws logs describe-log-groups $A --query 'length(logGroups)')"

  # ---------------------------------------------------------- RESUMEN MACRO
  ecs_n=$(grep -vc '(sin servicios)' "$T/ecs" 2>/dev/null || echo 0)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s+%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$ACCT" \
    "$(n aws ec2 describe-vpcs $A --query 'length(Vpcs)')" \
    "$(n aws ec2 describe-subnets $A --query 'length(Subnets)')" \
    "$(n aws ec2 describe-instances $A --filters Name=instance-state-name,Values=running --query 'length(Reservations[].Instances[])')" \
    "$(n aws ec2 describe-instances $A --filters Name=instance-state-name,Values=stopped --query 'length(Reservations[].Instances[])')" \
    "$(n aws rds describe-db-instances $A --query 'length(DBInstances)')" \
    "$(n aws elbv2 describe-load-balancers $A --query 'length(LoadBalancers)')" \
    "$ecs_n" \
    "$(n aws apigateway get-rest-apis $A --query 'length(items)')" \
    "$(n aws apigatewayv2 get-apis $A --query 'length(Items)')" \
    "$(n aws lambda list-functions $A --query 'length(Functions)')" \
    "$(n aws wafv2 list-web-acls $A --scope REGIONAL --query 'length(WebACLs)')" \
    "$(n aws network-firewall list-firewalls $A --query 'length(Firewalls)')" \
    "$(n aws ec2 describe-transit-gateway-attachments $A --query 'length(TransitGatewayAttachments)')" \
    "$(n aws ec2 describe-vpn-connections $A --query 'length(VpnConnections)')" >> "$SUMMARY"
  rm -rf "$T"
}

for p in $PROFILES; do
  account "$p" 2>&1 | grep -v '^$' --line-buffered -B0 | cat | tee "$OUTDIR/arquitectura-$p-$DAY.txt"
done

sec "VISION MACRO DEL ECOSISTEMA"
column -t -s $'\t' "$SUMMARY" | tee "$SUMMARY.tmp" && mv "$SUMMARY.tmp" "$SUMMARY"
echo
echo "Reportes guardados en: $OUTDIR/"
