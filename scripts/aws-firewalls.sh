#!/usr/bin/env bash
# aws-firewalls.sh - Inventario de firewalls y WAF con sus reglas (solo lectura)
# Revisa por cuenta: AWS Network Firewall, WAF regional (ALB/API GW), WAF CloudFront,
# Shield Advanced y politicas de Firewall Manager (desde la cuenta administradora).
# Uso:  ./aws-firewalls.sh                       # las 4 cuentas
#       ./aws-firewalls.sh network security
# Guarda el reporte en ./reportes/firewalls-<fecha>.txt

export AWS_PAGER=""
# Sin argumentos usa $AWS_PULSE_PROFILES o, si no existe, todos los perfiles de ~/.aws/config
PROFILES=${@:-${AWS_PULSE_PROFILES:-$(aws configure list-profiles 2>/dev/null | tr '\n' ' ')}}
REGION=${REGION:-us-east-1}
OUTDIR=${OUTDIR:-./reportes}; mkdir -p "$OUTDIR"; DAY=$(date +%F)
TAB=$(printf '\t')

sec() { printf '\n--- %s ---\n' "$1"; }
tab() {
  if command -v column >/dev/null 2>&1; then column -t -s "$TAB" | sed 's/^/    /'
  else awk -F'\t' '{for(i=1;i<=NF;i++){c[NR,i]=$i; if(length($i)>w[i])w[i]=length($i)} if(NF>nf)nf=NF}
    END{for(r=1;r<=NR;r++){l="    "; for(i=1;i<=nf;i++) l=l sprintf("%-" w[i] "s  ",c[r,i]); print l}}'; fi
}
clean() { tr -d '\r' | awk -F'\t' -v OFS='\t' '{for(i=1;i<=NF;i++) if($i=="") $i="-"; print}'; }

# ------------------------------------------------------------------ WAF
waf_scope() {   # $1 perfil-args  $2 REGIONAL|CLOUDFRONT
  A=$1; scope=$2; reg=$REGION; [ "$scope" = "CLOUDFRONT" ] && reg=us-east-1
  aws wafv2 list-web-acls $A --scope "$scope" --region "$reg" --output text \
    --query 'WebACLs[].[Name,Id,ARN]' 2>/dev/null | clean > "$T/acl"
  if ! grep -q . "$T/acl"; then echo "    Sin Web ACLs ($scope)"; return; fi
  while IFS="$TAB" read -r name id arn; do
    def=$(aws wafv2 get-web-acl $A --scope "$scope" --region "$reg" --name "$name" --id "$id" \
      --query 'join(`,`,keys(WebACL.DefaultAction))' --output text </dev/null 2>/dev/null)
    printf '\n  [WAF %s] %s   (accion por defecto: %s)\n' "$scope" "$name" "${def:-?}"
    [ "$def" = "Allow" ] && echo "    Modelo: deja pasar todo y BLOQUEA solo lo que coincide con las reglas (lista negra)"
    [ "$def" = "Block" ] && echo "    Modelo: bloquea todo y PERMITE solo lo que coincide con las reglas (lista blanca)"
    # Recursos protegidos
    echo "    Protege a:"
    found=0
    for rt in APPLICATION_LOAD_BALANCER API_GATEWAY APPSYNC COGNITO_USER_POOL APP_RUNNER_SERVICE VERIFIED_ACCESS_INSTANCE; do
      [ "$scope" = "CLOUDFRONT" ] && break
      aws wafv2 list-resources-for-web-acl $A --region "$reg" --web-acl-arn "$arn" --resource-type $rt \
        --query 'ResourceArns[]' --output text </dev/null 2>/dev/null | tr '\t' '\n' | grep . \
        | while read -r r; do n=${r#*/}; printf '      %-26s %s\n' "$rt" "$n"; done | grep . && found=1
    done
    if [ "$scope" = "CLOUDFRONT" ]; then
      aws cloudfront list-distributions $A --output text \
        --query "DistributionList.Items[?WebACLId=='$arn'].[Id,DomainName]" </dev/null 2>/dev/null \
        | grep . | sed 's/^/      CloudFront  /' && found=1
    fi
    [ "$found" = "0" ] && echo "      (ningun recurso: el WAF existe pero NO protege nada)"
    # Reglas
    aws wafv2 get-web-acl $A --scope "$scope" --region "$reg" --name "$name" --id "$id" --output json </dev/null 2>/dev/null > "$T/aclj"
    echo "    Reglas en orden de evaluacion (la primera que coincide decide):"
    python3 - "$T/aclj" <<'PY' | tab
import json, sys
try: w = json.load(open(sys.argv[1]))['WebACL']
except Exception: print("(no se pudo leer la Web ACL)"); sys.exit()
def act(r):
    a = r.get('Action') or r.get('OverrideAction') or {}
    k = next(iter(a), '-')
    return {'None': '(usa la del grupo)', 'Count': 'Count (SOLO MONITOREA)'}.get(k, k)
def kind(st):
    if 'ManagedRuleGroupStatement' in st:
        m = st['ManagedRuleGroupStatement']; d = f"{m.get('VendorName')}/{m.get('Name')}"
        ex = [x['Name'] for x in m.get('ExcludedRules', [])]
        ov = [f"{x['Name']}={next(iter(x.get('ActionToUse', {})), '?')}" for x in m.get('RuleActionOverrides', [])]
        if ex: d += " excluye:" + ",".join(ex)
        if ov: d += " override:" + ",".join(ov)
        return "Grupo administrado", d
    if 'RuleGroupReferenceStatement' in st: return "Grupo propio", st['RuleGroupReferenceStatement']['ARN'].split('/')[-2]
    if 'RateBasedStatement' in st: return "Rate limit", f"{st['RateBasedStatement'].get('Limit')} req / 5 min por IP"
    if 'IPSetReferenceStatement' in st: return "Lista de IPs", st['IPSetReferenceStatement']['ARN'].split('/')[-2]
    if 'GeoMatchStatement' in st: return "Geo / pais", ",".join(st['GeoMatchStatement'].get('CountryCodes', []))
    for k in ('ByteMatchStatement', 'RegexMatchStatement', 'SqliMatchStatement', 'XssMatchStatement', 'SizeConstraintStatement'):
        if k in st: return "Patron", k.replace('Statement', '')
    return "Compuesta", ",".join(st.keys())
rows = []
# Firewall Manager inyecta grupos ANTES (pre) y DESPUES (post) de las reglas propias de la cuenta
for fase, key in (("1-FMS pre", 'PreProcessFirewallManagerRuleGroups'), ("2-Cuenta", 'Rules'), ("3-FMS post", 'PostProcessFirewallManagerRuleGroups')):
    for r in sorted(w.get(key, []), key=lambda x: x.get('Priority', 0)):
        st = r.get('FirewallManagerStatement') or r.get('Statement') or {}
        t, d = kind(st)
        rows.append((fase, str(r.get('Priority')), r.get('Name', '-'), act(r), t, d))
if not rows:
    print("NINGUNA: este WAF no tiene reglas, deja pasar todo")
else:
    print("\t".join(("FASE", "PRIO", "REGLA", "ACCION", "TIPO", "DETALLE")))
    for x in rows: print("\t".join(x))
PY
  done < "$T/acl"
}

# ------------------------------------------------------- NETWORK FIREWALL
netfw() {
  A=$1
  aws network-firewall list-firewalls $A --region "$REGION" --output text --query 'Firewalls[].FirewallName' 2>/dev/null \
    | tr '\t' '\n' | grep . > "$T/fw"
  if ! grep -q . "$T/fw"; then echo "    Sin AWS Network Firewall"; return; fi
  while read -r f; do
    aws network-firewall describe-firewall $A --region "$REGION" --firewall-name "$f" --output text </dev/null \
      --query 'Firewall.[VpcId,FirewallPolicyArn,join(`,`,SubnetMappings[].SubnetId),DeleteProtection]' | clean > "$T/fd"
    IFS="$TAB" read -r vpc pol subs delp < "$T/fd"
    printf '\n  [NETWORK FIREWALL] %s\n    VPC: %s | subredes de inspeccion: %s\n    Politica: %s\n' "$f" "$vpc" "$subs" "${pol##*/}"
    aws network-firewall describe-firewall-policy $A --region "$REGION" --firewall-policy-arn "$pol" --output text </dev/null \
      --query 'FirewallPolicy.[join(`,`,StatelessDefaultActions),join(`,`,StatefulDefaultActions||[`-`]),StatefulEngineOptions.RuleOrder]' \
      | clean | awk -F'\t' '{printf "    Accion por defecto stateless: %s | stateful: %s | orden: %s\n",$1,$2,$3}'
    aws network-firewall describe-firewall-policy $A --region "$REGION" --firewall-policy-arn "$pol" --output text </dev/null \
      --query 'FirewallPolicy.[StatefulRuleGroupReferences[].ResourceArn, StatelessRuleGroupReferences[].ResourceArn][][]' \
      | tr '\t' '\n' | grep . > "$T/rg"
    while read -r rg; do
      aws network-firewall describe-rule-group $A --region "$REGION" --rule-group-arn "$rg" --output json </dev/null > "$T/rgj" 2>/dev/null
      python3 - "$T/rgj" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); rg = d.get('RuleGroup', {}); meta = d.get('RuleGroupResponse', {})
src = rg.get('RulesSource', {})
print(f"\n    Grupo de reglas: {meta.get('RuleGroupName')} ({meta.get('Type')}, capacidad {meta.get('Capacity')})")
if 'RulesSourceList' in src:
    l = src['RulesSourceList']
    print(f"      Lista de dominios ({l.get('GeneratedRulesType')}): {', '.join(l.get('Targets', []))[:300]}")
if 'RulesString' in src:
    lines = [x for x in src['RulesString'].splitlines() if x.strip() and not x.startswith('#')]
    print(f"      Reglas Suricata ({len(lines)}):")
    for x in lines[:20]: print("        " + x[:160])
for r in src.get('StatefulRules', [])[:30]:
    h = r['Header']
    print(f"      {r['Action']:6} {h['Protocol']:5} {h['Source']}:{h['SourcePort']} {h['Direction']} {h['Destination']}:{h['DestinationPort']}")
for r in src.get('StatelessRulesAndCustomActions', {}).get('StatelessRules', [])[:30]:
    m = r['RuleDefinition']['MatchAttributes']
    s = ','.join(x['AddressDefinition'] for x in m.get('Sources', [])) or 'any'
    t = ','.join(x['AddressDefinition'] for x in m.get('Destinations', [])) or 'any'
    p = ','.join(f"{x['FromPort']}-{x['ToPort']}" for x in m.get('DestinationPorts', [])) or 'any'
    print(f"      [{r['Priority']}] {','.join(r['RuleDefinition']['Actions'])}  {s} -> {t} : {p}")
PY
    done < "$T/rg"
  done < "$T/fw"
}

# ---------------------------------------------------------- FIREWALL MANAGER
fms() {
  A=$1; acct=$2
  admin=$(aws fms get-admin-account $A --region "$REGION" --query AdminAccount --output text 2>/dev/null)
  if [ -z "$admin" ] || [ "$admin" = "None" ]; then echo "    Firewall Manager no configurado"; return; fi
  if [ "$admin" != "$acct" ]; then echo "    Administrado por la cuenta $admin (las politicas se ven alla)"; return; fi
  echo "    Esta es la cuenta ADMINISTRADORA de Firewall Manager. Politicas que impone a la organizacion:"
  aws fms list-policies $A --region "$REGION" --output text \
    --query 'PolicyList[].[PolicyName,SecurityServiceType,ResourceType,RemediationEnabled,PolicyId]' 2>/dev/null | clean > "$T/pol"
  if ! grep -q . "$T/pol"; then echo "    (sin politicas)"; return; fi
  awk -F'\t' -v OFS='\t' 'BEGIN{print "POLITICA","TIPO","APLICA A","AUTO-REMEDIA"}
    { t=$2; if(t=="WAFV2")t="WAF"; else if(t=="SECURITY_GROUPS_COMMON")t="SG comun (se agrega a todos)";
      else if(t=="SECURITY_GROUPS_CONTENT_AUDIT")t="Auditoria de reglas SG"; else if(t=="SECURITY_GROUPS_USAGE_AUDIT")t="SG sin uso/redundantes";
      else if(t=="NETWORK_FIREWALL")t="Network Firewall"; else if(t=="SHIELD_ADVANCED")t="Shield Advanced"; else if(t=="DNS_FIREWALL")t="Route 53 DNS Firewall"
      r=($4=="True")?"SI (corrige solo)":"no (solo reporta)"; print $1,t,$3,r }' "$T/pol" | tab
  echo
  echo "    Cumplimiento por cuenta:"
  while IFS="$TAB" read -r pname ptype prt prem pid; do
    aws fms list-compliance-status $A --region "$REGION" --policy-id "$pid" --output text </dev/null \
      --query 'PolicyComplianceStatusList[].[MemberAccount,EvaluationResults[0].ComplianceStatus,EvaluationResults[0].ViolatorCount]' 2>/dev/null \
      | clean | awk -F'\t' -v p="$pname" '$1!="" && $1!="-" && $1!="None" {printf "      %-40s cuenta %-14s %-14s violaciones: %s\n",p,$1,$2,$3}'
  done < "$T/pol"
  echo
  echo "    Definicion de cada politica (lo que FMS empuja a las cuentas):"
  while IFS="$TAB" read -r pname ptype prt prem pid; do
    aws fms get-policy $A --region "$REGION" --policy-id "$pid" --output json </dev/null 2>/dev/null > "$T/polj"
    python3 - "$T/polj" "$pname" <<'PY'
import json, sys
try: p = json.load(open(sys.argv[1]))['Policy']
except Exception: sys.exit()
print(f"\n      [{sys.argv[2]}]")
inc = (p.get('IncludeMap', {}).get('ACCOUNT') or []) + (p.get('IncludeMap', {}).get('ORG_UNIT') or [])
exc = p.get('ExcludeMap', {}).get('ACCOUNT')
print(f"        Alcance: {'cuentas/OU ' + ','.join(inc) if inc else 'toda la organizacion'}" + (f" | excluye: {','.join(exc)}" if exc else ""))
if p.get('ResourceTags'): print("        Solo recursos con tags: " + ", ".join(f"{t['Key']}={t.get('Value','')}" for t in p['ResourceTags']))
msd = p.get('SecurityServicePolicyData', {}).get('ManagedServiceData')
if not msd: sys.exit()
d = json.loads(msd)
if 'defaultAction' in d: print(f"        Accion por defecto del WAF: {d['defaultAction'].get('type')}")
for fase, key in (("PRE ", 'preProcessRuleGroups'), ("POST", 'postProcessRuleGroups')):
    for g in d.get(key, []):
        mid = g.get('managedRuleGroupIdentifier') or {}
        name = f"{mid.get('vendorName')}/{mid.get('managedRuleGroupName')}" if mid else g.get('ruleGroupArn', '?').split('/')[-2]
        ov = (g.get('overrideAction') or {}).get('type', '-')
        ex = [x.get('name') for x in g.get('excludeRules', [])]
        rao = (g.get('ruleActionOverrides') or []) + (mid.get('ruleActionOverrides') or [])
        cnt = [x.get('name') for x in rao if 'count' in {k.lower() for k in (x.get('actionToUse') or {})}]
        extra = (" excluye:" + ",".join(ex) if ex else "") + (f" | {len(cnt)} reglas forzadas a Count" if cnt else "")
        modo = "SOLO MONITOREA (Count)" if ov == "COUNT" else ("bloquea, salvo las reglas forzadas a Count" if cnt else "aplica sus bloqueos")
        print(f"        {fase} {name:55} -> {modo}{extra}")
if d.get('loggingConfiguration'): print("        Logging del WAF: configurado")
else: print("        Logging del WAF: NO configurado (no hay registro de lo que bloquea)")
PY
  done < "$T/pol"
}

# ----------------------------------------------------------------- por cuenta
account() {
  p=$1; A="--profile $p"
  ACCT=$(aws sts get-caller-identity $A --query Account --output text 2>/dev/null) \
    || { echo "[$p] sin sesion: corre aws sso login"; return; }
  T=$(mktemp -d)
  printf '\n==================== %s (%s) ====================\n' "$p" "$ACCT"
  sec "AWS Network Firewall (firewall de red L3-L7 dentro de la VPC)"; netfw "$A"
  sec "WAF regional (protege ALB, API Gateway, etc.)";                  waf_scope "$A" REGIONAL
  sec "WAF CloudFront (protege la CDN)";                                waf_scope "$A" CLOUDFRONT
  sec "Shield Advanced (anti-DDoS de pago)"
  st=$(aws shield get-subscription-state $A --query SubscriptionState --output text 2>/dev/null)
  [ "$st" = "ACTIVE" ] && echo "    ACTIVO" || echo "    No contratado (solo Shield Standard, incluido gratis)"
  sec "Route 53 DNS Firewall"
  dns=$(aws route53resolver list-firewall-rule-group-associations $A --region "$REGION" --output text \
    --query 'FirewallRuleGroupAssociations[].[Name,VpcId,Status]' 2>/dev/null | grep .)
  if [ -n "$dns" ]; then printf '%s\n' "$dns" | sed 's/^/    /'; else echo "    Sin DNS Firewall"; fi
  sec "Firewall Manager";                                               fms "$A" "$ACCT"
  rm -rf "$T"
}

for p in $PROFILES; do account "$p"; done 2>>"$OUTDIR/errores-$DAY.log" | tee "$OUTDIR/firewalls-$DAY.txt"
echo; echo "Reporte: $OUTDIR/firewalls-$DAY.txt"
