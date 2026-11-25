# Guía de comandos

> [English](COMMANDS.md) · **Español**

Referencia rápida para conectarse, diagnosticar y resolver los errores más comunes. Todos los comandos son de solo lectura.

## 1. Conexión por SSO

| Comando | Para qué | Resultado esperado |
|---|---|---|
| `aws configure sso --profile prod` | Crear un perfil (solo la primera vez) | Pide la URL del portal, la cuenta y el rol |
| `aws sso login --sso-session <tu-sesion> --use-device-code` | Iniciar sesión; un login sirve para todas las cuentas | `Successfully logged into Start URL...` |
| `export AWS_PAGER=""` | Que la salida no se quede en `(END)` | Sin salida |
| `export AWS_REGION=us-east-1` | Región de trabajo | Sin salida |
| `export AWS_PULSE_PROFILES="prod dev network security"` | Cuentas que revisan los scripts y el dashboard | Sin salida |
| `aws sts get-caller-identity --profile prod` | Confirmar cuenta y rol | JSON con `Account` y `Arn` |
| `aws configure list-profiles` | Ver los perfiles configurados | Lista de perfiles |

```bash
# Verificar todas las cuentas de una vez
for p in $AWS_PULSE_PROFILES; do
  printf '%-12s ' $p; aws sts get-caller-identity --profile $p --query Account --output text
done
```

Para tener alias cortos (`prod`, `dev`…) a partir de perfiles existentes, agrega en `~/.aws/config` un bloque `[profile prod]` con el mismo `sso_session`, `sso_account_id` y `sso_role_name` del perfil original.

## 2. Un puerto o servicio no responde

| Paso | Comando | Si ves… | Entonces |
|---|---|---|---|
| 1. Probar | `nc -zv -w 5 <IP> <puerto>` | `succeeded` | Funciona |
| | | `Connection refused` | La red deja pasar y el servidor rechaza: revisa el servicio (paso 4) |
| | | `timed out` | Algo descarta el tráfico: Security Group, NACL o firewall (paso 2) |
| 2. Reglas | `./aws-architecture.sh <cuenta>` | Puerto no permitido | Ajustar el Security Group |
| 3. Tráfico real | VPC Flow Logs (abajo) | Tu IP no aparece | El tráfico sale por otra IP o lo bloquea tu firewall |
| 4. Servidor | `DAYS=1 CONSOLE=1 ./aws-changes.sh <cuenta>` | Contenedor detenido o creado | El servicio se reinició |

**Regla práctica:** si los puertos `closed` de nmap coinciden exactamente con los abiertos en el Security Group, la red de AWS deja pasar el tráfico y el problema está en el servidor.

```bash
# Flow Logs: tráfico de tu IP en los últimos 15 min (los flujos tardan ~10 min en aparecer)
START=$(( ($(date +%s) - 900) * 1000 ))
aws logs filter-log-events --profile prod --log-group-name <log-group-de-flow-logs> --start-time $START \
  --filter-pattern "\"$(curl -s ifconfig.me)\"" --query 'events[].message' --output text | tr '\t' '\n' | tail -20
```
En el flujo de respuesta, 1 paquete de ~40 bytes es un rechazo (RST); 3 o más paquetes con cientos de bytes son una conexión real.

## 3. Red y ruteo

```bash
# VPC por cuenta (OwnerId distinto = VPC compartida por AWS RAM)
aws ec2 describe-vpcs --profile network --output table \
  --query 'Vpcs[].[OwnerId,VpcId,CidrBlock,Tags[?Key==`Name`]|[0].Value]'

# Rutas del Transit Gateway (estáticas, BGP y blackhole)
aws ec2 search-transit-gateway-routes --profile network --output table \
  --transit-gateway-route-table-id <tgw-rtb-id> --filters Name=state,Values=active,blackhole \
  --query 'Routes[].[DestinationCidrBlock,Type,State,TransitGatewayAttachments[0].ResourceId]'

# Contenido de un prefix list usado en un Security Group
aws ec2 get-managed-prefix-list-entries --profile network --prefix-list-id <pl-id> --output table
```

| AWS | Equivalente en redes tradicionales |
|---|---|
| VPC | VRF |
| Subred | VLAN (en una sola zona de disponibilidad) |
| Security Group | ACL con estado en la interfaz |
| NACL | ACL sin estado en la SVI |
| Transit Gateway | Router núcleo |
| Asociación / propagación del TGW | Import / export de route-targets |
| VPN Site-to-Site | Dos túneles VTI con BGP |
| Prefix list | object-group |
| Elastic IP | NAT estático 1:1 |

## 4. WAF

```bash
# Solicitudes por día que el WAF habría bloqueado (reglas en Count)
ACL=<nombre-de-la-web-acl>
aws cloudwatch get-metric-statistics --profile prod --namespace AWS/WAFV2 \
  --metric-name CountedRequests --statistics Sum --period 86400 \
  --dimensions Name=WebACL,Value=$ACL Name=Region,Value=us-east-1 Name=Rule,Value=ALL \
  --start-time $(date -u -d '7 days ago' +%FT%TZ) --end-time $(date -u +%FT%TZ) \
  --query 'sort_by(Datapoints,&Timestamp)[].[Timestamp,Sum]' --output table
```
Cambia `CountedRequests` por `BlockedRequests` (lo bloqueado) o `AllowedRequests` (el tráfico total). Un WAF administrado por Firewall Manager guarda sus reglas en `PreProcessFirewallManagerRuleGroups` y `PostProcessFirewallManagerRuleGroups`, no en `Rules`.

## 5. Steampipe y Prowler

```bash
# Steampipe: inventario EC2 de todas las cuentas (requiere el agregador aws_all en ~/.steampipe/config/aws.spc)
steampipe query "select account_id, tags->>'Name' as nombre, instance_state, private_ip_address, public_ip_address
  from aws_all.aws_ec2_instance order by account_id"

# Prowler: auditoría de una cuenta (15-30 min); reporte HTML y CSV en prowler-out/
prowler aws --profile prod -f us-east-1 -M csv html -o prowler-out
```
En Steampipe, cada conexión del archivo `.spc` va en un bloque de varias líneas. Para VPC y subredes compartidas consulta por cuenta (`aws_network.…`) en lugar del agregador.

## 6. Errores frecuentes

| Mensaje | Solución |
|---|---|
| `(END)` al final de la salida | Tecla `q`, o `export AWS_PAGER=""` |
| `NoCredentials` / `Unable to locate credentials` | Agregar `--profile <perfil>` o `export AWS_PROFILE=<perfil>` |
| `The specified sso-session does not exist` | Revisar el nombre del bloque `[sso-session …]` en `~/.aws/config` |
| `Token has expired` | Repetir `aws sso login` |
| `gio: Operation not supported` (WSL) | Usar `--use-device-code` y abrir la URL en el navegador de Windows |
| `$'\r': command not found` | `sed -i 's/\r$//' *.sh` (archivo copiado desde Windows) |
| La terminal queda en `quote>` | Se copió una comilla curva: `Ctrl+C` y reescribir |
| `CERTIFICATE_VERIFY_FAILED` | Inspección SSL corporativa: instalar la CA o usar `AWS_CA_BUNDLE` |
| Steampipe `unexpected EOF` | `steampipe service stop --force` y consultar por cuenta |
| `AccessDenied` / `SubscriptionRequired` | Servicio no habilitado o fuera del rol de solo lectura: normal |
| El dashboard se queda "instalando dependencias" | Antivirus o firewall bloqueando PyPI: permitir `pypi.org` y `files.pythonhosted.org`, o instalar las librerías en el sistema |

## 7. Rutina sugerida

| Frecuencia | Comando |
|---|---|
| Diaria o ante un incidente | Dashboard, o `./aws-health-check.sh` |
| Semanal | `DAYS=7 ./aws-changes.sh` |
| Mensual | `./aws-firewalls.sh` y `./aws-architecture.sh` |
| Trimestral | Prowler en todas las cuentas |
