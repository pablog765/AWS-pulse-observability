# Command guide

> **English** · [Español](COMANDOS.md)

Quick reference to connect, troubleshoot and fix the most common errors. Every command is read-only.

## 1. SSO connection

| Command | Purpose | Expected result |
|---|---|---|
| `aws configure sso --profile prod` | Create a profile (first time only) | Prompts for the portal URL, the account and the role |
| `aws sso login --sso-session <your-session> --use-device-code` | Sign in; one login covers every account | `Successfully logged into Start URL...` |
| `export AWS_PAGER=""` | Keep output from stopping at `(END)` | No output |
| `export AWS_REGION=us-east-1` | Working region | No output |
| `export AWS_PULSE_PROFILES="prod dev network security"` | Accounts the scripts and dashboard review | No output |
| `aws sts get-caller-identity --profile prod` | Confirm account and role | JSON with `Account` and `Arn` |
| `aws configure list-profiles` | List configured profiles | Profile list |

```bash
# Check every account at once
for p in $AWS_PULSE_PROFILES; do
  printf '%-12s ' $p; aws sts get-caller-identity --profile $p --query Account --output text
done
```

To get short aliases (`prod`, `dev`…) from existing profiles, add a `[profile prod]` block in `~/.aws/config` with the same `sso_session`, `sso_account_id` and `sso_role_name` as the original profile.

## 2. A port or service is not responding

| Step | Command | If you see… | Then |
|---|---|---|---|
| 1. Test | `nc -zv -w 5 <IP> <port>` | `succeeded` | It works |
| | | `Connection refused` | The network lets traffic through and the server rejects it: check the service (step 4) |
| | | `timed out` | Something drops the traffic: Security Group, NACL or firewall (step 2) |
| 2. Rules | `./aws-architecture.sh <account>` | Port not allowed | Adjust the Security Group |
| 3. Real traffic | VPC Flow Logs (below) | Your IP does not show up | Traffic leaves through another IP or your firewall blocks it |
| 4. Server | `DAYS=1 CONSOLE=1 ./aws-changes.sh <account>` | Container stopped or created | The service restarted |

**Rule of thumb:** if the ports nmap reports as `closed` match exactly the ones open in the Security Group, AWS networking is letting traffic through and the problem is on the server.

```bash
# Flow Logs: traffic from your IP in the last 15 min (flows take ~10 min to appear)
START=$(( ($(date +%s) - 900) * 1000 ))
aws logs filter-log-events --profile prod --log-group-name <flow-logs-log-group> --start-time $START \
  --filter-pattern "\"$(curl -s ifconfig.me)\"" --query 'events[].message' --output text | tr '\t' '\n' | tail -20
```
In the response flow, 1 packet of ~40 bytes is a rejection (RST); 3 or more packets with hundreds of bytes are a real connection.

## 3. Network and routing

```bash
# VPCs per account (a different OwnerId = VPC shared through AWS RAM)
aws ec2 describe-vpcs --profile network --output table \
  --query 'Vpcs[].[OwnerId,VpcId,CidrBlock,Tags[?Key==`Name`]|[0].Value]'

# Transit Gateway routes (static, BGP and blackhole)
aws ec2 search-transit-gateway-routes --profile network --output table \
  --transit-gateway-route-table-id <tgw-rtb-id> --filters Name=state,Values=active,blackhole \
  --query 'Routes[].[DestinationCidrBlock,Type,State,TransitGatewayAttachments[0].ResourceId]'

# Contents of a prefix list used in a Security Group
aws ec2 get-managed-prefix-list-entries --profile network --prefix-list-id <pl-id> --output table
```

| AWS | Traditional networking equivalent |
|---|---|
| VPC | VRF |
| Subnet | VLAN (in a single Availability Zone) |
| Security Group | Stateful ACL on the interface |
| NACL | Stateless ACL on the SVI |
| Transit Gateway | Core router |
| TGW association / propagation | Route-target import / export |
| Site-to-Site VPN | Two VTI tunnels with BGP |
| Prefix list | object-group |
| Elastic IP | 1:1 static NAT |

## 4. WAF

```bash
# Requests per day the WAF would have blocked (rules in Count)
ACL=<web-acl-name>
aws cloudwatch get-metric-statistics --profile prod --namespace AWS/WAFV2 \
  --metric-name CountedRequests --statistics Sum --period 86400 \
  --dimensions Name=WebACL,Value=$ACL Name=Region,Value=us-east-1 Name=Rule,Value=ALL \
  --start-time $(date -u -d '7 days ago' +%FT%TZ) --end-time $(date -u +%FT%TZ) \
  --query 'sort_by(Datapoints,&Timestamp)[].[Timestamp,Sum]' --output table
```
Swap `CountedRequests` for `BlockedRequests` (what was blocked) or `AllowedRequests` (total traffic). A WAF managed by Firewall Manager keeps its rules in `PreProcessFirewallManagerRuleGroups` and `PostProcessFirewallManagerRuleGroups`, not in `Rules`.

## 5. Steampipe and Prowler

```bash
# Steampipe: EC2 inventory across all accounts (needs the aws_all aggregator in ~/.steampipe/config/aws.spc)
steampipe query "select account_id, tags->>'Name' as name, instance_state, private_ip_address, public_ip_address
  from aws_all.aws_ec2_instance order by account_id"

# Prowler: audit one account (15-30 min); HTML and CSV report in prowler-out/
prowler aws --profile prod -f us-east-1 -M csv html -o prowler-out
```
In Steampipe, each connection in the `.spc` file goes in a multi-line block. For shared VPCs and subnets, query per account (`aws_network.…`) instead of the aggregator.

## 6. Common errors

| Message | Fix |
|---|---|
| `(END)` at the end of the output | Press `q`, or `export AWS_PAGER=""` |
| `NoCredentials` / `Unable to locate credentials` | Add `--profile <profile>` or `export AWS_PROFILE=<profile>` |
| `The specified sso-session does not exist` | Check the `[sso-session …]` block name in `~/.aws/config` |
| `Token has expired` | Run `aws sso login` again |
| `gio: Operation not supported` (WSL) | Use `--use-device-code` and open the URL in the Windows browser |
| `$'\r': command not found` | `sed -i 's/\r$//' *.sh` (file copied from Windows) |
| The terminal is stuck at `quote>` | A curly quote was pasted: `Ctrl+C` and retype it |
| `CERTIFICATE_VERIFY_FAILED` | Corporate SSL inspection: install the CA or set `AWS_CA_BUNDLE` |
| Steampipe `unexpected EOF` | `steampipe service stop --force` and query per account |
| `AccessDenied` / `SubscriptionRequired` | Service not enabled or outside the read-only role: expected |
| The dashboard hangs at "installing dependencies" | Antivirus or firewall blocking PyPI: allow `pypi.org` and `files.pythonhosted.org`, or install the libraries system-wide |

## 7. Suggested routine

| Frequency | Command |
|---|---|
| Daily or during an incident | Dashboard, or `./aws-health-check.sh` |
| Weekly | `DAYS=7 ./aws-changes.sh` |
| Monthly | `./aws-firewalls.sh` and `./aws-architecture.sh` |
| Quarterly | Prowler on every account |
