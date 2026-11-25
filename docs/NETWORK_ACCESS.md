# Abrir AWS Pulse desde otras máquinas (WSL 2 en Windows)

> English summary: set `AWS_PULSE_PASSWORD`, enable WSL mirrored networking, open TCP 8501 in Windows Firewall (and the Hyper-V firewall), then browse to `http://<Windows-IP>:8501`.

## Por qué no abre desde otra PC

WSL 2 corre en una red virtual interna (172.x). La IP que ves dentro de WSL **no es alcanzable** desde la LAN, y el firewall de Windows (y ESET, si lo gestiona TI) bloquea el puerto 8501 por defecto.

## 1. Contraseña (obligatoria para accesos remotos)

Sin ella el dashboard rechaza cualquier conexión que no venga del propio equipo.

```bash
# en WSL, antes de lanzar el dashboard (o en ~/.bashrc)
export AWS_PULSE_PASSWORD='una-frase-larga-y-unica'
./iniciar_dashboard.sh
```

Quien entra por la red solo consulta: la página **Sesión** (login SSO) se oculta y el inicio de sesión se hace en tu equipo.

## 2. Red de WSL en modo espejo (Windows 11 22H2 o superior)

Crea o edita `C:\Users\<tu_usuario>\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
```

Luego en PowerShell: `wsl --shutdown` y vuelve a abrir WSL. Ahora WSL usa la misma IP que Windows.

## 3. Abrir el puerto 8501 (PowerShell como administrador)

```powershell
New-NetFirewallRule -DisplayName "AWS Pulse 8501" -Direction Inbound -Protocol TCP -LocalPort 8501 -Action Allow -Profile Domain,Private
New-NetFirewallHyperVRule -Name AWSPulse -DisplayName "AWS Pulse (WSL)" -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts 8501
```

Si el equipo tiene **ESET** administrado por TI, pide una regla de entrada TCP 8501 limitada a la subred de la oficina.

## 4. Compartir la URL correcta

```powershell
ipconfig   # usa la IPv4 del adaptador Ethernet/Wi-Fi de Windows, NO la 172.x de WSL
```

URL para los demás: `http://<IP-de-Windows>:8501`

## Alternativa sin modo espejo (Windows 10)

```powershell
$wsl = (wsl hostname -I).Split(" ")[0]
netsh interface portproxy add v4tov4 listenport=8501 listenaddress=0.0.0.0 connectport=8501 connectaddress=$wsl
```

La IP de WSL cambia al reiniciar: repite el comando después de cada reinicio.

## Buenas prácticas

- Solo red interna: nunca publiques el puerto a Internet.
- El dashboard usa **tu** sesión SSO de solo lectura: lo que ven los demás es lo que tú puedes ver. Ciérralo cuando no se use.
- Para gerencia de forma permanente, lo ideal es alojarlo en un servidor interno o en una EC2 con rol IAM de solo lectura y detrás de un ALB con autenticación (Cognito / IAM Identity Center).
