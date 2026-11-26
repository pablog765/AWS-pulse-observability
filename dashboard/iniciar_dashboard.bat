@echo off
title AWS Pulse
REM ------------------------------------------------------------------
REM  Levanta WSL, inicia el Dashboard AWS y abre el navegador.
REM  Si tu carpeta es otra, cambia la ruta de la siguiente linea.
REM ------------------------------------------------------------------
set CARPETA=~/proyectos/aws/aws-pulse/dashboard

echo Verificando la carpeta %CARPETA% en WSL...
wsl.exe -- bash -lc "test -x %CARPETA%/iniciar_dashboard.sh"
if errorlevel 1 (
  echo.
  echo ERROR: no se encontro %CARPETA%/iniciar_dashboard.sh en WSL,
  echo o no tiene permiso de ejecucion. En WSL ejecuta:
  echo    ls %CARPETA%
  echo    chmod +x %CARPETA%/iniciar_dashboard.sh
  pause
  exit /b 1
)

echo Iniciando el dashboard en una ventana aparte (no la cierres)...
start "AWS Pulse - no cerrar" wsl.exe -- bash -lc "cd %CARPETA% && ./iniciar_dashboard.sh; echo; echo 'El dashboard se detuvo. Revisa el mensaje de arriba.'; read -p 'Presiona Enter para cerrar...'"

echo Esperando a que responda (la primera vez puede tardar unos minutos)...
powershell -NoProfile -Command "for($i=0;$i -lt 150;$i++){try{Invoke-WebRequest -UseBasicParsing http://localhost:8501 -TimeoutSec 2 | Out-Null; exit 0}catch{Start-Sleep 2}}; exit 1"
if errorlevel 1 (
  echo.
  echo No respondio en 5 minutos. Revisa el error en la ventana "AWS Pulse - no cerrar".
  pause
  exit /b 1
)
start "" http://localhost:8501
