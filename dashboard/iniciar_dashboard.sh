#!/usr/bin/env bash
# Inicia AWS Pulse (Mac, Linux o WSL).   Modo demo sin AWS:  ./iniciar_dashboard.sh --demo
# 1) Si streamlit, pandas y plotly ya estan instalados en el sistema, los usa directamente.
# 2) Si no, crea un entorno aislado (.venv) e instala mostrando el progreso.
cd "$(dirname "$0")" || exit 1

if [ "$1" = "--demo" ]; then
  echo "MODO DEMO: datos inventados, no se conecta a AWS."
  export PATH="$PWD/demo:$PATH" AWS_CONFIG_FILE="$PWD/demo/aws_config" AWS_PULSE_PROFILES="prod dev network security" AWS_PULSE_ORG="${AWS_PULSE_ORG:-Demo}" AWS_PULSE_COST_DIR="$PWD/demo/costos"
  chmod +x demo/aws 2>/dev/null
fi
command -v aws >/dev/null 2>&1 || { echo "ERROR: AWS CLI no esta instalado o no esta en el PATH."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: falta python3."; exit 1; }

if python3 -c "import streamlit, pandas, plotly" 2>/dev/null; then
  PY=python3
  echo "Usando las librerias ya instaladas en el sistema."
elif .venv/bin/python -c "import streamlit, pandas, plotly" 2>/dev/null; then
  PY=.venv/bin/python
  echo "Usando el entorno .venv."
else
  echo "Instalando dependencias en .venv (se muestra el progreso)..."
  rm -rf .venv
  python3 -m venv .venv || { echo "ERROR: falta el modulo venv. En Ubuntu/WSL: sudo apt install -y python3-venv"; exit 1; }
  if ! .venv/bin/pip install --timeout 20 --retries 2 -r requirements.txt; then
    echo
    echo "ERROR: no se pudieron descargar las dependencias."
    echo " - Si es un error de certificado: .venv/bin/pip config set global.cert /etc/ssl/certs/ca-certificates.crt"
    echo " - Si es un bloqueo de red: permitir pypi.org y files.pythonhosted.org en el firewall o el antivirus."
    exit 1
  fi
  PY=.venv/bin/python
fi

echo "Dashboard en http://localhost:8501   (Ctrl+C para detenerlo)"
if [ "$(uname)" = "Darwin" ]; then (sleep 5; open http://localhost:8501) & fi
exec "$PY" -m streamlit run app.py
