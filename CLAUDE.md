# AWS Pulse: instrucciones para Claude Code

Dashboard local (Streamlit) y scripts Bash de observabilidad AWS multi-cuenta, **solo lectura**.

## Reglas
- Nunca ejecutes comandos AWS que creen, modifiquen o borren recursos. Solo `describe*`, `list*`, `get*`, `lookup-events`, `get-metric-data`.
- Nunca subas a git datos reales: `reportes/`, `*.tsv` fuera de `dashboard/demo/`, IDs de cuenta reales, IPs, nombres de la organización. El repo es público.
- Datos de ejemplo: solo en `dashboard/demo/` con cuentas 111111111111… e IPs RFC 5737.
- Responde en español; el código y los commits pueden ir en español.
- Horas siempre en `AWS_PULSE_TZ` (America/Guayaquil por defecto) vía `awsdata.to_local()`.

## Estructura
- `dashboard/app.py`: páginas de Streamlit. `dashboard/awsdata.py`: llamadas a AWS CLI (cache 5 min). `dashboard/finops.py`: precios y cálculo de costos.
- `scripts/*.sh`: diagnósticos por terminal. `docs/`: guías.

## Probar un cambio
- Demo sin AWS: `cd dashboard && ./iniciar_dashboard.sh --demo`
- El dashboard recarga solo al guardar (`runOnSave = true`): basta refrescar el navegador.
- Prueba rápida sin navegador: `python3 -c "from streamlit.testing.v1 import AppTest; at=AppTest.from_file('dashboard/app.py'); at.run(); print(at.exception)"`

## Al terminar
- Muestra un resumen corto del cambio y pregunta antes de hacer commit y push.
