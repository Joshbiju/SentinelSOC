from pathlib import Path
import os
BASE_DIR=Path(__file__).resolve().parent.parent
DB_PATH=os.getenv('SOC_DB',str(BASE_DIR/'data'/'soc.db'))
RULES_PATH=os.getenv('SOC_RULES',str(BASE_DIR/'rules'/'rules.json'))
AUTH_LOGS=['/var/log/auth.log','/var/log/secure','/var/log/syslog','/var/log/messages']
BRUTE_FORCE_THRESHOLD=int(os.getenv('SOC_BRUTE_FORCE_THRESHOLD','5'))
BRUTE_FORCE_WINDOW=int(os.getenv('SOC_BRUTE_FORCE_WINDOW','60'))
ALERT_COOLDOWN=int(os.getenv('SOC_ALERT_COOLDOWN','300'))
PORT_SCAN_THRESHOLD=int(os.getenv('SOC_PORT_SCAN_THRESHOLD','8'))
PORT_SCAN_WINDOW=int(os.getenv('SOC_PORT_SCAN_WINDOW','60'))
