import json
from datetime import datetime
from pathlib import Path


class AuditLogger:
    def __init__(self, log_file="secureai_guard_audit_log.jsonl"):
        self.log_file = Path(log_file)

    def log(self, event):
        event["timestamp"] = datetime.utcnow().isoformat() + "Z"
        with self.log_file.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")