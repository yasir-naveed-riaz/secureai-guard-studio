import re
from .risk_engine import calculate_risk_score, get_risk_level, get_recommendations
from .policies import DEFAULT_POLICY, decide_action
from .audit_logger import AuditLogger


class SecureAIGuard:
    def __init__(self, policy=None, enable_logging=True):
        self.policy = policy or DEFAULT_POLICY
        self.enable_logging = enable_logging
        self.logger = AuditLogger()

    def scan_prompt(self, text):
        return self._scan(text, scan_type="prompt")

    def scan_output(self, text):
        return self._scan(text, scan_type="output")

    def _scan(self, text, scan_type):
        flags = []

        checks = {
            "prompt_injection": self._detect_prompt_injection,
            "jailbreak_attempt": self._detect_jailbreak,
            "system_prompt_extraction": self._detect_system_prompt_extraction,
            "credential_extraction": self._detect_credential_extraction,
            "sensitive_data": self._detect_sensitive_data,
            "financial_fraud": self._detect_financial_fraud,
            "digital_asset_risk": self._detect_digital_asset_risk,
            "policy_bypass": self._detect_policy_bypass,
            "data_leakage": self._detect_data_leakage,
        }

        for flag, detector in checks.items():
            if detector(text):
                flags.append(flag)

        if scan_type == "output" and self._detect_unsafe_output(text):
            flags.append("unsafe_output")

        risk_score = calculate_risk_score(flags)
        risk_level = get_risk_level(risk_score)
        action = decide_action(risk_score, self.policy)
        masked_text = self._mask_sensitive_data(text) if self.policy.get("mask_sensitive_data") else text

        result = {
            "scan_type": scan_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "action": action,
            "flags": flags,
            "recommendations": get_recommendations(flags),
            "masked_text": masked_text,
        }

        if self.enable_logging and self.policy.get("log_events"):
            self.logger.log(result)

        return result

    def _match_any(self, patterns, text):
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

    def _detect_prompt_injection(self, text):
        return self._match_any([
            r"ignore previous instructions",
            r"ignore all instructions",
            r"forget your instructions",
            r"override your instructions",
            r"disregard the above",
            r"system prompt",
            r"developer message",
        ], text)

    def _detect_jailbreak(self, text):
        return self._match_any([
            r"jailbreak",
            r"developer mode",
            r"dan mode",
            r"act as unrestricted",
            r"no ethical limits",
            r"bypass safety",
            r"ignore safety",
        ], text)

    def _detect_system_prompt_extraction(self, text):
        return self._match_any([
            r"reveal system prompt",
            r"show hidden instructions",
            r"print your instructions",
            r"what are your system rules",
            r"display internal policy",
        ], text)

    def _detect_credential_extraction(self, text):
        return self._match_any([
            r"reveal.*password",
            r"show.*api key",
            r"give me.*token",
            r"admin credentials",
            r"secret key",
            r"private token",
            r"database password",
        ], text)

    def _detect_sensitive_data(self, text):
        return self._match_any([
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            r"\b(?:\+?\d{1,3})?[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
            r"\b(?:\d[ -]*?){13,16}\b",
            r"api[_-]?key\s*[:=]",
            r"password\s*[:=]",
            r"token\s*[:=]",
            r"secret\s*[:=]",
        ], text)

    def _detect_financial_fraud(self, text):
        return self._match_any([
            r"bypass payment",
            r"fake transaction",
            r"manipulate transaction",
            r"disable fraud detection",
            r"avoid aml",
            r"bypass kyc",
            r"unauthorized transfer",
            r"payment exploit",
        ], text)

    def _detect_digital_asset_risk(self, text):
        return self._match_any([
            r"private key",
            r"seed phrase",
            r"wallet exploit",
            r"smart contract exploit",
            r"drain wallet",
            r"crypto theft",
            r"sign transaction without approval",
        ], text)

    def _detect_policy_bypass(self, text):
        return self._match_any([
            r"do not follow policy",
            r"ignore compliance",
            r"skip security checks",
            r"disable logging",
            r"hide this activity",
            r"avoid audit",
        ], text)

    def _detect_data_leakage(self, text):
        return self._match_any([
            r"export customer records",
            r"dump database",
            r"leak user data",
            r"download all accounts",
            r"extract confidential",
        ], text)

    def _detect_unsafe_output(self, text):
        return self._match_any([
            r"here is how to bypass",
            r"use stolen credentials",
            r"disable monitoring",
            r"evade detection",
            r"avoid logging",
        ], text)

    def _mask_sensitive_data(self, text):
        text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL_MASKED]", text)
        text = re.sub(r"\b(?:\d[ -]*?){13,16}\b", "[CARD_NUMBER_MASKED]", text)
        text = re.sub(r"(api[_-]?key\s*[:=]\s*)\S+", r"\1[API_KEY_MASKED]", text, flags=re.IGNORECASE)
        text = re.sub(r"(password\s*[:=]\s*)\S+", r"\1[PASSWORD_MASKED]", text, flags=re.IGNORECASE)
        text = re.sub(r"(token\s*[:=]\s*)\S+", r"\1[TOKEN_MASKED]", text, flags=re.IGNORECASE)
        text = re.sub(r"(secret\s*[:=]\s*)\S+", r"\1[SECRET_MASKED]", text, flags=re.IGNORECASE)
        return text