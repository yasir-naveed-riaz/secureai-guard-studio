def calculate_risk_score(flags):
    weights = {
        "prompt_injection": 35,
        "jailbreak_attempt": 35,
        "system_prompt_extraction": 30,
        "credential_extraction": 35,
        "sensitive_data": 25,
        "financial_fraud": 35,
        "digital_asset_risk": 30,
        "policy_bypass": 35,
        "unsafe_output": 30,
        "data_leakage": 30,
    }

    score = sum(weights.get(flag, 10) for flag in flags)
    return min(score, 100)


def get_risk_level(score):
    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def get_recommendations(flags):
    recommendations = []

    if "prompt_injection" in flags or "jailbreak_attempt" in flags:
        recommendations.append("Apply prompt injection filtering and isolate system instructions from user input.")

    if "system_prompt_extraction" in flags:
        recommendations.append("Never expose system prompts, hidden instructions, tools, or internal policies.")

    if "credential_extraction" in flags or "sensitive_data" in flags:
        recommendations.append("Mask secrets, tokens, API keys, credentials, emails, and payment data before model processing.")

    if "financial_fraud" in flags:
        recommendations.append("Block requests related to payment bypass, fraud manipulation, AML/KYC evasion, or unauthorized transfers.")

    if "digital_asset_risk" in flags:
        recommendations.append("Protect wallet keys, seed phrases, signing workflows, and smart contract operations.")

    if "policy_bypass" in flags:
        recommendations.append("Enforce Zero Trust policies and log all bypass attempts for investigation.")

    if "unsafe_output" in flags:
        recommendations.append("Scan AI-generated output before displaying it to users or downstream systems.")

    if not recommendations:
        recommendations.append("No major risk detected. Continue monitoring and logging AI interactions.")

    return recommendations