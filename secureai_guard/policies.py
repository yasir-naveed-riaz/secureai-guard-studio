DEFAULT_POLICY = {
    "block_threshold": 80,
    "warn_threshold": 55,
    "mask_sensitive_data": True,
    "log_events": True,
}


def decide_action(score, policy=None):
    policy = policy or DEFAULT_POLICY

    if score >= policy["block_threshold"]:
        return "block"
    if score >= policy["warn_threshold"]:
        return "warn"
    return "allow"