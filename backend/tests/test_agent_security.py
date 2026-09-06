from core.security import generate_agent_token, hash_agent_token, verify_agent_token


def test_agent_token_is_high_entropy_and_not_stored_raw():
    token = generate_agent_token()
    digest = hash_agent_token(token)

    assert len(token) >= 40
    assert len(digest) == 64
    assert token != digest
    assert verify_agent_token(token, digest) is True


def test_agent_token_verification_rejects_wrong_or_missing_values():
    token = generate_agent_token()
    digest = hash_agent_token(token)

    assert verify_agent_token("wrong-token", digest) is False
    assert verify_agent_token(token, None) is False
    assert verify_agent_token("", digest) is False
