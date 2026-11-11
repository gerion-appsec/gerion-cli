from gerion_cli.core.types import SecretString


def test_secret_is_masked_in_str_and_repr():
    secret = SecretString("super-secret")
    assert "super-secret" not in str(secret)
    assert "super-secret" not in repr(secret)


def test_get_secret_value_returns_raw_value():
    assert SecretString("super-secret").get_secret_value() == "super-secret"


def test_bool_reflects_presence_of_value():
    assert bool(SecretString("x"))
    assert not bool(SecretString(""))


def test_none_is_handled():
    secret = SecretString(None)
    assert not secret
    assert secret.get_secret_value() is None or secret.get_secret_value() == ""
