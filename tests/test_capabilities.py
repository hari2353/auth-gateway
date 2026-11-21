from auth_gateway.capabilities import (
    MissingScope,
    has_scope,
    parse_scopes,
    require_all,
    require_any,
    require_scope,
)


def test_parse_scopes_from_string_and_iterable():
    assert parse_scopes("read:users write:users") == {"read:users", "write:users"}
    assert parse_scopes("read:users,write:users") == {"read:users", "write:users"}
    assert parse_scopes(["a", "b"]) == {"a", "b"}
    assert parse_scopes(None) == frozenset()


def test_exact_and_wildcard_matching():
    assert has_scope({"read:users"}, "read:users")
    assert has_scope("admin:*", "admin:keys")
    assert has_scope({"admin:*"}, "admin:users")
    assert has_scope({"admin*"}, "administrator")
    assert not has_scope({"read:users"}, "write:users")
    assert has_scope({"*"}, "anything")


def test_require_scope_raises_missing():
    try:
        require_scope({"read:users"}, "admin:keys")
    except MissingScope as exc:
        assert "admin:keys" in str(exc)
    else:
        raise AssertionError("missing scope accepted")


def test_require_all_and_any():
    require_all({"a", "b", "c"}, ["a", "b"])
    try:
        require_all({"a"}, ["a", "b"])
    except MissingScope:
        pass
    else:
        raise AssertionError("require_all accepted missing scope")
    require_any({"b"}, ["a", "b"])
    try:
        require_any({"c"}, ["a", "b"])
    except MissingScope:
        pass
    else:
        raise AssertionError("require_any accepted missing scope")
