"""F-07: the portal refuses to start on a credential its own source publishes.

The two defaults are not placeholders to be replaced later; they are signing
keys anyone who can read this file already holds. Every test below goes red if
the guard is removed. The first one also fixes the order: configuration is
resolved before the engine exists, so a misconfigured deployment cannot leave a
database behind on its way out.
"""
from __future__ import annotations

import pytest

from autorate_portal import db
from autorate_portal.app import (DEFAULT_SALT, DEFAULT_SECRET, ConfigurationError,
                                 create_app)

SALT_ENV = "AUTHORATE_TOKEN_SALT"
SECRET_ENV = "AUTHORATE_SECRET_KEY"


def _clear(monkeypatch):
    monkeypatch.delenv(SALT_ENV, raising=False)
    monkeypatch.delenv(SECRET_ENV, raising=False)


def test_construction_is_refused_before_any_engine_when_the_environment_is_empty(
        monkeypatch, tmp_path):
    _clear(monkeypatch)

    def never():
        raise AssertionError("the engine was created before the credential check")

    monkeypatch.setattr(db, "make_engine", never)
    with pytest.raises(ConfigurationError) as caught:
        create_app(store_dir=tmp_path)
    message = str(caught.value)
    assert SALT_ENV in message
    assert SECRET_ENV in message


def test_the_published_default_is_refused_even_when_the_environment_sets_it(
        monkeypatch, tmp_path):
    monkeypatch.setenv(SALT_ENV, DEFAULT_SALT)
    monkeypatch.setenv(SECRET_ENV, DEFAULT_SECRET)
    with pytest.raises(ConfigurationError) as caught:
        create_app(engine=db.make_engine("sqlite://"), store_dir=tmp_path)
    message = str(caught.value)
    assert "packaged default" in message
    assert DEFAULT_SALT not in message
    assert DEFAULT_SECRET not in message


def test_a_blank_value_is_not_a_credential(monkeypatch, tmp_path):
    monkeypatch.setenv(SALT_ENV, "   ")
    monkeypatch.setenv(SECRET_ENV, "")
    with pytest.raises(ConfigurationError) as caught:
        create_app(engine=db.make_engine("sqlite://"), store_dir=tmp_path)
    message = str(caught.value)
    assert SALT_ENV in message
    assert SECRET_ENV in message


def test_explicit_values_win_over_a_published_environment_default(monkeypatch, tmp_path):
    monkeypatch.setenv(SALT_ENV, DEFAULT_SALT)
    monkeypatch.setenv(SECRET_ENV, DEFAULT_SECRET)
    app = create_app(engine=db.make_engine("sqlite://"), store_dir=tmp_path,
                     salt="explicit-salt-value", secret_key="explicit-secret-value")
    assert app.state.salt == "explicit-salt-value"
    assert app.state.secret_key == "explicit-secret-value"


def test_non_default_environment_values_construct_the_app(monkeypatch, tmp_path):
    monkeypatch.setenv(SALT_ENV, "a-salt-that-is-not-in-the-source")
    monkeypatch.setenv(SECRET_ENV, "a-secret-that-is-not-in-the-source")
    app = create_app(engine=db.make_engine("sqlite://"), store_dir=tmp_path)
    assert app.state.salt == "a-salt-that-is-not-in-the-source"
    assert app.state.secret_key == "a-secret-that-is-not-in-the-source"


def test_the_refusal_names_what_is_missing_and_quotes_no_value(monkeypatch, tmp_path):
    _clear(monkeypatch)
    with pytest.raises(ConfigurationError) as caught:
        create_app(engine=db.make_engine("sqlite://"), store_dir=tmp_path)
    message = str(caught.value)
    assert message.count(": set ") == 2
    assert DEFAULT_SALT not in message
    assert DEFAULT_SECRET not in message
