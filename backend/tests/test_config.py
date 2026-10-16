"""Tests for automatic API-key creation/loading."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config  # noqa: E402


def test_creates_key_file_on_first_run(tmp_path, monkeypatch):
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    env_file = tmp_path / ".env"
    key = config.load_api_key(env_file)
    assert len(key) >= 32
    assert env_file.read_text().strip() == f"{config.API_KEY_ENV}={key}"


def test_reuses_existing_key_on_next_run(tmp_path, monkeypatch):
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    env_file = tmp_path / ".env"
    first = config.load_api_key(env_file)
    assert config.load_api_key(env_file) == first


def test_file_wins_over_environment_variable(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(f"{config.API_KEY_ENV}=from-file\n")
    monkeypatch.setenv(config.API_KEY_ENV, "from-env")
    assert config.load_api_key(env_file) == "from-file"


def test_environment_variable_seeds_a_missing_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    monkeypatch.setenv(config.API_KEY_ENV, "from-env")
    assert config.load_api_key(env_file) == "from-env"
    assert "from-env" in env_file.read_text()


def test_strips_quotes_and_whitespace(tmp_path, monkeypatch):
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(f'{config.API_KEY_ENV}= "abc123" \n')
    assert config.load_api_key(env_file) == "abc123"


def test_key_is_not_logged(tmp_path, monkeypatch, caplog):
    monkeypatch.delenv(config.API_KEY_ENV, raising=False)
    with caplog.at_level("WARNING", logger="malicious_email_scorer"):
        key = config.load_api_key(tmp_path / ".env")
    assert key not in caplog.text
