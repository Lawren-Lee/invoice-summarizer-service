from pathlib import Path

from app import load_api_key


def test_loader_reads_the_local_file():
    assert load_api_key()


def test_example_file_is_a_placeholder():
    example = Path("config/credentials.example.txt").read_text(encoding="utf-8")
    assert "REPLACE_WITH_YOUR_KEY" in example
