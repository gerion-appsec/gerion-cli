from datetime import datetime

from gerion_cli.tools.parser import generate_finding_template, generate_unique_id, redact_text


def test_generate_unique_id():
    """Test consistent ID generation."""
    test_inputs = ["file.txt", "secret_value", "rule-123"]

    id1 = generate_unique_id(test_inputs)
    id2 = generate_unique_id(test_inputs)

    assert id1 == id2
    assert len(id1) == 12

    # Verify different inputs yield different IDs
    id3 = generate_unique_id(test_inputs + ["diff"])
    assert id1 != id3

def test_generate_finding_template(mock_metadata):
    """Test template generation with all required fields."""
    template = generate_finding_template(mock_metadata)

    assert template["repository_name"] == "test-repo"
    assert template["branch_name"] == "test-branch"
    assert template["active"] is True
    assert template["mitigated"] is False
    assert template["false_positive"] is False

    # Check creation date format (isoformat)
    creation_date = datetime.fromisoformat(template["creation_date"])
    assert isinstance(creation_date, datetime)

def test_redact_text():
    """Test text redaction logic."""
    # Short values are fully masked
    assert redact_text("abc") == "[REDACTED]"
    assert redact_text("abcdefg") == "[REDACTED]"

    # Test long text
    long_text = "start_of_secret_value_end"
    redacted = redact_text(long_text)

    assert "sta" in redacted
    assert "end" in redacted
    assert "[REDACTED]" in redacted
    assert len(redacted) < len(long_text) + 12 # Roughly check length

def test_redact_text_none():
    """Test redaction handling of None/empty."""
    assert redact_text(None) is None
    assert redact_text("") == ""


def test_redact_text_caps_revealed_part():
    """A 40-char token used to reveal 12 characters (30%) in the uploaded mitigation."""
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    redacted = redact_text(token)

    assert redacted == "ghp_...[REDACTED]...Q7r8"
    visible = len(redacted) - len("...[REDACTED]...")
    assert visible <= 8
    for length in range(1, 200):
        value = "x" * length
        shown = redact_text(value).replace("...[REDACTED]...", "").replace("[REDACTED]", "")
        assert len(shown) <= min(8, length * 0.25)
