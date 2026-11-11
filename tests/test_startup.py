import subprocess
import sys

# Heavy modules only needed by some code paths (API calls, PDF reports). Loading them
# at startup made every invocation, even `gerion --version`, pay for them.
LAZY_MODULES = ("httpx", "fpdf", "PIL", "fontTools")


def test_cli_startup_does_not_import_heavy_modules():
    code = (
        "import sys, gerion_cli.main; "
        f"print(','.join(m for m in {LAZY_MODULES!r} if m in sys.modules))"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == ""
