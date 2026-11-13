import importlib.metadata

try:
    __version__ = importlib.metadata.version("gerion-cli")
except importlib.metadata.PackageNotFoundError:
    __version__ = "1.1.2"

# Client ID is static and based on CLI version
# Format: gerion-cli-{version}
CLIENT_ID = f"gerion-cli-{__version__}"

