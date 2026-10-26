
import hashlib
from pathlib import Path


def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""

    path = Path(file_path)
    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def get_file_size(file_path):
    """Return the file size in bytes."""

    return Path(file_path).stat().st_size


def get_file_metadata(file_path):
    """Return basic file identification information."""

    path = Path(file_path)

    return {
        "file_name": path.name,
        "file_size_bytes": get_file_size(path),
        "sha256": calculate_file_hash(path),
    }
