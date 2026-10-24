"""Application configuration loaded from environment variables via python-dotenv."""

import os
import warnings

from dotenv import load_dotenv

load_dotenv()

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MiB

DATABASE = os.path.join(_BASE_DIR, "instance", "vault.db")
UPLOAD_FOLDER = os.path.join(_BASE_DIR, "instance", "uploads")

SECRET_KEY = os.environ.get("SECRET_KEY")
MASTER_KEY = os.environ.get("MASTER_KEY")

if not SECRET_KEY or not MASTER_KEY:
    warnings.warn(
        "SECRET_KEY and/or MASTER_KEY not set in environment "
        "(development only; set both for production).",
        stacklevel=1,
    )

ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "jpg", "jpeg", "png", "mp4", "mov", "avi", "mkv",
}
