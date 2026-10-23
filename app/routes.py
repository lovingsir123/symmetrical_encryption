"""HTTP routes for the legal-aid vault (upload/download arrive in later tasks)."""

from flask import Blueprint, jsonify

bp = Blueprint("vault", __name__)


@bp.get("/health")
def health():
    return jsonify({"status": "ok"}), 200
