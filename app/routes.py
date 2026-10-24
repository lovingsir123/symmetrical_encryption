"""HTTP routes: auth views, dashboard, per-user upload/download/delete."""

import io

from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, send_file, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired

from db import get_db

from . import storage
from .auth import register_user, verify_or_lock
from .models import list_files_for_owner

bp = Blueprint("vault", __name__)

# Fixed client-facing strings (generic by design: see auth.verify_or_lock for
# the lockout ruling, and the storage docstring for metadata indistinguishability).
GENERIC_LOGIN_MSG = "Invalid username or password."
GENERIC_REGISTER_MSG = "Registration failed. Check the details and try again."
CREATED_MSG = "Account created. Please log in."
NO_FILE_MSG = "No file selected."
BAD_EXT_MSG = "Invalid file type."
DELETED_MSG = "File deleted."
NOT_FOUND_MSG = "File not found."

# Canonical general-purpose mime per allowlisted extension. The mime stored in
# META comes from the uploading client, so download rebuilds it from the
# extension instead of echoing stored data -- an attacker can never make a
# blob surface as text/html or any scripted type.
SAFE_MIMES = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "txt": "text/plain",
    "csv": "text/csv",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "mp4": "video/mp4",
    "mov": "video/quicktime",
    "avi": "video/x-msvideo",
    "mkv": "video/x-matroska",
}


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


class UploadForm(FlaskForm):
    # No FileRequired here: an empty submit gets the dedicated NO_FILE flash.
    file = FileField("File")
    submit = SubmitField("Upload")


class DeleteForm(FlaskForm):
    # CSRF token only; FlaskForm injects it via hidden_tag().
    submit = SubmitField("Delete")


@bp.app_template_filter("hsize")
def _hsize(num):
    """Human-readable byte size for the dashboard table."""
    size = float(num or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if size == int(size) else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


@bp.get("/health")
def health():
    from flask import jsonify

    return jsonify({"status": "ok"}), 200


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("vault.dashboard"))
    form = RegisterForm()
    if form.validate_on_submit():
        # Same generic message for weak inputs and a taken username.
        user = register_user(form.username.data, form.password.data)
        if user is not None:
            flash(CREATED_MSG)
            return redirect(url_for("vault.login"))
        flash(GENERIC_REGISTER_MSG)
    return render_template("register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("vault.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = verify_or_lock(form.username.data, form.password.data)
        if user is None:
            # One message for wrong password, unknown user and locked account,
            # so the rate-limit state is never reflected to an unauthenticated
            # caller.
            flash(GENERIC_LOGIN_MSG)
        else:
            login_user(user)
            flash("Logged in.")
            return redirect(url_for("vault.dashboard"))
    return render_template("login.html", form=form)


@bp.get("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("vault.login"))


@bp.get("/dashboard")
@login_required
def dashboard():
    # Deliberate metadata floor: the dashboard reads only DB columns (id, size,
    # date). Plaintext filename/mime live only inside the encrypted blobs, and
    # listing them would mean decrypting every file on every visit; the
    # original name is surfaced only in the upload flash and inside META.
    files = list_files_for_owner(get_db(), int(current_user.get_id()))
    return render_template(
        "dashboard.html", form=UploadForm(), files=files
    )


@bp.post("/upload")
@login_required
def upload():
    form = UploadForm()
    if not form.validate_on_submit():
        # CSRF failures already returned a 400 before we got here.
        return redirect(url_for("vault.dashboard"))

    f = form.file.data
    if f is None or not f.filename:
        flash(NO_FILE_MSG)
        return redirect(url_for("vault.dashboard"))

    filename = f.filename
    if not storage.check_extension(filename):
        # Generic: the rejected name is never echoed back.
        flash(BAD_EXT_MSG)
        return redirect(url_for("vault.dashboard"))

    row = storage.save_upload(
        current_app.config["UPLOAD_FOLDER"],
        f.read(),
        user_id=int(current_user.get_id()),
        filename=filename,
        mime=f.mimetype or "application/octet-stream",
        master=current_app.config["MASTER_KEY_BYTES"],
    )
    # The plaintext original name exists only here (flash) and inside META.
    flash(f"Upload complete: {filename} (File ID: {row['id']}).")
    return redirect(url_for("vault.dashboard"))


@bp.get("/download/<file_id>")
@login_required
def download(file_id):
    result = storage.load_user_file(
        int(current_user.get_id()), file_id,
        master=current_app.config["MASTER_KEY_BYTES"],
    )
    if result is None:
        # One generic 404 for not-found, not-owner, tamper and crypto failure.
        abort(404)
    plaintext, meta = result
    ext = (meta.get("filename") or "").rpartition(".")[-1].lower()
    return send_file(
        io.BytesIO(plaintext),
        mimetype=SAFE_MIMES.get(ext, "application/octet-stream"),
        download_name=meta["filename"],
        as_attachment=True,
    )


@bp.post("/delete/<file_id>")
@login_required
def delete(file_id):
    form = DeleteForm()
    if form.validate_on_submit():
        ok = storage.delete_user_file(int(current_user.get_id()), file_id)
        flash(DELETED_MSG if ok else NOT_FOUND_MSG)
    else:
        flash("Request rejected.")
    return redirect(url_for("vault.dashboard"))
