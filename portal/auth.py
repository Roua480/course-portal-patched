import secrets
from datetime import timedelta

from flask import Blueprint, redirect, render_template, request, session
from flask_login import current_user, login_required, login_user, logout_user

from .models import Mail, ResetToken, User, db, utcnow
from .policy import requires

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username", "")).first()
        if user and user.check_password(request.form.get("password", "")):
            session.clear()
            login_user(user)
            session["csrf_token"] = secrets.token_urlsafe(32)
            resp = redirect("/")
            return resp
        error = "Invalid username or password."
    return render_template("login.html", error=error), (401 if error else 200)


@bp.post("/logout")
@requires("authenticated")
def logout():
    logout_user()
    session.clear()
    resp = redirect("/login")
    resp.delete_cookie("role")
    return resp


@bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    sent = False
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username", "")).first()
        if user:
            token = secrets.token_urlsafe(32)
            db.session.add(ResetToken(token=token, user_id=user.id,
                                      expires_at=utcnow() + timedelta(minutes=30)))
            db.session.add(Mail(
                to_address=user.email,
                subject="Reset your Course Portal password",
                body=f"Open {request.host_url}reset?token={token} within 30 minutes."))
            db.session.commit()
        sent = True
    return render_template("forgot.html", sent=sent)


@bp.route("/reset", methods=["GET", "POST"])
def reset():
    token = request.args.get("token", "")
    rt = db.session.get(ResetToken, token) if token else None
    if rt is None or rt.used or rt.expires_at < utcnow():
        return render_template("reset.html", error="This reset link is invalid or has expired.",
                               done=False, invalid=True), 400
    if request.method == "POST":
        pw = request.form.get("new_password", "")
        if len(pw) < 8:
            return render_template("reset.html", error="Password must be at least 8 characters.",
                                   done=False), 400
        rt.user.set_password(pw)
        rt.used = True
        db.session.commit()
        return render_template("reset.html", error=None, done=True)
    return render_template("reset.html", error=None, done=False)


@bp.get("/inbox")
@login_required
@requires("authenticated")
def inbox():
    mails = (Mail.query.filter_by(to_address=current_user.email)
             .order_by(Mail.sent_at.desc(), Mail.id.desc()).all())
    return render_template("inbox.html", mails=mails)
