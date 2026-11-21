from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required

from .models import User, db

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/me")
@login_required
def me():
    return jsonify(id=current_user.id, username=current_user.username,
                   role=current_user.role, email=current_user.email)


@bp.put("/users/<int:uid>/email")
@login_required
def set_email(uid):
    # Identity comes from the authenticated session, never the URL's target ID.
    if uid != current_user.id:
        abort(403)
    user = current_user
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    if not isinstance(email, str) or "@" not in email or len(email) > 120:
        abort(400)
    email = email.strip().lower()
    if User.query.filter(db.func.lower(User.email) == email, User.id != user.id).first():
        abort(409)
    user.email = email
    db.session.commit()
    return jsonify(status="ok")
