"""Central, default-deny RBAC followed by object/context ABAC."""
import secrets
from ipaddress import ip_address, ip_network
from datetime import timedelta
from flask import abort, current_app, g, request, session
from flask_login import current_user
from werkzeug.exceptions import HTTPException
from .models import AssignmentExtension, db, utcnow

ROLE_PERMISSIONS = {
    "student": {"view_material", "submit", "view_grade", "view_submission"},
    "ta": {"view_material", "grade", "view_gradebook", "view_submission"},
    "instructor": {"view_material", "create_assignment", "grade", "change_grade",
                   "view_gradebook", "release_grades", "view_submission"},
    "registrar": {"enroll", "manage_roles", "assign_staff"},
    "chair": {"view_gradebook"},
}


def view_material(user, obj, ctx):
    return obj is not None and obj.id in user.enrolled_in | user.staff_of


def submit(user, obj, ctx):
    if obj is None or obj.course_id not in user.enrolled_in:
        return False
    deadline = obj.deadline
    approval = db.session.get(AssignmentExtension, (user.id, obj.id))
    if approval is not None:
        deadline += timedelta(days=3)
    return utcnow() < deadline


def view_grade(user, obj, ctx):
    return obj is not None and obj.student_id == user.id and obj.released


def view_submission(user, obj, ctx):
    return obj is not None and (obj.student_id == user.id or obj.course_id in user.staff_of)


def create_assignment(user, obj, ctx):
    return obj is not None and obj.id in user.teaches


def grade(user, obj, ctx):
    return obj is not None and obj.course_id in user.staff_of and not obj.released


def change_grade(user, obj, ctx):
    return (obj is not None and obj.course_id in user.teaches and obj.released
            and utcnow() < obj.course.grade_deadline and ctx.get("network") == "campus")


def view_gradebook(user, obj, ctx):
    if user.role == "chair":
        return obj is not None and obj.department == user.department
    return obj is not None and obj.id in user.staff_of


def release_grades(user, obj, ctx):
    return obj is not None and obj.id in user.teaches


def enroll(user, obj, ctx):
    return True


def manage_roles(user, obj, ctx):
    return True


def assign_staff(user, obj, ctx):
    return True


CONDITIONS = {f.__name__: f for f in (
    view_material, submit, view_grade, view_submission, create_assignment, grade,
    change_grade, view_gradebook, release_grades, enroll, manage_roles, assign_staff)}


def can(user, perm, obj=None, ctx=None):
    if not user or not user.is_authenticated:
        return False
    if perm not in ROLE_PERMISSIONS.get(user.role, set()):
        return False
    condition = CONDITIONS.get(perm)
    return bool(condition and condition(user, obj, ctx or {}))


def requires(perm, load=None):
    """Declare route metadata, evaluated by the global hook."""
    def deco(f):
        f.portal_rule = (perm, load)
        return f
    return deco


def deny(status, reason):
    current_app.logger.warning("Access denied: endpoint=%s method=%s user=%s reason=%s",
                               request.endpoint, request.method, current_user.get_id(), reason)
    abort(status)


def request_context():
    # Direct peer address only. No ProxyFix and no trust in client proxy headers.
    try:
        peer = ip_address(request.remote_addr or "")
        campus = any(peer in net for net in (ip_network("10.0.0.0/8"), ip_network("127.0.0.0/8")))
    except ValueError:
        campus = False
    return {"network": "campus" if campus else "external"}


def install(app):
    public = {"auth.login", "auth.forgot", "auth.reset", "static", "robots"}
    signed_in = {"auth.logout", "auth.inbox", "courses.dashboard", "api.me", "api.set_email"}

    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    def short_error(error):
        return "<h1>Request refused</h1>", error.code

    @app.before_request
    def authorize():
        is_public = request.endpoint in public
        if not is_public and not current_user.is_authenticated:
            deny(401, "authentication required")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            expected = session.get("csrf_token")
            supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            # First-contact anonymous auth requests have no existing session to exploit.
            # Once a session/token exists, public forms must validate it as well.
            bootstrap = (is_public and not session.get("_user_id") and expected is None
                         and request.endpoint in {"auth.login", "auth.forgot", "auth.reset"})
            if not bootstrap and not (isinstance(expected, str) and isinstance(supplied, str)
                                      and secrets.compare_digest(expected.encode(), supplied.encode())):
                deny(403, "CSRF token")
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        if is_public:
            return
        if request.routing_exception is not None:
            deny(request.routing_exception.code, "unavailable route or method")
        if request.endpoint in signed_in:
            return
        view = app.view_functions.get(request.endpoint)
        rule = getattr(view, "portal_rule", None)
        if rule is None:
            deny(403, "missing rule")
        perm, load = rule
        # Reject roles before loading IDs, so they cannot probe object existence.
        if perm not in ROLE_PERMISSIONS.get(current_user.role, set()) or perm not in CONDITIONS:
            deny(403, "role permission")
        try:
            g.policy_object = load(**request.view_args) if load else None
        except HTTPException as error:
            deny(error.code, "object unavailable")
        if not can(current_user, perm, g.policy_object, request_context()):
            deny(404 if perm in {"view_submission", "view_grade"} else 403, "object condition")

