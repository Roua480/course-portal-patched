"""Central, default-deny RBAC followed by object/context ABAC."""
from flask import abort, current_app, g, request
from flask_login import current_user
from werkzeug.exceptions import HTTPException
from .models import utcnow

ROLE_PERMISSIONS = {
    "student": {"view_material", "submit", "view_grade", "view_submission"},
    "ta": {"view_material", "grade", "view_gradebook", "view_submission"},
    "instructor": {"view_material", "create_assignment", "grade", "change_grade",
                   "view_gradebook", "release_grades", "view_submission"},
    "registrar": {"enroll", "manage_roles", "assign_staff"},
}


def view_material(user, obj, ctx):
    return obj is not None and obj.id in user.enrolled_in | user.staff_of


def submit(user, obj, ctx):
    return (obj is not None and obj.course_id in user.enrolled_in
            and utcnow() < obj.deadline)


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
            and utcnow() < obj.course.grade_deadline)


def view_gradebook(user, obj, ctx):
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
        if request.endpoint in public:
            return
        if not current_user.is_authenticated:
            deny(401, "authentication required")
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
        if not can(current_user, perm, g.policy_object, {}):
            deny(404 if perm in {"view_submission", "view_grade"} else 403, "object condition")
