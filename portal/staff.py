from markupsafe import escape
from datetime import datetime

from flask import Blueprint, abort, g, render_template, request
from flask_login import login_required

from .models import Assignment, Course, CourseTA, Enrollment, Submission, User, db
from .policy import requires, ROLE_PERMISSIONS

bp = Blueprint("staff", __name__)


@bp.post("/staff/release/<int:cid>")
@login_required
@requires("release_grades", lambda cid: db.get_or_404(Course, cid))
def release(cid):
    course = g.policy_object
    for sub in Submission.query.join(Assignment).filter(Assignment.course_id == cid):
        sub.released = True
    db.session.commit()
    return f"Grades released for {escape(course.code)}."


@bp.get("/staff/assignments/new")
@requires("create_assignment", lambda: db.get_or_404(Course, request.args.get("course_id", type=int)))
def new_assignment_form():
    return render_template("course_new_assignment.html", course=g.policy_object)


@bp.post("/staff/assignments/new")
@requires("create_assignment", lambda: db.get_or_404(Course, request.form.get("course_id", type=int)))
def new_assignment():
    cid = int(request.form["course_id"])
    deadline = datetime.fromisoformat(request.form["deadline"])
    db.session.add(Assignment(course_id=cid, title=request.form["title"],
                              deadline=deadline))
    db.session.commit()
    return f"Assignment added to course {cid}."


@bp.get("/registrar-x9k2")
@login_required
@requires("manage_roles")
def registrar_console():
    return render_template("registrar_console.html", users=User.query.all())


@bp.post("/registrar-x9k2/role")
@login_required
@requires("manage_roles")
def set_role():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    if request.form.get("role") not in ROLE_PERMISSIONS:
        abort(400)
    user.role = request.form["role"]
    db.session.commit()
    return f"Role of {escape(user.username)} set to {escape(user.role)}."


@bp.post("/registrar-x9k2/enroll")
@login_required
@requires("enroll", lambda: db.get_or_404(Course, request.form.get("course_id", type=int)))
def enroll():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    cid = int(request.form["course_id"])
    db.session.add(Enrollment(user_id=user.id, course_id=cid))
    db.session.commit()
    return f"{escape(user.username)} enrolled in course {cid}."


@bp.get("/registrar")
@login_required
@requires("assign_staff")
def registrar():
    return render_template("registrar.html", courses=Course.query.all())


@bp.post("/courses/<int:cid>/staff/add")
@login_required
@requires("assign_staff", lambda cid: db.get_or_404(Course, cid))
def add_ta(cid):
    course = g.policy_object
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    if db.session.get(CourseTA, (user.id, cid)) is None:
        db.session.add(CourseTA(user_id=user.id, course_id=cid))
        db.session.commit()
    return f"{escape(user.username)} added as TA of {escape(course.code)}."
