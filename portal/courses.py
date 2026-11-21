from markupsafe import escape
from flask import Blueprint, g, render_template, request
from flask_login import current_user, login_required

from .models import Assignment, Course, Submission, db
from .policy import requires, can

bp = Blueprint("courses", __name__)


@bp.get("/")
@login_required
@requires("authenticated")
def dashboard():
    ids = current_user.enrolled_in | current_user.staff_of
    courses = Course.query.filter(Course.id.in_(ids)).all() if ids else []
    return render_template("dashboard.html", courses=courses)


@bp.get("/courses/<int:cid>/materials")
@login_required
@requires("view_material", lambda cid: db.get_or_404(Course, cid))
def materials(cid):
    return render_template("materials.html", course=g.policy_object)


@bp.post("/assignments/<int:aid>/submit")
@login_required
@requires("submit", lambda aid: db.get_or_404(Assignment, aid))
def submit(aid):
    sub = Submission.query.filter_by(assignment_id=aid, student_id=current_user.id).first()
    if sub is None:
        sub = Submission(assignment_id=aid, student_id=current_user.id)
        db.session.add(sub)
    sub.body = request.form.get("body", "")
    db.session.commit()
    return render_template("submission.html", sub=sub, show_grade=can(current_user, "view_grade", sub) or can(current_user, "view_gradebook", sub.course))


@bp.get("/submissions/<int:sid>")
@login_required
@requires("view_submission", lambda sid: db.get_or_404(Submission, sid))
def view_submission(sid):
    sub = g.policy_object
    return render_template("submission.html", sub=sub, show_grade=can(current_user, "view_grade", sub) or can(current_user, "view_gradebook", sub.course))


@bp.post("/submissions/<int:sid>/grade")
@login_required
@requires("grade", lambda sid: db.get_or_404(Submission, sid))
def grade(sid):
    sub = g.policy_object
    sub.grade = request.form.get("grade")
    db.session.commit()
    return f"Grade for submission {sub.id} set to {escape(sub.grade)}."


@bp.post("/submissions/<int:sid>/change")
@login_required
@requires("change_grade", lambda sid: db.get_or_404(Submission, sid))
def change(sid):
    sub = g.policy_object
    return render_template("change_confirm.html", sub=sub,
                           grade=request.form.get("grade"))


@bp.post("/submissions/<int:sid>/change/confirm")
@login_required
@requires("change_grade", lambda sid: db.get_or_404(Submission, sid))
def change_confirm(sid):
    sub = g.policy_object
    if request.form.get("confirmed") == "true":
        sub.grade = request.form.get("grade")
        db.session.commit()
        return f"Grade for submission {sub.id} changed to {escape(sub.grade)}."
    return "Change cancelled."


@bp.get("/gradebook/<int:cid>")
@requires("view_gradebook", lambda cid: db.get_or_404(Course, cid))
def gradebook(cid):
    course = g.policy_object
    subs = (Submission.query.join(Assignment)
            .filter(Assignment.course_id == cid).all())
    return render_template("gradebook.html", course=course, subs=subs)
