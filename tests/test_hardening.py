"""Integration checks for legitimate flows and policy boundary conditions."""
from datetime import timedelta
import re
import pytest
from conftest import login
from portal.models import AssignmentExtension, Course, Submission, User, db, utcnow


@pytest.mark.parametrize("path", ["/", "/api/me", "/gradebook/1", "/registrar-x9k2"])
def test_protected_routes_require_authentication(client, path):
    assert client.get(path).status_code == 401


def test_legitimate_student_and_instructor_flows(client):
    login(client, "lina")
    assert client.get("/courses/1/materials").status_code == 200
    assert client.get("/submissions/1").status_code == 200
    assert client.post("/assignments/2/submit", data={"body": "Updated work"}).status_code == 200
    login(client, "dr_haddad")
    assert client.post("/submissions/2/grade", data={"grade": "B+"}).status_code == 200
    assert client.post("/staff/release/1").status_code == 200
    assert db.session.get(Submission, 2).released


def test_unreleased_grade_and_feedback_are_not_shown_to_student(client):
    sub = db.session.get(Submission, 2)
    sub.grade, sub.feedback = "A+", "STAFF ONLY DRAFT"
    db.session.commit()
    login(client, "lina")
    response = client.get("/submissions/2")
    assert response.status_code == 200
    assert "STAFF ONLY DRAFT" not in response.text and "A+" not in response.text


def test_email_update_is_self_only_and_rejects_duplicate_addresses(client):
    login(client, "lina")
    assert client.put("/api/users/6/email", json={"email": "new@portal.lab"}).status_code == 200
    assert db.session.get(User, 6).email == "new@portal.lab"
    assert client.put("/api/users/6/email", json={"email": "HADDAD@PORTAL.LAB"}).status_code == 409
    assert db.session.get(User, 2).email == "haddad@portal.lab"
    assert client.put("/api/users/2/email", json={"email": "new@portal.lab"}).status_code == 403


@pytest.mark.parametrize("path", ["/submissions/1/change", "/submissions/1/change/confirm"])
def test_both_grade_change_steps_recheck_deadline(client, path):
    login(client, "dr_haddad")
    db.session.get(Course, 1).grade_deadline = utcnow() - timedelta(seconds=1)
    db.session.commit()
    assert client.post(path, data={"grade": "A+", "confirmed": "true"}).status_code == 403
    assert db.session.get(Submission, 1).grade == "B"


def test_unauthorized_role_cannot_probe_object_existence(client):
    login(client, "lina")
    assert client.get("/gradebook/1").status_code == client.get("/gradebook/99999").status_code == 403
    assert client.get("/submissions/3").status_code == client.get("/submissions/99999").status_code == 404


def test_login_rotates_token_and_rejects_prelogin_token(client):
    page = client.get("/login")
    before = client.csrf_token()
    assert before in page.text
    login(client, "dr_haddad")
    assert client.csrf_token() != before
    response = client.post("/submissions/2/grade", data={"grade": "A+"}, csrf=False,
                           headers={"X-CSRF-Token": before})
    assert response.status_code == 403


def test_public_form_with_existing_session_requires_token(client):
    client.get("/forgot")
    assert client.post("/forgot", data={"username": "lina"}, csrf=False).status_code == 403
    assert client.post("/forgot", data={"username": "lina"}).status_code == 200


def test_cross_origin_first_login_is_refused(client):
    assert client.post("/login", data={"username": "lina", "password": "Portal1234!"},
                       headers={"Origin": "http://127.0.0.1:8000"}, csrf=False).status_code == 403


def test_all_rendered_forms_and_meta_contain_token(client):
    login(client, "registrar")
    page = client.get("/registrar-x9k2").text
    assert '<meta name="csrf-token"' in page
    forms = re.findall(r"<form\b.*?</form>", page, re.S)
    assert forms
    assert all('name="csrf_token"' in form and client.csrf_token() in form for form in forms)


def test_logout_requires_post_and_token(client):
    login(client, "lina")
    assert client.get("/logout").status_code == 405
    assert client.post("/logout", csrf=False).status_code == 403
    assert client.post("/logout").status_code == 302
    assert client.get("/api/me").status_code == 401


def test_chair_is_read_only_through_routes(client):
    login(client, "chair")
    assert client.get("/gradebook/1").status_code == 200
    assert client.post("/staff/release/1").status_code == 403
    assert client.post("/submissions/2/grade", data={"grade": "A+"}).status_code == 403


def test_approved_extension_is_enforced_through_submit_route(client):
    login(client, "lina")
    assert client.post("/assignments/3/submit", data={"body": "late"}).status_code == 403
    db.session.add(AssignmentExtension(user_id=6, assignment_id=3, approved_by_id=2))
    db.session.commit()
    assert client.post("/assignments/3/submit", data={"body": "approved late work"}).status_code == 200


def test_enrolled_ta_is_denied_through_grade_route(client):
    login(client, "rana")
    assert client.post("/submissions/4/grade", data={"grade": "A+"}).status_code == 403
    assert db.session.get(Submission, 4).grade == "B+"


def test_denial_is_logged_without_exposing_reason(client, caplog):
    login(client, "lina")
    response = client.get("/registrar-x9k2")
    assert response.status_code == 403
    assert response.text == "<h1>Request refused</h1>"
    assert "Access denied:" in caplog.text and "role permission" in caplog.text
