"""Part 4 N1-N4: at least two denials per requirement."""
from portal.policy import can


def test_n1_chair_reads_own_department(world):
    assert can(world["chair"], "view_gradebook", world["cmps215"])


def test_n1_chair_cannot_read_other_department(world):
    world["cmps202"].department = "EECE"
    assert not can(world["chair"], "view_gradebook", world["cmps202"])


def test_n1_chair_cannot_change_grades(world):
    assert not can(world["chair"], "change_grade", world["sub_rel_215"], {"network": "campus"})


from datetime import timedelta
from portal.models import AssignmentExtension, db, utcnow


def approve(world, assignment):
    db.session.add(AssignmentExtension(user_id=world["lina"].id,
                   assignment_id=assignment.id, approved_by_id=world["dr_haddad"].id))
    db.session.flush()


def test_n2_approved_extension_allows_late_submission(world):
    assignment = world["a3_late"]
    assignment.deadline = utcnow() - timedelta(days=2)
    approve(world, assignment)
    assert can(world["lina"], "submit", assignment)


def test_n2_late_without_approval_is_denied(world):
    assert not can(world["lina"], "submit", world["a3_late"])


def test_n2_approval_cannot_exceed_three_days(world):
    assignment = world["a3_late"]
    assignment.deadline = utcnow() - timedelta(days=3, seconds=1)
    approve(world, assignment)
    assert not can(world["lina"], "submit", assignment)


from conftest import login
from portal.models import Submission


def test_n3_campus_instructor_can_change_released_grade(client):
    login(client, "dr_haddad")
    response = client.post("/submissions/1/change/confirm",
                           data={"grade": "A-", "confirmed": "true"},
                           environ_overrides={"REMOTE_ADDR": "10.1.2.3"})
    assert response.status_code == 200
    assert db.session.get(Submission, 1).grade == "A-"


def test_n3_external_instructor_is_denied(client):
    login(client, "dr_haddad")
    response = client.post("/submissions/1/change/confirm",
                           data={"grade": "A+", "confirmed": "true"},
                           environ_overrides={"REMOTE_ADDR": "198.51.100.9"})
    assert response.status_code == 403
    assert db.session.get(Submission, 1).grade == "B"


def test_n3_forged_campus_headers_do_not_bypass_external_denial(client):
    login(client, "dr_haddad")
    response = client.post("/submissions/1/change/confirm",
                           data={"grade": "A+", "confirmed": "true"},
                           environ_overrides={"REMOTE_ADDR": "198.51.100.9"},
                           headers={"X-Forwarded-For": "127.0.0.1", "X-Network": "campus",
                                    "Forwarded": "for=10.1.2.3", "X-Real-IP": "10.1.2.3"})
    assert response.status_code == 403
    assert db.session.get(Submission, 1).grade == "B"


def test_n4_unenrolled_ta_can_grade(world):
    assert can(world["omar_ta"], "grade", world["sub_open_215"])


def test_n4_enrolled_ta_cannot_grade_own_submission(world):
    assert not can(world["rana_ta"], "grade", world["sub_open_202"])


def test_n4_enrolled_ta_cannot_grade_another_student(world):
    other = world["sub_sami"]
    other.released = False
    assert not can(world["rana_ta"], "grade", other)
