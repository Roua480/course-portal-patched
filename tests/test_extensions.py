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
