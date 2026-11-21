"""Part 4 N1-N4: at least two denials per requirement."""
from portal.policy import can


def test_n1_chair_reads_own_department(world):
    assert can(world["chair"], "view_gradebook", world["cmps215"])


def test_n1_chair_cannot_read_other_department(world):
    world["cmps202"].department = "EECE"
    assert not can(world["chair"], "view_gradebook", world["cmps202"])


def test_n1_chair_cannot_change_grades(world):
    assert not can(world["chair"], "change_grade", world["sub_rel_215"], {"network": "campus"})
