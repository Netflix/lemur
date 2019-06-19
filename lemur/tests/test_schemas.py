import pytest
from marshmallow.exceptions import ValidationError

from lemur.tests.factories import RoleFactory


def test_get_object_attribute():
    from lemur.schemas import get_object_attribute

    with pytest.raises(ValidationError):
        get_object_attribute({})

    with pytest.raises(ValidationError):
        get_object_attribute([{}], many=True)

    with pytest.raises(ValidationError):
        get_object_attribute([{}, {"id": 1}], many=True)

    with pytest.raises(ValidationError):
        get_object_attribute([{}, {"name": "test"}], many=True)

    assert get_object_attribute({"name": "test"}) == "name"
    assert get_object_attribute({"id": 1}) == "id"
    assert get_object_attribute([{"name": "test"}], many=True) == "name"
    assert get_object_attribute([{"id": 1}], many=True) == "id"


def test_fetch_objects(session):
    from lemur.roles.models import Role
    from lemur.schemas import fetch_objects

    role = RoleFactory()
    role1 = RoleFactory()
    session.commit()

    data = {"id": role.id}
    found_role = fetch_objects(Role, data)
    assert found_role == role

    data = {"name": role.name}
    found_role = fetch_objects(Role, data)
    assert found_role == role

    data = [{"id": role.id}, {"id": role1.id}]
    found_roles = fetch_objects(Role, data, many=True)
    assert found_roles == [role, role1]

    data = [{"name": role.name}, {"name": role1.name}]
    found_roles = fetch_objects(Role, data, many=True)
    assert found_roles == [role, role1]

    with pytest.raises(ValidationError):
        data = [{"name": "blah"}, {"name": role1.name}]
        fetch_objects(Role, data, many=True)

    with pytest.raises(ValidationError):
        data = {"name": "nah"}
        fetch_objects(Role, data)
