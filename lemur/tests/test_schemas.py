import json
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


def test_plugin_input_schema(session):
    from lemur.schemas import PluginInputSchema

    input_data = {
        "description": "Allow the uploading of certificates to Amazon S3",
        "slug": "aws-s3",
        "plugin_options": [
            {
                "name": "exportPlugin",
                "type": "export-plugin",
                "required": True,
                "helpMessage": "Export plugin to use before sending data to destination.",
                "value": {
                    "title": "export",
                    "description": "Exports a CSR",
                    "slug": "openssl-csr",
                    "route": "plugins"
                }
            },
            {
                "name": "bucket",
                "type": "str",
                "validation": "[0-9a-z.-]{3,63}",
                "value": "nflx"
            },
            {
                "name": "accountNumber",
                "type": "str",
                "required": True,
                "value": "555555555555"
            },
        ],
        "title": "AWS-S3"
    }

    data, errors = PluginInputSchema().load(input_data)

    assert not errors
    assert data
    assert "plugin_object" in data

    for plugin_option in data["plugin_options"]:
        if "plugin" in plugin_option["type"]:
            assert "plugin_object" in plugin_option["value"]
        else:
            assert "helpMessage" in plugin_option


def test_plugin_input_schema_invalid_account_number(session):
    from lemur.schemas import PluginInputSchema

    input_data = {
        "description": "Allow the uploading of certificates to Amazon S3",
        "slug": "aws-s3",
        "plugin_options": [
            {
                "name": "accountNumber",
                "type": "str",
                "required": True,
                "value": "1234"  # invalid account number
            },
        ],
        "title": "AWS-S3"
    }

    data, errors = PluginInputSchema().load(input_data)

    assert errors
    assert '\'accountNumber\' cannot be validated' in json.dumps(errors)
