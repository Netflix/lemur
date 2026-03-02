#!/usr/bin/env python3
"""
Script to create default resources for local development.
This creates the default user and test authority.
Called by the Docker entrypoint when LEMUR_CREATE_DEFAULTS=true.
"""

import sys
from datetime import datetime, timedelta

# Setup Flask app context
from lemur.factory import create_app

app = create_app()


def create_user(username, password, email, role_names):
    from lemur.users import service as user_service
    from lemur.roles import service as role_service

    user = user_service.get_by_username(username)
    if user:
        print(f" # User '{username}' already exists")
        return user

    # Convert role names to role objects
    roles = []
    for role_name in role_names:
        role = role_service.get_by_name(role_name)
        if not role:
            print(f" # ERROR: Role '{role_name}' not found")
            return None
        roles.append(role)

    user = user_service.create(
        username=username,
        password=password,
        email=email,
        active=True,
        roles=roles,
        profile_picture="",
    )
    print(
        f" # Default user '{username}' created with roles {', '.join(role_names)} (ID: {user.id})"
    )

    return user


def create_default_users():
    """Create the default users if they don't exist."""
    create_user("user", "pass", "user@email.com", ["admin"])
    create_user("operator", "pass", "operator@email.com", ["operator"])


def create_default_authority():
    """Create the default test authority if it doesn't exist."""
    from lemur.users import service as user_service
    from lemur.roles import service as role_service
    from lemur.plugins.base import plugins
    from lemur.authorities import service as authority_service
    from lemur import database

    # Check if TestCA authority already exists
    existing = authority_service.get_by_name("TestCA")
    if existing:
        print(" # Default authority 'TestCA' already exists")
        return existing

    user = user_service.get_by_username("user")

    if not user:
        print(" # Error: No user found to set as authority creator")
        return None

    # Get the cryptography issuer plugin object
    plugin = plugins.get("cryptography-issuer")
    if not plugin:
        print(" # Error: cryptography-issuer plugin not found")
        return None

    # Authority options
    authority_options = {
        "name": "TestCA",
        "owner": "user@email.com",
        "description": "Test Certificate Authority for local development",
        "common_name": "TestCA Root CA",
        "country": "US",
        "state": "California",
        "location": "San Francisco",
        "organization": "Example Inc",
        "organizational_unit": "IT Department",
        "type": "root",
        "signing_algorithm": "sha256WithRSA",
        "key_type": "RSA2048",
        "sensitivity": "medium",
        "serial_number": 1,
        "first_serial": 1,
        "validity_start": datetime(2000, 1, 1),
        "validity_end": datetime(2000, 1, 1)
        + timedelta(days=36500),  # 100 years from 2000-01-01
        "plugin": {"slug": "cryptography-issuer", "plugin_object": plugin},
        "extensions": {"sub_alt_names": {"names": []}, "custom": []},
        "creator": user,
    }

    try:
        authority = authority_service.create(**authority_options)
        print(
            f" # Default authority 'TestCA' created successfully (ID: {authority.id})"
        )

        # Add the user to the authority roles so they can see and manage it
        roles_to_add = ["TestCA_admin", "user@email.com"]
        for role_name in roles_to_add:
            role = role_service.get_by_name(role_name)
            if role and user:
                if role not in user.roles:
                    user.roles.append(role)
                    print(f" # Added user '{user.username}' to role '{role_name}'")
                else:
                    print(f" # User '{user.username}' already has role '{role_name}'")

        # Also add operator user to TestCA_operator role so they can create certificates
        operator = user_service.get_by_username("operator")
        if operator:
            testca_operator_role = role_service.get_by_name("TestCA_operator")
            if testca_operator_role:
                if testca_operator_role not in operator.roles:
                    operator.roles.append(testca_operator_role)
                    print(f" # Added operator user to role 'TestCA_operator'")
                else:
                    print(f" # Operator user already has role 'TestCA_operator'")

        database.commit()
        print(f" # User roles updated successfully")
        return authority
    except Exception as e:
        print(f" # Error creating default authority: {e}")
        import traceback

        traceback.print_exc()
        return None


def main():
    """Main function to create default resources."""
    print(" # Creating default resources for local development")

    with app.app_context():
        # Create default users
        create_default_users()
        create_default_authority()


if __name__ == "__main__":
    sys.exit(main())
