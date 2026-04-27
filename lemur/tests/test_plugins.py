from lemur.plugins.views import *  # noqa


from .vectors import (
    VALID_ADMIN_HEADER_TOKEN,
)


def test_plugins_list_get(client, app):
    response = client.get(api.url_for(PluginsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert response.status_code == 200

    data = response.get_json()

    # Perform some assertions on data based on what you expect
    assert 'items' in data
    assert isinstance(data['items'], list)

    for item in data['items']:
        assert 'title' in item
