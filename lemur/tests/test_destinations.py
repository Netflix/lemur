from lemur.destinations.service import *  # noqa
from lemur.destinations.views import *  # noqa

from json import dumps


def test_crud(session):
    destination = create('testdest', 'aws-destination', {}, description='destination1')
    assert destination.id > 0

    destination = update(destination.id, 'testdest2', {}, 'destination2')
    assert destination.label == 'testdest2'

    assert len(get_all()) == 1

    delete(1)
    assert len(get_all()) == 0


def test_destination_get(client):
    assert client.get(api.url_for(Destinations, destination_id=1)).status_code == 401


def test_destination_post(client):
    assert client.post(api.url_for(Destinations, destination_id=1), data={}).status_code == 405


def test_destination_put(client):
    assert client.put(api.url_for(Destinations, destination_id=1), data={}).status_code == 401


def test_destination_delete(client):
    assert client.delete(api.url_for(Destinations, destination_id=1)).status_code == 401


def test_destination_patch(client):
    assert client.patch(api.url_for(Destinations, destination_id=1), data={}).status_code == 405


VALID_USER_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'}


def test_auth_destination_get(client):
    assert client.get(api.url_for(Destinations, destination_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_destination_post_(client):
    assert client.post(api.url_for(Destinations, destination_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_destination_put(client):
    assert client.put(api.url_for(Destinations, destination_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_destination_delete(client):
    assert client.delete(api.url_for(Destinations, destination_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_destination_patch(client):
    assert client.patch(api.url_for(Destinations, destination_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


VALID_ADMIN_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyNTAyMTgsInN1YiI6MiwiZXhwIjoxNTIxNTYzODE4fQ.6mbq4-Ro6K5MmuNiTJBB153RDhlM5LGJBjI7GBKkfqA'}


def test_admin_destination_get(client):
    assert client.get(api.url_for(Destinations, destination_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_destination_post(client):
    assert client.post(api.url_for(Destinations, destination_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_destination_put(client):
    assert client.put(api.url_for(Destinations, destination_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_destination_delete(client):
    assert client.delete(api.url_for(Destinations, destination_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 500


def test_admin_destination_patch(client):
    assert client.patch(api.url_for(Destinations, destination_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_destinations_get(client):
    assert client.get(api.url_for(DestinationsList)).status_code == 401


def test_destinations_post(client):
    assert client.post(api.url_for(DestinationsList), data={}).status_code == 401


def test_destinations_put(client):
    assert client.put(api.url_for(DestinationsList), data={}).status_code == 405


def test_destinations_delete(client):
    assert client.delete(api.url_for(DestinationsList)).status_code == 405


def test_destinations_patch(client):
    assert client.patch(api.url_for(DestinationsList), data={}).status_code == 405


def test_auth_destinations_get(client):
    assert client.get(api.url_for(DestinationsList), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_destinations_post(client):
    assert client.post(api.url_for(DestinationsList), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_admin_destinations_get(client):
    resp = client.get(api.url_for(DestinationsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [], 'total': 0}


def test_admin_destinations_crud(client):
    assert client.post(api.url_for(DestinationsList), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400
    data = {'plugin': {'slug': 'aws-destination', 'pluginOptions': {}}, 'label': 'test', 'description': 'test'}
    resp = client.post(api.url_for(DestinationsList), data=dumps(data), content_type='application/json', headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert client.get(api.url_for(Destinations, destination_id=resp.json['id']), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
    resp = client.get(api.url_for(DestinationsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json['items'][0]['description'] == 'test'
    assert client.delete(api.url_for(Destinations, destination_id=2), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
    resp = client.get(api.url_for(DestinationsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [], 'total': 0}
