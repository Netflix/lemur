from lemur.sources.service import *  # noqa
from lemur.sources.views import *  # noqa

from json import dumps


def test_crud(session):
    source = create('testdest', 'aws-source', {}, description='source1')
    assert source.id > 0

    source = update(source.id, 'testdest2', {}, 'source2')
    assert source.label == 'testdest2'

    assert len(get_all()) == 1

    delete(1)
    assert len(get_all()) == 0


def test_source_get(client):
    assert client.get(api.url_for(Sources, source_id=1)).status_code == 401


def test_source_post(client):
    assert client.post(api.url_for(Sources, source_id=1), data={}).status_code == 405


def test_source_put(client):
    assert client.put(api.url_for(Sources, source_id=1), data={}).status_code == 401


def test_source_delete(client):
    assert client.delete(api.url_for(Sources, source_id=1)).status_code == 401


def test_source_patch(client):
    assert client.patch(api.url_for(Sources, source_id=1), data={}).status_code == 405


VALID_USER_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'}


def test_auth_source_get(client):
    assert client.get(api.url_for(Sources, source_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_source_post_(client):
    assert client.post(api.url_for(Sources, source_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_source_put(client):
    assert client.put(api.url_for(Sources, source_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_source_delete(client):
    assert client.delete(api.url_for(Sources, source_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_source_patch(client):
    assert client.patch(api.url_for(Sources, source_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


VALID_ADMIN_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyNTAyMTgsInN1YiI6MiwiZXhwIjoxNTIxNTYzODE4fQ.6mbq4-Ro6K5MmuNiTJBB153RDhlM5LGJBjI7GBKkfqA'}


def test_admin_source_get(client):
    assert client.get(api.url_for(Sources, source_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_source_post(client):
    assert client.post(api.url_for(Sources, source_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_source_put(client):
    assert client.put(api.url_for(Sources, source_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_source_delete(client):
    assert client.delete(api.url_for(Sources, source_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_source_patch(client):
    assert client.patch(api.url_for(Sources, source_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_sources_get(client):
    assert client.get(api.url_for(SourcesList)).status_code == 401


def test_sources_post(client):
    assert client.post(api.url_for(SourcesList), data={}).status_code == 401


def test_sources_put(client):
    assert client.put(api.url_for(SourcesList), data={}).status_code == 405


def test_sources_delete(client):
    assert client.delete(api.url_for(SourcesList)).status_code == 405


def test_sources_patch(client):
    assert client.patch(api.url_for(SourcesList), data={}).status_code == 405


def test_auth_sources_get(client):
    assert client.get(api.url_for(SourcesList), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_sources_post(client):
    assert client.post(api.url_for(SourcesList), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_admin_sources_get(client):
    resp = client.get(api.url_for(SourcesList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [], 'total': 0}


def test_admin_sources_crud(client):
    assert client.post(api.url_for(SourcesList), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400
    data = {'plugin': {'slug': 'aws-source', 'pluginOptions': {}}, 'label': 'test', 'description': 'test'}
    resp = client.post(api.url_for(SourcesList), data=dumps(data), content_type='application/json', headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert client.get(api.url_for(Sources, source_id=resp.json['id']), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
    resp = client.get(api.url_for(SourcesList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json['items'][0]['description'] == 'test'
    assert client.delete(api.url_for(Sources, source_id=2), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
    resp = client.get(api.url_for(SourcesList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [], 'total': 0}
