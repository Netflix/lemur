from lemur.plugins.lemur_email.templates.config import env

import os.path


def test_render():
    messages = [{
        'name': 'a-really-really-long-certificate-name',
        'owner': 'bob@example.com',
        'not_after': '2015-12-14 23:59:59'
    }] * 10

    template = env.get_template('{}.html'.format('expiration'))
    body = template.render(dict(messages=messages, hostname='lemur.test.example.com'))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'email.html'), 'w+') as f:
        f.write(body.encode('utf8'))
