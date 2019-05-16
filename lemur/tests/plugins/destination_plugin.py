from lemur.plugins.bases import DestinationPlugin


class TestDestinationPlugin(DestinationPlugin):
    title = "Test"
    slug = "test-destination"
    description = "Enables testing"

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        super(TestDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        return
