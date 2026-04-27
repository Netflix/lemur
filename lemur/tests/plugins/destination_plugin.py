from lemur.plugins.bases import DestinationPlugin


class TestDestinationPlugin(DestinationPlugin):
    title = "Test"
    slug = "test-destination"
    description = "Enables testing"

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        return


class TestDestinationPluginDuplicatesAllowed(DestinationPlugin):
    title = "Test with Duplicates Allowed"
    slug = "test-destination-dupe-allowed"
    description = "Enables testing; allows duplicates"

    author = "Jasmine Schladen"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def allow_multiple_per_account(self):
        return True

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        return
