from lemur.plugins.bases import SourcePlugin


class TestSourcePlugin(SourcePlugin):
    title = "Test"
    slug = "test-source"
    description = "Enables testing"

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        super(TestSourcePlugin, self).__init__(*args, **kwargs)

        self.certificates = []

    def get_certificates(self, *args, **kwargs):
        return self.certificates

    def update_endpoint(self, endpoint, certificate):
        return
