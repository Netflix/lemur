from lemur.tests.conftest import *  # noqa


@pytest.fixture
def vault_source_plugin():
    from lemur.plugins.base import register
    from lemur.plugins.lemur_vault_dest.tests.plugin import TestSourcePlugin

    register(TestSourcePlugin)
    return TestSourcePlugin
