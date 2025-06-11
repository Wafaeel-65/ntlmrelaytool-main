import pytest
from datetime import datetime
from src.modules.storage.models import Target, Credential, Plugin, Utilisateur
from src.modules.storage.database import Database

class TestDatabase:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.db = Database(":memory:")
        
    def test_execute_query(self):
        result = self.db.execute_query("SELECT 1")
        assert result == [(1,)]

class TestModels:
    def test_target_model(self):
        target = Target(username='test_user', hash='test_hash')
        assert target.username == 'test_user'
        assert target.hash == 'test_hash'

    def test_credential_model(self):
        credential = Credential(username='test_user', hash='test_hash')
        assert credential.username == 'test_user'
        assert credential.ntlm_hash == 'test_hash'

    def test_plugin_model(self):
        plugin = Plugin(
            nom_plugin="Test Plugin",
            description="Test Description",
            version="1.0",
            ntlm_key="test_key"
        )
        assert plugin.nom_plugin == "Test Plugin"
        assert plugin.description == "Test Description"
        assert plugin.version == "1.0"
        assert plugin.ntlm_key == "test_key"
        assert isinstance(plugin.date_creation, datetime)

    def test_utilisateur_model(self):
        user = Utilisateur(
            username="Test User",
            role="admin"
        )
        assert user.username == "Test User"
        assert user.role == "admin"
        assert isinstance(user.created_at, datetime)