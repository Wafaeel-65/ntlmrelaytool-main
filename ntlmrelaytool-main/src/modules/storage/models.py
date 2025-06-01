from datetime import datetime
from typing import Optional

class Target:
    def __init__(self, id: Optional[int] = None, host: str = None, port: int = None,
                 username: str = None, hash: str = None):
        self.id = id
        self.host = host
        self.port = port
        self.username = username
        self.hash = hash
        self.created_at = datetime.now()

class NTLMCapture:
    def __init__(self, source: str, destination: str, username: Optional[str] = None,
                 domain: Optional[str] = None, ntlm_type: int = 0, payload: str = None):
        self.source = source
        self.destination = destination
        self.username = username
        self.domain = domain
        self.ntlm_type = ntlm_type
        self.payload = payload
        self.capture_time = datetime.now()

class Credential:
    def __init__(self, username: str, hash: str, id: Optional[int] = None):
        self.id = id
        self.username = username
        self.ntlm_hash = hash
        self.created_at = datetime.now()

class Plugin:
    def __init__(self, nom_plugin: str, description: str, version: str, ntlm_key: str = None, source_ip: str = None, request_name: str = None):
        self.nom_plugin = nom_plugin
        self.description = description
        self.version = version
        self.ntlm_key = ntlm_key
        self.source_ip = source_ip
        self.request_name = request_name
        self.date_creation = datetime.now()

class Utilisateur:
    def __init__(self, username: str, role: str):
        self.username = username
        self.role = role
        self.created_at = datetime.now()

class Execute:
    def __init__(self, plugin_id: int, target: str, status: str):
        self.plugin_id = plugin_id
        self.target = target
        self.status = status
        self.execute_time = datetime.now()

class Resultat:
    def __init__(self, execute_id: int, output: str):
        self.execute_id = execute_id
        self.output = output
        self.created_at = datetime.now()