from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
import os


VALID_NETWORK_MODES = {"offline", "manual", "scheduled"}
LOCAL_OLLAMA_HOSTS = {"localhost", "127.0.0.1", "host.docker.internal", "::1"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    data_directory: Path
    network_mode: str
    ollama_endpoint: str
    ollama_chat_model: str
    ollama_embedding_model: str
    ai_provider: str
    external_ai_enabled: bool
    external_ai_base_url: str
    external_ai_api_key: str
    external_ai_model: str
    connector_allowlist: tuple[str, ...]


def local_ollama_endpoint(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in LOCAL_OLLAMA_HOSTS:
        raise ValueError("OLLAMA_ENDPOINT must be an http URL for localhost or host.docker.internal only")
    return value.rstrip("/")


def get_settings() -> Settings:
    mode = os.getenv("NETWORK_MODE", "manual").lower()
    if mode not in VALID_NETWORK_MODES:
        mode = "manual"
    endpoint = local_ollama_endpoint(os.getenv("OLLAMA_ENDPOINT", "http://host.docker.internal:11434"))
    data_directory = Path(os.getenv("DATA_DIRECTORY", "./data")).resolve()
    data_directory.mkdir(parents=True, exist_ok=True)
    return Settings(
        database_url=os.environ["DATABASE_URL"],
        data_directory=data_directory,
        network_mode=mode,
        ollama_endpoint=endpoint,
        ollama_chat_model=os.getenv("OLLAMA_CHAT_MODEL", ""),
        ollama_embedding_model=os.getenv("OLLAMA_EMBEDDING_MODEL", ""),
        ai_provider=os.getenv("AI_PROVIDER", "ollama").strip().lower(),
        external_ai_enabled=os.getenv("EXTERNAL_AI_ENABLED", "false").strip().lower() == "true",
        external_ai_base_url=os.getenv("EXTERNAL_AI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
        external_ai_api_key=os.getenv("EXTERNAL_AI_API_KEY", ""),
        external_ai_model=os.getenv("EXTERNAL_AI_MODEL", ""),
        connector_allowlist=tuple(host.strip().lower() for host in os.getenv("CONNECTOR_ALLOWLIST", "").split(",") if host.strip()),
    )
