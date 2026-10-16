from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NETOPS"
    app_env: str = "development"
    debug: bool = True
    cors_origins: str = (
        "http://localhost:5173,"
        "http://127.0.0.1:5173,"
        "http://localhost:5174,"
        "http://127.0.0.1:5174"
    )

    database_url: str

    # Cisco switch integration
    switch_management_ip: str = ""
    switch_username: str = ""
    switch_password: str = ""
    switch_enable_secret: str = ""
    switch_allowed_ips: str = ""

    # Sophos firewall integration
    sophos_base_url: str = ""
    sophos_api_token: str = ""
    sophos_username: str = ""
    sophos_password: str = ""
    sophos_verify_tls: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

