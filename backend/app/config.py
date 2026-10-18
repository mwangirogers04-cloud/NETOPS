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

    # Authentication & JWT
    jwt_secret_key: str = "netops-enterprise-auth-jwt-secret-key-2026-min-32-chars!"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 1440
    frontend_base_url: str = "http://127.0.0.1:5173"

    # Notification / Email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from_email: str = "noreply@netops.local"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

