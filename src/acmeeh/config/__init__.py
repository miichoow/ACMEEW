"""Configuration subsystem for ACMEEH.

Public API::

    from acmeeh.config import get_config, AcmeehConfig

    # At startup (CLI only):
    AcmeehConfig(config_file="config.yaml")

    # Everywhere else:
    cfg   = get_config()
    port  = cfg.settings.server.port       # typed access
    custom = cfg.get("ca.vault.url")       # dynamic dot-path
"""

from acmeeh.config.acmeeh_config import (
    AcmeehConfig,
    ConfigValidationError,
    get_config,
)
from acmeeh.config.settings import (
    AcmeehSettings,
    AcmePathSettings,
    AcmeSettings,
    ApiSettings,
    AuditLogSettings,
    CAInternalSettings,
    CAProfileSettings,
    CASettings,
    ChallengeSettings,
    DatabaseSettings,
    Dns01Settings,
    DnsSettings,
    EmailSettings,
    HookEntrySettings,
    HookSettings,
    Http01Settings,
    IdentifierPolicySettings,
    LoggingSettings,
    NonceSettings,
    OrderSettings,
    ProxySettings,
    RateLimitRule,
    RateLimitSettings,
    SecuritySettings,
    ServerSettings,
    SmtpSettings,
    TlsAlpn01Settings,
    TosSettings,
)

__all__ = [
    "AcmePathSettings",
    "AcmeSettings",
    # Core
    "AcmeehConfig",
    # Root
    "AcmeehSettings",
    "ApiSettings",
    "AuditLogSettings",
    "CAInternalSettings",
    "CAProfileSettings",
    "CASettings",
    "ChallengeSettings",
    "ConfigValidationError",
    "DatabaseSettings",
    "Dns01Settings",
    "DnsSettings",
    "EmailSettings",
    "HookEntrySettings",
    "HookSettings",
    "Http01Settings",
    "IdentifierPolicySettings",
    "LoggingSettings",
    "NonceSettings",
    "OrderSettings",
    "ProxySettings",
    "RateLimitRule",
    "RateLimitSettings",
    "SecuritySettings",
    # Sections
    "ServerSettings",
    "SmtpSettings",
    "TlsAlpn01Settings",
    "TosSettings",
    "get_config",
]
