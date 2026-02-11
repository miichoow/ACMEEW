"""CA backend registry.

Loads the configured CA backend by name and returns an initialised
:class:`CABackend` instance.  Supports built-in backends (``internal``,
``external``) and custom backends via the ``ext:`` prefix.

Usage::

    from acmeeh.ca.registry import load_ca_backend

    backend = load_ca_backend(ca_settings)
    result = backend.sign(csr, profile=profile, validity_days=90)
"""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

from acmeeh.ca.base import CABackend, CAError

if TYPE_CHECKING:
    from acmeeh.config.settings import CASettings

log = logging.getLogger(__name__)

# Maps config string → (module_path, class_name)
_BUILTIN_BACKENDS: dict[str, tuple[str, str]] = {
    "internal": ("acmeeh.ca.internal", "InternalCABackend"),
    "external": ("acmeeh.ca.external", "ExternalCABackend"),
    "acme_proxy": ("acmeeh.ca.acme_proxy", "AcmeProxyBackend"),
    "hsm": ("acmeeh.ca.hsm", "HsmCABackend"),
}


def load_ca_backend(ca_settings: CASettings) -> CABackend:
    """Load and return the configured CA backend.

    Parameters
    ----------
    ca_settings:
        The ``ca`` section from :class:`AcmeehSettings`.

    Returns
    -------
    CABackend
        An initialised backend instance.

    Raises
    ------
    CAError
        If the backend cannot be loaded.

    """
    backend_name = ca_settings.backend

    if backend_name in _BUILTIN_BACKENDS:
        return _load_builtin(backend_name, ca_settings)
    if backend_name.startswith("ext:"):
        return _load_external(backend_name[4:], ca_settings)
    msg = (
        f"Unknown CA backend '{backend_name}'; "
        f"built-in options: {sorted(_BUILTIN_BACKENDS)}. "
        f"Use 'ext:mypackage.module.ClassName' for custom backends."
    )
    raise CAError(
        msg,
    )


def _load_builtin(name: str, ca_settings: CASettings) -> CABackend:
    """Load a built-in CA backend."""
    mod_path, cls_name = _BUILTIN_BACKENDS[name]

    try:
        module = importlib.import_module(mod_path)
        cls = getattr(module, cls_name)
    except (ImportError, AttributeError) as exc:
        msg = f"Failed to load built-in CA backend '{name}': {exc}"
        raise CAError(
            msg,
        ) from exc

    _validate_class(cls, name)
    backend = cls(ca_settings)
    log.info("Loaded CA backend: %s", name)
    return backend


def _load_external(fqn: str, ca_settings: CASettings) -> CABackend:
    """Load a custom CA backend by fully-qualified class name.

    Parameters
    ----------
    fqn:
        e.g. ``"mycompany.pki.backends.ADCSBackend"``

    """
    module_path, _, cls_name = fqn.rpartition(".")
    if not module_path:
        msg = (
            f"Invalid external CA backend '{fqn}': must be fully "
            "qualified (e.g. 'mypackage.module.ClassName')"
        )
        raise CAError(
            msg,
        )

    try:
        module = importlib.import_module(module_path)
        cls = getattr(module, cls_name)
    except (ImportError, AttributeError) as exc:
        msg = f"Failed to load external CA backend '{fqn}': {exc}"
        raise CAError(
            msg,
        ) from exc

    if not (isinstance(cls, type) and issubclass(cls, CABackend)):
        msg = f"External CA backend '{fqn}' must be a subclass of CABackend"
        raise CAError(
            msg,
        )

    _validate_class(cls, f"ext:{fqn}")
    backend = cls(ca_settings)
    log.info("Loaded external CA backend: %s", fqn)
    return backend


def _validate_class(cls: type, label: str) -> None:
    """Verify that a backend class has the required methods."""
    if not (isinstance(cls, type) and issubclass(cls, CABackend)):
        msg = f"CA backend '{label}' is not a subclass of CABackend"
        raise CAError(
            msg,
        )

    for method_name in ("sign", "revoke"):
        method = getattr(cls, method_name, None)
        if method is None or getattr(method, "__isabstractmethod__", False):
            msg = f"CA backend '{label}' does not implement '{method_name}()'"
            raise CAError(
                msg,
            )
