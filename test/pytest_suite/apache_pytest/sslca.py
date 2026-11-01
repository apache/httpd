"""Compatibility re-export: the CA generator now lives in :mod:`pyhttpd.sslca`."""

from pyhttpd.sslca import (  # noqa: F401
    CA_DN,
    CERT_DN,
    DAYS,
    EMAIL_FIELD,
    PASS,
    SSLCA,
)
