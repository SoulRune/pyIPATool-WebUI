"""Exception hierarchy for the App Store service layer."""

from __future__ import annotations

from typing import Any, Optional


class AppStoreError(RuntimeError):
    """Base error that carries optional metadata from upstream responses."""

    def __init__(self, message: str, *, metadata: Optional[Any] = None) -> None:
        super().__init__(message)
        self.metadata = metadata


class AuthCodeRequiredError(AppStoreError):
    pass


class PasswordTokenExpiredError(AppStoreError):
    pass


class LicenseRequiredError(AppStoreError):
    pass


ARCADE_VERSIONS_UNAVAILABLE_MESSAGE = (
    "Apple didn't return the version list for this Apple Arcade game ({reason}). Shown instead: "
    "versions known to third-party community catalogs (Timbrd, bilin) - downloads of them still go "
    "through Apple and may or may not be served for Arcade games."
)
ARCADE_NOT_SUPPORTED_MESSAGE = ARCADE_VERSIONS_UNAVAILABLE_MESSAGE.format(reason="no details")
APPS_SITE_RATE_LIMITED_MESSAGE = (
    "Couldn't find this game's current version: Apple Arcade games are only listed on apps.apple.com, "
    "and it is rate-limiting this server's IP right now (HTTP 429, usually for a few minutes). "
    "Try again in a few minutes. Once the version list has loaded once, the server remembers a version "
    "of the game and doesn't need apps.apple.com for it any more. Shown instead: versions known to "
    "community catalogs."
)

ARCADE_REFUSED_MESSAGE = (
    "Apple refused to issue this Apple Arcade game to this account (\"subscription required\"). "
    "Apple sometimes refuses Arcade games through the route this tool uses even with an active "
    "subscription - there's no workaround for that here."
)


class ArcadeNotSupportedError(AppStoreError):
    """The request needs something Apple doesn't serve for Apple Arcade games
    (version list, an older version) - see ARCADE_NOT_SUPPORTED_MESSAGE.
    ``latest_version_id``: the current version, which *can* be downloaded."""

    def __init__(self, message: str = ARCADE_NOT_SUPPORTED_MESSAGE, metadata=None, latest_version_id: str = "") -> None:
        super().__init__(message, metadata=metadata)
        self.latest_version_id = latest_version_id


ARCADE_NOT_SUBSCRIBED_MESSAGE = (
    "Apple answered \"Subscription Required\" for this Apple Arcade game version. Over the route this "
    "tool uses (Apple Configurator's download endpoints) Apple often doesn't see the account's Arcade "
    "subscription, and getting the game again doesn't help (Apple then says \"not for sale\"). Some "
    "other versions of the game may still be served - try them from the list."
)


class ArcadeRefusedError(ArcadeNotSupportedError):
    """Apple refused the Arcade game itself (purchase/download)."""

    def __init__(self, message: str = ARCADE_REFUSED_MESSAGE, metadata=None) -> None:
        super().__init__(message, metadata=metadata)


class TemporarilyUnavailableError(AppStoreError):
    pass


class SubscriptionRequiredError(AppStoreError):
    pass


class PlatformLookupEmptyError(AppStoreError):
    """The MDM platform lookup had no entry (or no offer) for the app in this
    storefront/catalog (ipatool errPlatformAppNotFound / errPlatformOffersNotFound)."""


class AppNotFoundError(AppStoreError):
    """iTunes lookup by bundle id found nothing (ipatool ErrAppNotFound)."""


class VersionNotServedError(AppStoreError):
    """Apple answered, but only with a different (current) version: the
    requested one isn't available to this account any more."""
