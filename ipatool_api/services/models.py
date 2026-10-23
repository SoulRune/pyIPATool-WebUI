"""Domain models for the iPatool service layer."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Account:
    email: str
    password_token: str
    directory_services_id: str
    name: str
    store_front: str
    password: Optional[str] = None
    pod: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Account":
        return cls(
            email=data.get("email", ""),
            password_token=data.get("passwordToken", ""),
            directory_services_id=data.get("directoryServicesIdentifier", ""),
            name=data.get("name", ""),
            store_front=data.get("storeFront", ""),
            password=data.get("password"),
            pod=data.get("pod"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "passwordToken": self.password_token,
            "directoryServicesIdentifier": self.directory_services_id,
            "name": self.name,
            "storeFront": self.store_front,
            "password": self.password,
            "pod": self.pod,
        }

    def to_public_dict(self) -> Dict[str, Any]:
        """What the browser may see (``to_dict()`` has the password and token)."""
        return {
            "email": self.email,
            "name": self.name,
            "storeFront": self.store_front,
        }


@dataclass
class App:
    id: int
    bundle_id: str = ""
    name: str = ""
    version: str = ""
    price: float = 0.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "App":
        return cls(
            id=int(data.get("trackId") or data.get("id", 0)),
            bundle_id=data.get("bundleId", ""),
            name=data.get("trackName", ""),
            version=data.get("version", ""),
            price=float(data.get("price", 0.0) or 0.0),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trackId": self.id,
            "bundleId": self.bundle_id,
            "trackName": self.name,
            "version": self.version,
            "price": self.price,
        }


@dataclass
class SAPConfig:
    """SAP signing configuration published in Apple's bag (sign-sap-*)."""

    setup_url: str
    certificate_url: str
    version: int


@dataclass
class BagOutput:
    auth_endpoint: str
    sap: Optional[SAPConfig] = None


@dataclass
class Sinf:
    id: int
    data: bytes

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Sinf":
        return cls(id=int(data.get("id", 0)), data=data.get("sinf", b""))


@dataclass
class SearchOutput:
    count: int
    results: List[App] = field(default_factory=list)


@dataclass
class DownloadOutput:
    destination_path: str
    sinfs: List[Sinf]


@dataclass
class ListVersionsOutput:
    external_version_identifiers: List[str]
    latest_external_version_id: str


@dataclass
class CommunityVersionEntry:
    """One entry from a third-party, crowd-sourced version-history database
    (currently: Timbrd, api.timbrd.com/apple/app-version/index.php). This is
    NOT an official Apple API - see AppStoreService.list_versions_community
    for the caveats."""

    external_version_id: str
    bundle_version: str
    created_at: Optional[str] = None
    size: Optional[int] = None
    source: str = "timbrd"
    # Private catalog only: ok / lost / unknown (see services/catalog.py).
    status: Optional[str] = None
    # Other catalogs that list the same id ("timbrd", "catalog-external:ok", ...).
    also_in: List[str] = field(default_factory=list)
    checked_at: Optional[str] = None
    # Private catalog only (when the collector recorded them).
    build: Optional[str] = None
    minimum_os: Optional[str] = None
    release_date_display: Optional[str] = None
    artist: Optional[str] = None
    genre: Optional[str] = None
    age_rating: Optional[str] = None
    copyright: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "build": self.build,
            "minimumOs": self.minimum_os,
            "releaseDateDisplay": self.release_date_display,
            "artist": self.artist,
            "genre": self.genre,
            "ageRating": self.age_rating,
            "copyright": self.copyright,
            "externalVersionId": self.external_version_id,
            "bundleVersion": self.bundle_version,
            "createdAt": self.created_at,
            "size": self.size,
            "source": self.source,
            "status": self.status,
            "alsoIn": list(self.also_in),
            "checkedAt": self.checked_at,
        }


@dataclass
class CommunityVersionsOutput:
    source: str
    entries: List[CommunityVersionEntry] = field(default_factory=list)


@dataclass
class GetVersionMetadataOutput:
    display_version: str
    build_number: str
    release_date: Optional[datetime]
    release_date_display: str
    file_size: int
    bundle_id: str
    artist_name: str
    item_name: str
    genre: str
    age_rating: str
    requires_rosetta: bool
    runs_on_apple_silicon: bool
    copyright_info: str
    minimum_os: str = ""        # e.g. "15.0", from the version's Info.plist; "" if unknown
    minimum_os_name: str = ""   # "iOS", "tvOS", "watchOS", "macOS"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "minimumOsVersion": self.minimum_os,
            "minimumOsName": self.minimum_os_name,
            "displayVersion": self.display_version,
            "buildNumber": self.build_number,
            "releaseDate": self.release_date.isoformat() if self.release_date else None,
            "releaseDateDisplay": self.release_date_display,
            "fileSize": self.file_size,
            "bundleId": self.bundle_id,
            "artistName": self.artist_name,
            "itemName": self.item_name,
            "genre": self.genre,
            "ageRating": self.age_rating,
            "requiresRosetta": self.requires_rosetta,
            "runsOnAppleSilicon": self.runs_on_apple_silicon,
            "copyright": self.copyright_info,
        }
