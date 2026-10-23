"""SAP signer checks.

The integration test contacts Apple's live SAP setup endpoints and downloads
~32 MB of Apple frameworks on first run, so it is skipped unless
IPATOOL_SAP_LIVE=1 is set. It mirrors ipatool's own signer_integration_test.go
(same fixed hardware id and messages).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ipatool_api.services.sap import unicorn_available
from ipatool_api.services.sap.errors import SAPError
from ipatool_api.services.sap.signer import Signer, SignerConfig

_SETUP = "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy"
_CERT = "https://s.mzstatic.com/sap/setupCert.plist"
_HW = bytes([0x02, 0, 0, 0, 0, 1])


def _cfg(**overrides):
    base = dict(setup_url=_SETUP, certificate_url=_CERT, version=200, hardware_id=_HW)
    base.update(overrides)
    return SignerConfig(**base)


@pytest.mark.parametrize(
    "overrides, needle",
    [
        (dict(version=199), "version"),
        (dict(hardware_id=b""), "hardware"),
        (dict(hardware_id=b"x" * 21), "hardware"),
        (dict(setup_url="http://insecure/"), "HTTPS"),
    ],
)
def test_config_is_validated(overrides, needle):
    with pytest.raises(SAPError) as info:
        Signer(_cfg(**overrides))
    assert needle in str(info.value)


@pytest.mark.skipif(not os.getenv("IPATOOL_SAP_LIVE"), reason="set IPATOOL_SAP_LIVE=1 to hit Apple")
def test_live_handshake_and_signing():
    if not unicorn_available():
        pytest.skip("unicorn not installed")
    signer = Signer(_cfg())
    try:
        first = signer.sign(b"ipatool SAP smoke test")
        second = signer.sign(b"ipatool second SAP smoke test")
        assert first and second
        assert first != second  # each signature embeds a fresh nonce
    finally:
        signer.close()
    with pytest.raises(SAPError):
        signer.sign(b"after close")
