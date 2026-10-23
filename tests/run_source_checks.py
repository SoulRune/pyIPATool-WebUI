"""AGPL-3.0 section 13: every page links to /source (and to --repo-url when set);
/source is a zip of the running copy without caches, VCS data, vendored Unicorn
or anything from ~/.ipatool."""
import io
import os
import sys
import tempfile
import zipfile

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
os.environ.setdefault("IPATOOL_NO_VAULT_OFFER", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as appmod  # noqa: E402


def mkapp(*argv):
    return appmod.build_app(appmod.parse_args(list(argv)))


client = mkapp("--host", "127.0.0.1").test_client()
page = client.get("/", headers={"Host": "localhost:5002"}).get_data(as_text=True)
assert 'href="/source"' in page and "GNU AGPL-3.0" in page, page[-600:]
r = client.get("/source", headers={"Host": "localhost:5002"})
assert r.status_code == 200 and r.mimetype == "application/zip"
names = zipfile.ZipFile(io.BytesIO(r.data)).namelist()
for needed in ("LICENSE", "NOTICE", "app.py", "ipatool_api/routes/ui.py", "templates/layout.html", "vendor/README.md"):
    assert "pyIPATool-WebUI/" + needed in names, needed
assert not any("__pycache__" in n or "/.git/" in n or "vendor/unicorn/" in n or n.endswith(".pyc") for n in names)
assert not any("/.ipatool/" in n or n.endswith(("keychain.json", "cookies.lwp", ".key")) for n in names)

assert ">GitHub<" not in page and ">Repository<" not in page

client = mkapp("--host", "127.0.0.1", "--repo-url", "https://github.com/you/fork").test_client()
page = client.get("/", headers={"Host": "localhost:5002"}).get_data(as_text=True)
assert 'href="/source"' in page and 'href="https://github.com/you/fork"' in page and ">GitHub<" in page
client = mkapp("--host", "127.0.0.1", "--source-url", "https://example.org/my-fork").test_client()
page = client.get("/", headers={"Host": "localhost:5002"}).get_data(as_text=True)
assert 'href="/source"' in page and 'href="https://example.org/my-fork"' in page and ">Repository<" in page
print("SOURCE OK")
