"""OTA install checks against a faked Apple backend: python tests/run_ota_checks.py"""
import os, sys, time, plistlib, io, zipfile, struct, zlib, tempfile
from urllib.parse import unquote, urlparse
HOME=tempfile.mkdtemp(); os.environ["HOME"]=HOME; os.environ["USERPROFILE"]=HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_webui_checks.py")).read().split("# ---- browser mode")[0])  # reuse fakes
bapp = mkapp("--host", "0.0.0.0")
A = bapp.test_client()
assert A.post("/api/auth/login", json={"email":"ann@example.com","password":"pw"}).status_code == 200
jid = A.post("/api/download-jobs", json={"appId": 42, "externalVersionId": "2"}).get_json()["jobId"]
for _ in range(50):
    j = A.get(f"/api/download-jobs/{jid}").get_json()
    if j["status"] in ("ready","error"): break
    time.sleep(0.1)
assert j["status"]=="ready", j
print("installUrl:", j["installUrl"][:60]+"...", "| otaNeedsHttps:", j["otaNeedsHttps"])
manifest_url = unquote(j["installUrl"].split("url=",1)[1]); assert manifest_url == j["manifestUrl"]
iOS = bapp.test_client()  # the iOS installer: no session cookie
path = urlparse(manifest_url).path
r = iOS.get(path); assert r.status_code==200 and r.mimetype=="text/xml", r.status_code
m = plistlib.loads(r.data)["items"][0]
print("manifest:", m["metadata"], "| asset:", m["assets"][0]["url"].rsplit("/",1)[-1])
ipa_path = urlparse(m["assets"][0]["url"]).path
full = iOS.get(ipa_path); assert full.status_code==200
part = iOS.get(ipa_path, headers={"Range":"bytes=100-199"}); assert part.status_code==206 and part.data==full.data[100:200]
print("ipa:", len(full.data), "bytes; Range -> 206 OK")
# wrong token / other job id
bad = path.replace(path.split("/")[3], "WRONGTOKEN"); assert iOS.get(bad).status_code==404
assert iOS.get(f"/api/download-jobs/{jid}").status_code==404  # other session still can't poll
# streaming walk of the delivered IPA
def stream_walk(data):
    f=io.BytesIO(data); n=0
    while True:
        sig=struct.unpack("<I",f.read(4))[0]
        if sig==0x02014b50: return n
        assert sig==0x04034b50
        ver,flags,method,t,d,crc,cs,us,nl,el=struct.unpack("<HHHHHIIIHH",f.read(26)); f.read(nl+el)
        if flags & 8:
            dec=zlib.decompressobj(-15); out=b""
            while not dec.eof: out+=dec.decompress(f.read(1))
            f.seek(-len(dec.unused_data),1); dsig,dcrc,_,dus=struct.unpack("<IIII",f.read(16))
            assert dsig==0x08074b50 and dcrc==zlib.crc32(out)
        else:
            body=f.read(cs); assert zlib.crc32(body)==crc
        n+=1
z=zipfile.ZipFile(io.BytesIO(full.data))
print("streamed entries:", stream_walk(full.data), "/", len(z.infolist()), "| names:", [n.rsplit('/',1)[-1] for n in z.namelist()])
print("OTA OK")
