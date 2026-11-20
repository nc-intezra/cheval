#!/usr/bin/env python3
"""Regenerate tests/fixtures/rpm/sample/: repository metadata written by the real
createrepo_c (pip install createrepo_c), so cheval's parsers are tested against what the
tool actually emits. Packages are described, not built: the metadata is what matters.

    python3 tests/fixtures/rpm/make-sample.py tests/fixtures/rpm/sample
"""
import hashlib, os, shutil, sys
import createrepo_c as cr

out = sys.argv[1]
shutil.rmtree(out, ignore_errors=True)
rd = os.path.join(out, "repodata")
os.makedirs(rd)

PKGS = [  # name, arch, href, payload
    ("bash", "x86_64", "Packages/b/bash-5.1.8-9.el9.x86_64.rpm", b"bash payload"),
    ("tzdata", "noarch", "Packages/t/tzdata-2024a-1.el9.noarch.rpm", b"tzdata payload"),
    ("bash", "src", "Packages/b/bash-5.1.8-9.el9.src.rpm", b"source payload"),
    ("odd&name", "x86_64", "Packages/o/odd&name-1-1.el9.x86_64.rpm", b"needs escaping"),
]

def pkg(name, arch, href, payload):
    p = cr.Package()
    p.name, p.arch, p.epoch, p.version, p.release = name, arch, "0", "1.0", "1.el9"
    p.pkgId = hashlib.sha256(payload).hexdigest()
    p.checksum_type = "sha256"
    p.location_href = href
    p.size_package, p.size_installed, p.size_archive = len(payload), 10, 10
    p.summary, p.description, p.url, p.rpm_license = "s & t", "d", "https://example.org", "MIT"
    p.time_file = p.time_build = 1700000000
    p.provides = [(name, "EQ", "0", "1.0", "1.el9", False)]
    p.files = [("", "/usr/share/doc/", name)]
    p.changelogs = [("Someone <a@b> - 1.0-1", 1700000000, "- initial")]
    return p

files = {
    "primary": (cr.PrimaryXmlFile, os.path.join(rd, "primary.xml.gz")),
    "filelists": (cr.FilelistsXmlFile, os.path.join(rd, "filelists.xml.gz")),
    "other": (cr.OtherXmlFile, os.path.join(rd, "other.xml.gz")),
}
writers = {k: cls(path, cr.GZ_COMPRESSION) for k, (cls, path) in files.items()}
dbs = {k: getattr(cr, k.capitalize() + "Sqlite")(os.path.join(rd, k + ".sqlite")) for k in files}
for w in writers.values():
    w.set_num_of_pkgs(len(PKGS))
for spec in PKGS:
    p = pkg(*spec)
    for k, w in writers.items():
        w.add_pkg(p)
        dbs[k].add_pkg(p)
    os.makedirs(os.path.join(out, os.path.dirname(spec[2])), exist_ok=True)
    open(os.path.join(out, spec[2]), "wb").write(spec[3])
for w in writers.values():
    w.close()

repomd = cr.Repomd()
repomd.set_revision("1700000000")
for k, (_, path) in files.items():
    rec = cr.RepomdRecord(k, path)
    rec.fill(cr.SHA256)
    rec.rename_file()
    repomd.set_record(rec)
    db = dbs[k]
    db.dbinfo_update(rec.checksum)
    db.close()
    dbpath = os.path.join(rd, k + ".sqlite")
    comp = os.path.join(rd, k + ".sqlite.xz")
    cr.compress_file(dbpath, comp, cr.XZ_COMPRESSION)
    os.remove(dbpath)
    dbrec = cr.RepomdRecord(k + "_db", comp)
    dbrec.fill(cr.SHA256)
    dbrec.rename_file()
    repomd.set_record(dbrec)
comps = os.path.join(rd, "comps.xml")
open(comps, "w").write('<?xml version="1.0"?>\n<comps><group><id>core</id></group></comps>\n')
rec = cr.RepomdRecord("group", comps)
rec.fill(cr.SHA256)
rec.rename_file()
repomd.set_record(rec)
open(os.path.join(rd, "repomd.xml"), "w").write(repomd.xml_dump())
print("wrote", out)
