// Tests for path/linkpath sanitization CVEs.
// Adapted from upstream test/ghsa-8qq5-rm4j-mr97.ts for 2.2.1's API (tap 0.x + tar.Extract).
// Each CVE's patch adds its own tests to this file.

var tap = require("tap")
var tar = require("../tar.js")
var TarHeader = require("../lib/header.js")
var fs = require("fs")
var path = require("path")
var rimraf = require("rimraf")
var mkdirp = require("mkdirp")

var target = path.resolve(__dirname, "tmp/ghsa-8qq5")
var tarFile = path.resolve(__dirname, "tmp/ghsa-8qq5.tar")

function makeHeader(props) {
  return TarHeader.encode({
    path: props.path, mode: props.mode || 0644, uid: 0, gid: 0,
    size: props.size || 0, mtime: 0, cksum: 0, type: props.type,
    linkpath: props.linkpath || '', ustar: 'ustar\0', ustarver: '00',
    uname: '', gname: '', devmaj: 0, devmin: 0, fill: ''
  })
}

function zeroes(size) {
  var buf = new Buffer(size)
  for (var i = 0; i < size; i++) buf[i] = 0
  return buf
}

function buildTar(entries) {
  var chunks = []
  for (var i = 0; i < entries.length; i++) {
    chunks.push(makeHeader(entries[i]))
    // optional entry body, padded out to whole 512-byte blocks
    var body = entries[i].body
    if (body) {
      if (!Buffer.isBuffer(body)) body = new Buffer(body)
      var padded = zeroes(Math.ceil(body.length / 512) * 512)
      body.copy(padded)
      chunks.push(padded)
    }
  }
  // eof is two blocks of nulls
  chunks.push(zeroes(1024))
  return Buffer.concat(chunks)
}

tap.test("preclean", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  mkdirp.sync(path.dirname(tarFile))
  t.pass("cleaned")
  t.end()
})

// CVE-2026-29786: drive-relative path c:../escape.txt is rejected
// The fix reorders: strip absolute root THEN check '..'.
// Before: c:../foo split to ['c:..', 'foo'] — no '..' match, not caught on Linux.
// After: strip 'c:' root → '../foo' → split → '..' detected → rejected.
tap.test("CVE-2026-29786: drive-relative path c:../escape.txt is rejected", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var escapeFile = path.resolve(target, "..", "cve29786-escape-" + process.pid + ".txt")

  var tarBuf = buildTar([
    { path: "c:../cve29786-escape-" + process.pid + ".txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var exists = false
      try { fs.lstatSync(escapeFile); exists = true } catch (e) {}
      t.equal(exists, false,
        "c:../escape file should not be created outside target")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-29786: absolute path with '..' is stripped before '..' check
// /../a/target: strip '/' → '../a/target' → '..' detected → rejected (for path).
tap.test("CVE-2026-29786: absolute path with embedded '..' is rejected after stripping", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)

  var tarBuf = buildTar([
    { path: "/../a/target.txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      // '../a/target.txt' should be rejected because '..' in path
      var exists = false
      try { fs.lstatSync(path.resolve(target, "../a/target.txt")); exists = true } catch (e) {}
      t.equal(exists, false,
        "/../a/target.txt should be rejected after stripping root")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: hardlink with '..' linkpath does not link to external file
tap.test("CVE-2026-23745: hardlink with '..' linkpath does not link to external file", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretFile = path.resolve(target, "..", "ghsa-secret-" + process.pid + ".txt")
  fs.writeFileSync(secretFile, "ORIGINAL DATA")
  var secretInode = fs.lstatSync(secretFile).ino

  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    { path: "sub/exploit_sub", type: "1", linkpath: "../ghsa-secret-" + process.pid + ".txt" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exploitPath = path.resolve(target, "sub/exploit_sub")
    try {
      var exploitStat = fs.lstatSync(exploitPath)
      t.notEqual(exploitStat.ino, secretInode,
        "exploit_sub must not share inode with external secret (hardlink blocked)")
    } catch (e) {
      t.pass("exploit_sub was not created at all (hardlink blocked)")
    }
    t.equal(fs.readFileSync(secretFile, 'utf8'), "ORIGINAL DATA",
      "external secret file must remain unchanged")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-23745: absolute linkpath has root stripped
tap.test("CVE-2026-23745: absolute linkpath has root stripped", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/abs_sym", type: "2", linkpath: "/some/absolute/path" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "a/abs_sym"))
        t.notEqual(linkTarget, "/some/absolute/path",
          "absolute symlink target should have been stripped")
        t.equal(linkTarget.charAt(0) !== "/", true,
          "stripped symlink target should be relative: got " + linkTarget)
      } catch (err) {
        t.fail("symlink should have been created with stripped linkpath: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: writeFileSync through extracted hardlink does not modify external secret
tap.test("CVE-2026-23745: writeFileSync through extracted hardlink does not modify external secret", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretFile = path.resolve(target, "..", "ghsa-writefile-" + process.pid + ".txt")
  fs.writeFileSync(secretFile, "ORIGINAL DATA")

  var tarBuf = buildTar([
    { path: "exploit_hard", type: "1", linkpath: secretFile }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exploitPath = path.resolve(target, "exploit_hard")
    try { fs.writeFileSync(exploitPath, "OVERWRITTEN") } catch (e) {}
    t.equal(fs.readFileSync(secretFile, 'utf8'), "ORIGINAL DATA",
      "external secret must NOT be modified via extracted hardlink (writeFileSync exploit)")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-23745 + sub-directory variant: writeFileSync through sub/exploit_sub
tap.test("CVE-2026-23745: writeFileSync through sub/exploit_sub does not modify external secret", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretName = "ghsa-subwrite-" + process.pid + ".txt"
  var secretFile = path.resolve(target, "..", secretName)
  fs.writeFileSync(secretFile, "SECRET DATA")

  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    { path: "sub/exploit_sub", type: "1", linkpath: "../" + secretName }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exploitPath = path.resolve(target, "sub/exploit_sub")
    try { fs.writeFileSync(exploitPath, "OVERWRITTEN") } catch (e) {}
    t.equal(fs.readFileSync(secretFile, 'utf8'), "SECRET DATA",
      "external secret must NOT be modified via sub/exploit_sub writeFileSync")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-29786: escape-attempting drive-relative symlink linkpath (4+ levels of '..')
// After stripping 'c:', linkpath contains enough '..' to escape — rejected or neutered.
tap.test("CVE-2026-29786: escape-attempting drive-relative symlink linkpath is handled", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/winrootdotsescapelink", type: "2", linkpath: "c:..\\..\\..\\..\\foo\\bar" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var linkPath = path.resolve(target, "a/winrootdotsescapelink")
      try {
        var linkTarget = fs.readlinkSync(linkPath)
        t.equal(linkTarget.indexOf("c:"), -1,
          "drive prefix stripped even for escape-attempting linkpath: got " + linkTarget)
      } catch (err) {
        t.pass("escape-attempting symlink not created: " + err.code)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: '..' is only rejected for hardlinks, because a symlink target is
// relative to the entry's own directory.  An escaping symlink target must still be
// neutered so the link can never point outside of the extraction directory.
tap.test("CVE-2026-23745: escaping symlink linkpath cannot point outside the extraction dir", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/esc_sym", type: "2", linkpath: "../../../../etc/passwd" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var linkPath = path.resolve(target, "a/esc_sym")
      var linkTarget
      try {
        linkTarget = fs.readlinkSync(linkPath)
      } catch (err) {
        t.pass("escaping symlink was not created: " + err.code)
        t.end()
        return
      }
      var resolved = path.resolve(path.dirname(linkPath), linkTarget)
      t.equal(resolved === target || resolved.indexOf(target + "/") === 0, true,
        "symlink target must stay inside the extraction dir: got " + resolved)
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: a sibling directory whose name merely starts with the extraction
// dir's name (eg /tmp/target-evil next to /tmp/target) is outside the target, so a
// symlink pointing into it must be re-rooted rather than treated as contained.
tap.test("CVE-2026-23745: sibling-prefix symlink linkpath cannot escape the extraction dir", function (t) {
  rimraf.sync(target)
  var evilDir = target + "-evil"
  rimraf.sync(evilDir)
  var tarBuf = buildTar([
    { path: "s", type: "2", linkpath: "../" + path.basename(target) + "-evil/passwd" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var linkPath = path.resolve(target, "s")
      var linkTarget
      try {
        linkTarget = fs.readlinkSync(linkPath)
      } catch (err) {
        t.pass("sibling-prefix symlink was not created: " + err.code)
        rimraf.sync(evilDir)
        t.end()
        return
      }
      var resolved = path.resolve(path.dirname(linkPath), linkTarget)
      t.equal(resolved === target || resolved.indexOf(target + "/") === 0, true,
        "symlink must not resolve into a sibling dir sharing the target's name prefix: got " + resolved)
      rimraf.sync(evilDir)
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: a relative symlink that stays inside the extraction dir keeps
// working — the '..' rejection must not break legitimate archives.
tap.test("CVE-2026-23745: relative symlink linkpath inside the target is preserved", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/rel_sym", type: "2", linkpath: "../x" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "a/b/rel_sym"))
        t.equal(linkTarget, "../x",
          "relative symlink pointing inside the target is preserved")
      } catch (err) {
        t.fail("relative symlink should have been created: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-31802: drive-prefix path cleaned via parts.join before resolve
tap.test("CVE-2026-31802: drive-prefix path cleaned via parts.join before resolve", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "c:foo/inner.txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var expected = path.resolve(target, "foo/inner.txt")
      var exists = false
      try { fs.statSync(expected); exists = true } catch (e) {}
      t.equal(exists, true,
        "drive-prefix 'c:foo/inner.txt' should extract to target/foo/inner.txt after stripping")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

function runChainExploitTest(t, linkType, typeName) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var exploitedName = "exploited-" + typeName + "-" + process.pid + ".txt"
  var exploitedFile = path.resolve(target, "..", exploitedName)
  fs.writeFileSync(exploitedFile, "original content")

  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/up", type: "2", linkpath: "../.." },
    { path: "a/b/escape", type: "2", linkpath: "up/.." },
    { path: "exploit", type: linkType, linkpath: "a/b/escape/" + exploitedName }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    try { fs.writeFileSync(path.resolve(target, "exploit"), "pwned") } catch (e) {}
    t.equal(fs.readFileSync(exploitedFile, 'utf8'), "original content",
      "external exploited-file must NOT be modified via " + typeName + " chain")
    try { fs.unlinkSync(exploitedFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
}

tap.test("CVE-2026-26960: symlink chain exploit blocked (Link type)", function (t) {
  runChainExploitTest(t, "1", "Link")
})

tap.test("CVE-2026-26960: symlink chain exploit blocked (SymbolicLink type)", function (t) {
  runChainExploitTest(t, "2", "SymbolicLink")
})

// CVE-2026-26960: the advisory's own PoC shape.  Each hop of the chain passes the
// string-based containment check on its own (a/b/c/up resolves to a, a/b/escape
// resolves to a/b), but on disk a/b/escape lands above the extraction dir, and the
// hardlink target is resolved through it.
tap.test("CVE-2026-26960: advisory PoC hardlink through a two-hop symlink chain is blocked", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretName = "cve26960-poc-secret-" + process.pid + ".txt"
  var secretFile = path.resolve(target, "..", secretName)
  fs.writeFileSync(secretFile, "ORIGINAL DATA")
  var secretInode = fs.lstatSync(secretFile).ino

  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/c/", type: "5", mode: 0755 },
    { path: "a/b/c/up", type: "2", linkpath: "../.." },
    { path: "a/b/escape", type: "2", linkpath: "c/up/../.." },
    { path: "exfil", type: "1", linkpath: "a/b/escape/" + secretName }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exfil = path.resolve(target, "exfil")
    try {
      t.notEqual(fs.lstatSync(exfil).ino, secretInode,
        "exfil must not share an inode with the external secret")
    } catch (e) {
      t.pass("exfil was not created at all (symlink chain blocked)")
    }
    try { fs.writeFileSync(exfil, "OVERWRITTEN") } catch (e) {}
    t.equal(fs.readFileSync(secretFile, 'utf8'), "ORIGINAL DATA",
      "external secret must NOT be modified through the symlink chain")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-26960: a plain file entry nested under the escaping symlink must not be
// written through it either — the escape is not limited to link entries.
tap.test("CVE-2026-26960: plain file entry cannot be written through a symlink chain", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var pocName = "cve26960-through-" + process.pid + ".txt"
  var outside = path.resolve(target, "..", pocName)
  try { fs.unlinkSync(outside) } catch (e) {}

  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/up", type: "2", linkpath: "../.." },
    { path: "a/b/escape", type: "2", linkpath: "up/.." },
    { path: "a/b/escape/" + pocName, type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var escaped = false
    try { fs.lstatSync(outside); escaped = true } catch (e) {}
    t.equal(escaped, false,
      "file entry must not be written outside the extraction dir through the symlink chain")
    try { fs.unlinkSync(outside) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-26960 regression guard: recording a symlink must not block its siblings
// or any other legitimate in-tree entry.
tap.test("CVE-2026-26960: legitimate entries still extract alongside a recorded symlink", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)

  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/x", type: "0", size: 0 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/y", type: "2", linkpath: "../x" },
    { path: "a/b/z", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var xExists = false
    try { fs.lstatSync(path.resolve(target, "a/x")); xExists = true } catch (e) {}
    t.equal(xExists, true, "a/x still extracted")
    try {
      t.equal(fs.readlinkSync(path.resolve(target, "a/b/y")), "../x",
        "legitimate in-tree symlink still created")
    } catch (err) {
      t.fail("legitimate in-tree symlink should have been created: " + err.message)
    }
    var zExists = false
    try { fs.lstatSync(path.resolve(target, "a/b/z")); zExists = true } catch (e) {}
    t.equal(zExists, true, "sibling of a recorded symlink still extracted")
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-53655 (GHSA-vmf3-w455-68vh): tar file smuggling by applying a
// pending PAX/GNU extended header to an intermediary metadata block.
//
// A PAX extended header describes the *next file entry*, not the metadata
// blocks that may sit between it and that file.  node-tar used to apply the
// pending fields to any block that was not one of the handful of types it
// recognized as meta, so a crafted "size" record was honored by blocks such
// as SparseFile / TapeVolumeHeader / SolarisACL / an unrecognized type flag.
// Since the size decides where the next 512-byte header is looked for, that
// let the block swallow the entries that followed: node-tar never saw them,
// while GNU tar / libarchive / python tarfile did.

// build a PAX record: "%d %s=%s\n", <length>, <keyword>, <value>
// where <length> counts itself.
function paxRecord(key, val) {
  var tail = " " + key + "=" + val + "\n"
  var len = tail.length + 1
  while (String(len).length + tail.length > len) len++
  return String(len) + tail
}

// run a tarball through tar.Parse() and collect everything it reports.
function parseTar(tarBuf, cb) {
  mkdirp.sync(path.dirname(tarFile))
  fs.writeFileSync(tarFile, tarBuf)
  var events = []
  var errors = []
  var parser = tar.Parse()

  parser.on("*", function (ev, entry) {
    var seen = { event: ev
               , path: entry.props.path
               , type: entry.props.type
               , size: entry.props.size
               , data: "" }
    events.push(seen)
    entry.on("data", function (c) { seen.data += c.toString() })
  })
  parser.on("error", function (er) { errors.push(er) })
  parser.on("end", function () { cb(events, errors) })

  // feed it by hand rather than with pipe(): pipe() tears itself down on the
  // first "error", so a parser that desynchronizes would hang the test
  // instead of failing it.
  var rs = fs.createReadStream(tarFile)
  rs.on("data", function (c) { parser.write(c) })
  rs.on("end", function () { parser.end() })
}

function firstEvent(events, ev) {
  for (var i = 0; i < events.length; i++) {
    if (events[i].event === ev) return events[i]
  }
  return null
}

// every type flag that falls through to the "ignoredEntry" branch
var smuggleTypes =
  [ { type: "A", name: "SolarisACL" }
  , { type: "I", name: "Inode" }
  , { type: "M", name: "ContinuationFile" }
  , { type: "S", name: "SparseFile" }
  , { type: "V", name: "TapeVolumeHeader" }
  , { type: "Q", name: "unrecognized type flag" }
  ]

smuggleTypes.forEach(function (meta) {
  tap.test("CVE-2026-53655: extended header size is not applied to a " +
           meta.name + " block", function (t) {
    var pax = paxRecord("size", 1024)
    var tarBuf = buildTar(
      [ { path: "PaxHeaders/smuggle", type: "x", size: pax.length, body: pax }
      , { path: "smuggle-" + meta.type, type: meta.type, size: 0 }
      , { path: "real.txt", type: "0", size: 4, body: "REAL" }
      ])

    parseTar(tarBuf, function (events, errors) {
      t.equal(errors.length, 0, "tarball parses without error")

      var ignored = firstEvent(events, "ignoredEntry")
      t.ok(ignored, meta.name + " block is seen as an ignored entry")
      if (ignored) {
        t.equal(ignored.size, 0,
          meta.name + " keeps the size from its own header, not the PAX size")
      }

      var real = firstEvent(events, "entry")
      t.ok(real, "the file after the " + meta.name +
        " block is still parsed, not smuggled past the parser")
      if (real) {
        t.equal(real.path, "real.txt", "smuggled entry has the expected path")
        t.equal(real.size, 4, "smuggled entry has its own size")
        t.equal(real.data, "REAL", "smuggled entry has its own contents")
      }
      t.end()
    })
  })
})

// same smuggling primitive, driven by a global extended header, which sticks
// around for the whole archive instead of just the next entry.
tap.test("CVE-2026-53655: global extended header size is not applied to a " +
         "SparseFile block", function (t) {
  var gex = paxRecord("size", 1024)
  var body = "REAL" + new Array(1021).join("A")
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/global", type: "g", size: gex.length, body: gex }
    , { path: "smuggle-S", type: "S", size: 0 }
    , { path: "real.txt", type: "0", size: 4, body: body }
    ])

  parseTar(tarBuf, function (events, errors) {
    t.equal(errors.length, 0, "tarball parses without error")

    var ignored = firstEvent(events, "ignoredEntry")
    t.ok(ignored, "SparseFile block is seen as an ignored entry")
    if (ignored) {
      t.equal(ignored.size, 0,
        "SparseFile keeps its own size, not the global extended header size")
    }

    var real = firstEvent(events, "entry")
    t.ok(real, "the file after the SparseFile block is still parsed")
    if (real) {
      t.equal(real.path, "real.txt", "smuggled entry has the expected path")
      // normal fs entries still honor the global extended header
      t.equal(real.size, 1024, "normal entry still honors the global header")
      t.equal(real.data, body, "normal entry has its own contents")
    }
    t.end()
  })
})

// GNU long path blocks are metadata too: they must be measured by their own
// header, and must not stop the pending extended header from reaching the
// file entry that follows them.
tap.test("CVE-2026-53655: extended header size is not applied to a GNU " +
         "long path block", function (t) {
  var longPath = "gnu/long/path/name.txt"
  var pax = paxRecord("size", 4) + paxRecord("path", "pax-path.txt")
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/long", type: "x", size: pax.length, body: pax }
    , { path: "././@LongLink", type: "L", size: longPath.length + 1
      , body: longPath + "\0" }
    , { path: "short.txt", type: "0", size: 4, body: "REAL" }
    ])

  parseTar(tarBuf, function (events, errors) {
    t.equal(errors.length, 0, "tarball parses without error")

    var long = firstEvent(events, "longPath")
    t.ok(long, "long path block is seen")
    if (long) {
      t.equal(long.size, longPath.length + 1,
        "long path block keeps the size from its own header")
    }

    var real = firstEvent(events, "entry")
    t.ok(real, "the file after the long path block is still parsed")
    if (real) {
      t.equal(real.path, longPath, "long path still applies to the file")
      t.equal(real.size, 4, "file size is unchanged")
      t.equal(real.data, "REAL", "file contents are unchanged")
    }
    t.end()
  })
})

// the fix must not stop extended headers from doing their job for the file
// entries they actually describe.
tap.test("CVE-2026-53655: extended header still applies to a normal file",
         function (t) {
  var pax = paxRecord("size", 10) + paxRecord("path", "pax-applied.txt")
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/file", type: "x", size: pax.length, body: pax }
    , { path: "short.txt", type: "0", size: 5, body: "HELLOWORLD" }
    ])

  parseTar(tarBuf, function (events, errors) {
    t.equal(errors.length, 0, "tarball parses without error")
    var real = firstEvent(events, "entry")
    t.ok(real, "file entry is parsed")
    if (real) {
      t.equal(real.path, "pax-applied.txt", "extended header path applies")
      t.equal(real.size, 10, "extended header size applies")
      t.equal(real.data, "HELLOWORLD", "whole body is read")
    }
    t.end()
  })
})

// GNUDumpDir is a real file system entry, so it stays on the side of the
// fence that does honor extended headers.
tap.test("CVE-2026-53655: extended header still applies to a GNUDumpDir",
         function (t) {
  var pax = paxRecord("size", 10)
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/dump", type: "x", size: pax.length, body: pax }
    , { path: "dumpdir/", type: "D", size: 5, body: "HELLOWORLD" }
    ])

  parseTar(tarBuf, function (events, errors) {
    t.equal(errors.length, 0, "tarball parses without error")
    var real = firstEvent(events, "entry")
    t.ok(real, "dump dir entry is parsed")
    if (real) {
      t.equal(real.size, 10, "extended header size applies to GNUDumpDir")
      t.equal(real.data, "HELLOWORLD", "whole body is read")
    }
    t.end()
  })
})

// CVE-2026-59875 (GHSA-gvwx-54wh-qm9j): a NUL byte inside a PAX extended
// header *value* was kept verbatim, so a record such as
//
//   "26 path=safe.txt\0evil.txt\n"
//
// produced a JS string with a NUL in it.  GNU tar and bsdtar terminate the
// string at the NUL and only ever see "safe.txt", so a validator that
// pre-scans the tarball with either of them cannot see the smuggled tail
// (CWE-436), and every fs call that receives the untruncated string --
// fs.lstat(), fs.open(), fs.symlink() -- rejects it with an
// ERR_INVALID_ARG_VALUE thrown from inside the async FSReqCallback chain,
// i.e. outside any try/catch the caller wrapped the extraction in (CWE-248).
//
// The fix terminates the value at the first NUL while it is being decoded,
// which is also where the GNU long path/linkpath blocks already do it.

// a NUL, spelled out so that "\0" is never followed by a digit in a string
// literal (where it would be read as the start of an octal escape).
var NUL = String.fromCharCode(0)

// like parseTar(), but also hands back the fields object that each extended
// header ends up with -- that object is what a PAX value is decoded into, and
// what parse.js hands on as the pending/global extended header.
function parsePaxTar(tarBuf, cb) {
  mkdirp.sync(path.dirname(tarFile))
  fs.writeFileSync(tarFile, tarBuf)
  var events = []
  var fields = []
  var errors = []
  var parser = tar.Parse()

  parser.on("*", function (ev, entry) {
    var seen = { event: ev
               , path: entry.props.path
               , linkpath: entry.props.linkpath
               , type: entry.props.type
               , size: entry.props.size
               , data: "" }
    events.push(seen)
    entry.on("data", function (c) { seen.data += c.toString() })
    if (ev === "extendedHeader" || ev === "globalExtendedHeader") {
      entry.on("end", function () { fields.push(entry.fields) })
    }
  })
  parser.on("error", function (er) { errors.push(er) })
  parser.on("end", function () { cb(events, fields, errors) })

  // fed by hand rather than with pipe(), for the same reason as parseTar()
  var rs = fs.createReadStream(tarFile)
  rs.on("data", function (c) { parser.write(c) })
  rs.on("end", function () { parser.end() })
}

// the upstream regression case, "12 path=x\0y\n" => path is "x"
tap.test("CVE-2026-59875: a NUL terminates a PAX path value", function (t) {
  var pax = paxRecord("path", "x" + NUL + "y")
  t.equal(pax, "12 path=x" + NUL + "y\n", "record is the advisory's shape")

  var tarBuf = buildTar(
    [ { path: "PaxHeaders/nul", type: "x", size: pax.length, body: pax }
    , { path: "visible.txt", type: "0", size: 0 }
    ])

  parsePaxTar(tarBuf, function (events, fields, errors) {
    t.equal(errors.length, 0, "tarball parses without error")

    t.equal(fields.length, 1, "the extended header was parsed")
    if (fields.length) {
      t.equal(fields[0].path, "x", "PAX value is terminated at the NUL")
      t.equal(fields[0].path.indexOf(NUL), -1,
        "no NUL survives into the decoded PAX value")
    }

    var real = firstEvent(events, "entry")
    t.ok(real, "the file entry is parsed")
    if (real) {
      t.equal(real.path, "x", "entry path is the truncated PAX path")
      t.equal(real.path.indexOf(NUL), -1, "entry path holds no NUL byte")
    }
    t.end()
  })
})

// linkpath is the other field the advisory names: it reaches fs.symlink()
// and fs.link() the same way path reaches fs.open().
tap.test("CVE-2026-59875: a NUL terminates a PAX linkpath value", function (t) {
  var pax = paxRecord("linkpath", "a" + NUL + "b")
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/nullink", type: "x", size: pax.length, body: pax }
    , { path: "sym", type: "2", size: 0, linkpath: "placeholder" }
    ])

  parsePaxTar(tarBuf, function (events, fields, errors) {
    t.equal(errors.length, 0, "tarball parses without error")

    t.equal(fields.length, 1, "the extended header was parsed")
    if (fields.length) {
      t.equal(fields[0].linkpath, "a", "PAX linkpath is terminated at the NUL")
      t.equal(fields[0].linkpath.indexOf(NUL), -1,
        "no NUL survives into the decoded PAX linkpath")
    }

    var real = firstEvent(events, "entry")
    t.ok(real, "the symlink entry is parsed")
    if (real) {
      t.equal(real.linkpath, "a", "entry linkpath is the truncated PAX value")
      t.equal(real.linkpath.indexOf(NUL), -1,
        "entry linkpath holds no NUL byte")
    }
    t.end()
  })
})

// this parser frames a record by its length, not by the \n, so a value may
// legitimately contain a newline -- and therefore a second NUL after it.
// Truncation has to take the whole tail, or that second NUL still gets out.
tap.test("CVE-2026-59875: a NUL terminates a PAX value that spans a newline",
         function (t) {
  var pax = paxRecord("path", "a" + NUL + "b\nc" + NUL + "d")
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/multi", type: "x", size: pax.length, body: pax }
    , { path: "visible.txt", type: "0", size: 0 }
    ])

  parsePaxTar(tarBuf, function (events, fields, errors) {
    t.equal(errors.length, 0, "tarball parses without error")

    t.equal(fields.length, 1, "the extended header was parsed")
    if (fields.length) {
      t.equal(fields[0].path, "a", "value is cut at the *first* NUL")
      t.equal(fields[0].path.indexOf(NUL), -1,
        "no later NUL survives into the decoded PAX value")
    }

    var real = firstEvent(events, "entry")
    t.ok(real, "the file entry is parsed")
    if (real) t.equal(real.path.indexOf(NUL), -1, "entry path holds no NUL byte")
    t.end()
  })
})

// truncating before the numeric coercion must leave numeric records working.
tap.test("CVE-2026-59875: a NUL-terminated numeric PAX value still parses",
         function (t) {
  var pax = paxRecord("size", "4" + NUL + "999")
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/num", type: "x", size: pax.length, body: pax }
    , { path: "num.txt", type: "0", size: 4, body: "REAL" }
    ])

  parsePaxTar(tarBuf, function (events, fields, errors) {
    t.equal(errors.length, 0, "tarball parses without error")
    if (fields.length) {
      t.equal(fields[0].size, 4, "numeric PAX value is cut at the NUL")
    }

    var real = firstEvent(events, "entry")
    t.ok(real, "the file entry is parsed")
    if (real) {
      t.equal(real.size, 4, "entry keeps the truncated size, not 4999")
      t.equal(real.data, "REAL", "entry body is read whole")
    }
    t.end()
  })
})

// the advisory's own PoC, run all the way through an extraction: the process
// must survive it, only the visible name may be created, and the smuggled
// tail must not appear on disk.
tap.test("CVE-2026-59875: extracting a NUL-smuggled PAX path does not throw",
         function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)

  var pax = paxRecord("path", "safe.txt" + NUL + "evil.txt")
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/poc", type: "x", size: pax.length, body: pax }
    , { path: "placeholder.txt", type: "0", size: 0 }
    ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish(er) {
    if (done) return
    done = true
    t.equal(er, undefined, "extraction reports no error")

    var safe = false
    try { fs.lstatSync(path.resolve(target, "safe.txt")); safe = true } catch (e) {}
    t.equal(safe, true, "the visible name is the one that gets created")

    var evil = false
    try { fs.lstatSync(path.resolve(target, "evil.txt")); evil = true } catch (e) {}
    t.equal(evil, false, "the smuggled name is not created")

    var names = fs.readdirSync(target)
    for (var i = 0; i < names.length; i++) {
      t.equal(names[i].indexOf(NUL), -1,
        "no extracted name carries a NUL byte: " + JSON.stringify(names[i]))
    }
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", function () { finish() })
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// positive control: a PAX path override with no NUL in it still applies, so
// the truncation cannot be over-firing on legitimate archives.
tap.test("CVE-2026-59875: a NUL-free PAX path override still applies",
         function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)

  var pax = paxRecord("path", "foo/bar.txt")
  var tarBuf = buildTar(
    [ { path: "PaxHeaders/ok", type: "x", size: pax.length, body: pax }
    , { path: "orig.txt", type: "0", size: 0 }
    ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish(er) {
    if (done) return
    done = true
    t.equal(er, undefined, "extraction reports no error")

    var overridden = false
    try { fs.lstatSync(path.resolve(target, "foo/bar.txt")); overridden = true }
    catch (e) {}
    t.equal(overridden, true, "PAX path override still names the file")

    var orig = false
    try { fs.lstatSync(path.resolve(target, "orig.txt")); orig = true } catch (e) {}
    t.equal(orig, false, "the header path was really overridden")
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", function () { finish() })
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-59874: a *negative* size.  The size of an entry is what says when
// that entry ends, and Entry.write() only ends it when _remaining reaches
// exactly 0.  Counting down from below zero never gets there: every block
// that follows is handed to the same entry forever, so the parser never looks
// for another header, the rest of the archive disappears, and the stream ends
// in an "unexpected eof" -- an unbounded loop over the input that yields
// nothing.  A negative size can arrive three ways: as a base-256 field in the
// 512-byte header block, as a PAX "size=-N" record in an extended header, or
// as the same record in a global extended header.  All three are refused
// here, and the pack side never writes such a record out either.

var Entry = require("../lib/entry.js")
var ExtendedHeader = require("../lib/extended-header.js")
var ExtendedHeaderWriter = require("../lib/extended-header-writer.js")

// run a PAX body through the extended-header state machine on its own, and
// hand back the fields object it decoded into.
function paxFields(body) {
  var header = new TarHeader(makeHeader(
    { path: "PaxHeaders/x", type: "x", size: body.length }))
  var eh = new ExtendedHeader(header)
  eh.write(new Buffer(body))
  return eh.fields
}

// Overwrite the 12-byte size field of an encoded header block with a
// base-256 negative number, the way GNU tar writes a value that the octal
// field cannot hold: a 0xFF flag byte, then the two's complement of the
// value, most significant byte first.  The checksum covers the whole block,
// so it has to be recomputed once the bytes are in place.
function setNegativeSize(block, n) {
  var off = tar.fieldOffs[tar.fields.size]
    , end = tar.fieldEnds[tar.fields.size]

  for (var i = end - 1; i >= off; i--) {
    var v = Math.floor(n / Math.pow(256, end - 1 - i))
    block[i] = ((v % 256) + 256) % 256
  }
  block[off] = 0xFF

  var sum = TarHeader.prototype.calcSum(block)
    , oct = sum.toString(8)
  while (oct.length < 6) oct = "0" + oct
  block.write(oct + NUL + " ", tar.fieldOffs[tar.fields.cksum], 8, "utf8")

  return block
}

// the record-level rule: a "size" record is stored only when it decodes to a
// number that is zero or greater.  Every other key keeps its old behavior.
tap.test("CVE-2026-59874: only a size of zero or more survives PAX decoding",
         function (t) {
  t.equal(paxFields(paxRecord("size", 1000)).size, 1000, "size=1000 is kept")
  t.equal(paxFields(paxRecord("size", 0)).size, 0, "size=0 is kept")
  t.equal(paxFields(paxRecord("size", -1)).hasOwnProperty("size"), false,
    "size=-1 is dropped")
  t.equal(paxFields(paxRecord("size", -1000)).hasOwnProperty("size"), false,
    "size=-1000 is dropped")
  t.equal(paxFields(paxRecord("size", -1000)).size, undefined,
    "no size at all comes out of a negative record")
  // the rule is about "size" only -- other numeric records are untouched.
  t.equal(paxFields(paxRecord("uid", -1)).uid, -1, "uid=-1 is left alone")
  t.end()
})

// the advisory's record, in a real tarball: it must not reach the fields
// object, and the file that follows the PAX block must still be parsed.
tap.test("CVE-2026-59874: a negative PAX size record is not stored",
         function (t) {
  var pax = paxRecord("size", -1000)
  t.equal(pax, "14 size=-1000\n", "record is the advisory's shape")

  var tarBuf = buildTar(
    [ { path: "PaxHeaders/neg", type: "x", size: pax.length, body: pax }
    , { path: "real.txt", type: "0", size: 4, body: "REAL" }
    ])

  parsePaxTar(tarBuf, function (events, fields, errors) {
    t.equal(errors.length, 0, "tarball parses without error")

    t.equal(fields.length, 1, "the extended header was parsed")
    if (fields.length) {
      t.equal(fields[0].hasOwnProperty("size"), false,
        "the negative size never lands in the extended header fields")
      t.equal(fields[0].size, undefined, "no size comes out of the PAX block")
    }

    var real = firstEvent(events, "entry")
    t.ok(real, "the file after the PAX block is still parsed")
    if (real) {
      t.equal(real.path, "real.txt", "the entry keeps its own path")
      t.equal(real.size, 4, "the entry keeps the size from its own header")
      t.equal(real.data, "REAL", "the entry body is read whole")
    }
    t.end()
  })
})

// positive control: dropping negative sizes must not stop a legitimate PAX
// size override from taking effect.
tap.test("CVE-2026-59874: a non-negative PAX size record still applies",
         function (t) {
  var body = "REAL" + new Array(997).join("A")
  var pax = paxRecord("size", 1000)
  t.equal(body.length, 1000, "the body really is 1000 bytes")

  var tarBuf = buildTar(
    [ { path: "PaxHeaders/pos", type: "x", size: pax.length, body: pax }
    , { path: "pos.txt", type: "0", size: 4, body: body }
    ])

  parsePaxTar(tarBuf, function (events, fields, errors) {
    t.equal(errors.length, 0, "tarball parses without error")
    t.equal(fields.length, 1, "the extended header was parsed")
    if (fields.length) t.equal(fields[0].size, 1000, "size=1000 is stored")

    var real = firstEvent(events, "entry")
    t.ok(real, "the file entry is parsed")
    if (real) {
      t.equal(real.size, 1000, "the extended header size still applies")
      t.equal(real.data, body, "the whole body is read")
    }
    t.end()
  })
})

// the other source of a negative size: the raw 512-byte header block.
tap.test("CVE-2026-59874: a negative size in the header block never reaches " +
         "Entry._remaining", function (t) {
  var block = setNegativeSize(
    makeHeader({ path: "neg.txt", type: "0", size: 0 }), -1000)
  t.ok(TarHeader.parseNumeric(block.slice(tar.fieldOffs[tar.fields.size],
                                          tar.fieldEnds[tar.fields.size])) < 0,
    "the crafted size field really does decode to a negative number")

  var header = new TarHeader(block)
  t.equal(header.cksumValid, true, "the crafted block is still a valid header")
  t.equal(header.size, 0, "the negative base-256 size decodes as no size")

  var entry = new Entry(header)
  t.equal(entry.size, 0, "the entry gets no size")
  t.equal(entry._remaining, 0, "_remaining starts at zero, so the entry ends")

  // ... and when the negative size is layered on by an extended header or a
  // global one, which is where a PAX record would land if one got through.
  var ok = new TarHeader(makeHeader({ path: "ok.txt", type: "0", size: 4 }))
  var ext = new Entry(ok, { size: -1000 })
  t.equal(ext._remaining, 0,
    "an extended header size below zero cannot make _remaining negative")
  var gex = new Entry(ok, null, { size: -1000 })
  t.equal(gex._remaining, 0,
    "a global extended header size below zero cannot either")

  // the ordinary case is untouched.
  var plain = new Entry(ok)
  t.equal(plain._remaining, 4, "a normal size still drives _remaining")
  t.end()
})

// end to end: the entry with the negative size must not eat the entries that
// come after it, and the parse must finish.
tap.test("CVE-2026-59874: a negative header size does not swallow the rest " +
         "of the archive", function (t) {
  var head = setNegativeSize(
    makeHeader({ path: "neg.txt", type: "0", size: 0 }), -1000)
  var tarBuf = Buffer.concat(
    [ head
    , buildTar([{ path: "after.txt", type: "0", size: 4, body: "REAL" }])
    ])

  parseTar(tarBuf, function (events, errors) {
    t.equal(errors.length, 0, "tarball parses without error")
    t.equal(events.length, 2, "both entries are reported")

    var neg = events[0]
    t.ok(neg, "the entry with the negative size is reported")
    if (neg) {
      t.equal(neg.path, "neg.txt", "it is the entry its header named")
      t.equal(neg.size, 0, "its size is zero, not a negative number")
    }

    var after = events[1]
    t.ok(after, "the entry after it is still parsed")
    if (after) {
      t.equal(after.path, "after.txt", "the following entry is not swallowed")
      t.equal(after.data, "REAL", "and its body is read whole")
    }
    t.end()
  })
})

// the pack side of the same rule: a negative size is never written into a
// generated extended header, so this tar cannot hand one to another reader.
tap.test("CVE-2026-59874: a negative size is never written into a generated " +
         "extended header", function (t) {
  var neg = new ExtendedHeaderWriter(
    { path: "neg.txt", size: -1000, uid: 0, gid: 0 })
  neg._encodeFields()
  var body = Buffer.concat(neg.body).toString()
  t.equal(body.indexOf("size="), -1,
    "no size record is written out: " + JSON.stringify(body))

  var pos = new ExtendedHeaderWriter(
    { path: "pos.txt", size: 1000, uid: 0, gid: 0 })
  pos._encodeFields()
  t.notEqual(Buffer.concat(pos.body).toString().indexOf("size=1000"), -1,
    "a size of zero or more is still written out")
  t.end()
})

tap.test("cleanup", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  t.pass("cleaned")
  t.end()
})
