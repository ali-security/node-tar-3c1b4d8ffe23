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

tap.test("cleanup", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  t.pass("cleaned")
  t.end()
})
