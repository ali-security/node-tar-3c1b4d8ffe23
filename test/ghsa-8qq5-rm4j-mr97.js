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

function buildTar(entries) {
  var chunks = []
  for (var i = 0; i < entries.length; i++) chunks.push(makeHeader(entries[i]))
  chunks.push(new Buffer(1024))
  for (var j = 0; j < 1024; j++) chunks[chunks.length - 1][j] = 0
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

tap.test("cleanup", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  t.pass("cleaned")
  t.end()
})
