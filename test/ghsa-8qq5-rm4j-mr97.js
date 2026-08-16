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

tap.test("cleanup", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  t.pass("cleaned")
  t.end()
})
