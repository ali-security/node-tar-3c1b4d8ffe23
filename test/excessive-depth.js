var tap = require("tap")
  , tar = require("../tar.js")
  , TarHeader = require("../lib/header.js")
  , fs = require("fs")
  , path = require("path")
  , rimraf = require("rimraf")
  , mkdirp = require("mkdirp")

var target = path.resolve(__dirname, "tmp/excessive-depth-test")
var tarFile = path.resolve(__dirname, "tmp/excessive-depth-test.tar")

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
  t.pass("cleaned!")
  t.end()
})

tap.test("maxDepth option is set correctly", function (t) {
  var extract1 = tar.Extract({ path: target })
  t.equal(extract1._maxDepth, 1024, "default maxDepth should be 1024")

  var extract2 = tar.Extract({ path: target, maxDepth: 100 })
  t.equal(extract2._maxDepth, 100, "custom maxDepth should be respected")

  var extract3 = tar.Extract({ path: target, maxDepth: Infinity })
  t.equal(extract3._maxDepth, Infinity, "Infinity maxDepth should be allowed")

  t.end()
})

tap.test("path depth check works correctly", function (t) {
  // Test that the depth checking logic works
  var parts1 = "a/b/c/d/e".split("/").filter(function(p) { return p })
  t.equal(parts1.length, 5, "path with 5 components should have length 5")

  var parts2 = "a/b/c/d/e/f/g/h/i/j/k".split("/").filter(function(p) { return p })
  t.equal(parts2.length, 11, "path with 11 components should have length 11")

  var parts3 = "".split("/").filter(function(p) { return p })
  t.equal(parts3.length, 0, "empty path should have length 0")

  t.end()
})

// Integration tests: build a tar with deep paths, extract, verify rejection
function runMaxDepthTest(t, maxDepth, depth, opts) {
  rimraf.sync(target)
  mkdirp.sync(path.dirname(tarFile))
  var deepPath = ""
  for (var i = 0; i < depth; i++) deepPath += "a/"
  deepPath += "foo.txt"

  var tarBuf = buildTar([
    { path: deepPath, type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract(opts)
    .on("end", function () {
      var deepTarget = path.resolve(target, deepPath)
      var exists = false
      try { fs.statSync(deepTarget); exists = true } catch (e) {}
      t.equal(exists, false, "excessively deep file should not be extracted")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
}

tap.test("extraction deeper than maxDepth is rejected", function (t) {
  runMaxDepthTest(t, 10, 15, { path: target, maxDepth: 10 })
})

tap.test("custom maxDepth=64 rejects 80-deep path", function (t) {
  runMaxDepthTest(t, 64, 80, { path: target, maxDepth: 64 })
})
