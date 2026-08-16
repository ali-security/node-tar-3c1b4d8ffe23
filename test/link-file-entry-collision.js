// Set the umask, so that it works the same everywhere.
process.umask(parseInt('22', 8))

var tap = require("tap")
  , tar = require("../tar.js")
  , fs = require("fs")
  , path = require("path")
  , hex = path.resolve(__dirname, "link-file-entry-collision/bad-link.hex")
  , src = path.resolve(__dirname, "tmp/link-file-entry-collision-src")
  , file = path.resolve(src, "bad-link.tar")
  , target = path.resolve(__dirname, "tmp/link-file-entry-collision")
  , index = 0
  , fstream = require("fstream")
  , mkdirp = require("mkdirp")
  , rimraf = require("rimraf")

// The fixture tarball is checked in as an annotated hex dump rather than as a
// binary blob, so that the malicious entries stay reviewable in plain text.
// Every hex line holds half of a 512 byte tar block, followed by a "#" comment
// rendering those same bytes as ascii.  Lines starting with "--" are headings.
function readHexFixture (f) {
  var lines = fs.readFileSync(f, "utf8").split("\n")
    , bytes = []

  for (var i = 0; i < lines.length; i ++) {
    var line = lines[i].trim()
    if (!line || line.indexOf("--") === 0) continue
    var comment = line.indexOf("#")
    if (comment !== -1) line = line.substr(0, comment)
    bytes.push(line.replace(/\s+/g, ""))
  }

  return new Buffer(bytes.join(""), "hex")
}

tap.test("preclean", function (t) {
  rimraf.sync(target)
  rimraf.sync(src)
  t.pass("cleaned!")
  t.end()
})

tap.test("build fixture", function (t) {
  var buf = readHexFixture(hex)
  t.equal(buf.length, 3584, "fixture is 7 tar blocks of 512 bytes")
  mkdirp.sync(src)
  fs.writeFileSync(file, buf)
  t.end()
})

tap.test("extract test", function (t) {
  var extract = tar.Extract(target)
  var inp = fs.createReadStream(file)
  inp.pipe(extract)

  extract.on("end", function () {
    t.equal(fs.readFileSync(target + "/bad-link-target", "utf8"),
      "this should remain the same\n")
    t.equal(fs.readFileSync(target + "/a.txt", "utf8"),
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    t.end()
  })
})

tap.test("cleanup", function (t) {
  rimraf.sync(target)
  rimraf.sync(src)
  t.pass("cleaned!")
  t.end()
})
