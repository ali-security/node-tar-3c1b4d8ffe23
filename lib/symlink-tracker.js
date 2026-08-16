// CVE-2026-26960 (GHSA-83g3-92jg-28cx) — analyst-authored module for tar 2.2.1.
// Tracks symlinks parsed from the tar stream so later entries cannot be extracted
// through them. Upstream's fix uses `lstatSync` against the filesystem; that does
// not work in 2.2.1 because fstream writes asynchronously, so a symlink declared
// earlier in the same tar may not be on disk when later entries are checked.

var path = require("path")

function SymlinkTracker (cwd) {
  if (!(this instanceof SymlinkTracker)) return new SymlinkTracker(cwd)
  this.cwd = cwd
  this.seen = {}
}

SymlinkTracker.prototype.has = function (key) {
  return !!(key && this.seen[key])
}

SymlinkTracker.prototype._keyFor = function (abs) {
  return path.relative(this.cwd, abs).replace(/\\/g, '/')
}

// Walks the directory chain from cwd to entry's parent. Returns the absolute
// directory whose tar-relative key is a recorded symlink, or null.
SymlinkTracker.prototype.findInDirChain = function (entryPath) {
  var entryDir = path.resolve(this.cwd, path.dirname(entryPath))
  var relDir = path.relative(this.cwd, entryDir)
  if (!relDir || relDir === '.') return null
  var dirParts = relDir.split(path.sep)
  var checkDir = this.cwd
  for (var i = 0; i < dirParts.length; i++) {
    checkDir = path.join(checkDir, dirParts[i])
    if (this.has(this._keyFor(checkDir))) return checkDir
  }
  return null
}

// Walks the prefixes of a hardlink linkpath (tar-relative). Returns the prefix
// that matches a recorded symlink, or null.
SymlinkTracker.prototype.findInHardlinkPath = function (linkpath) {
  var lp = (linkpath || '').replace(/\\/g, '/')
  var parts = lp.split('/')
  var prefix = ''
  for (var i = 0; i < parts.length - 1; i++) {
    prefix = prefix ? prefix + '/' + parts[i] : parts[i]
    if (this.has(prefix)) return prefix
  }
  return null
}

// Walks the resolved hardlink target path (absolute, inside cwd). Returns the
// absolute directory that matches a recorded symlink, or null.
SymlinkTracker.prototype.findInLinkTargetChain = function (linkTarget) {
  var rel = path.relative(this.cwd, linkTarget)
  if (!rel) return null
  var parts = rel.split(path.sep)
  var checkLink = this.cwd
  for (var i = 0; i < parts.length - 1; i++) {
    checkLink = path.join(checkLink, parts[i])
    if (this.has(this._keyFor(checkLink))) return checkLink
  }
  return null
}

// Walks a SymbolicLink's own target path components, ignoring '..', '.', and ''.
// Returns the candidate that matches a recorded symlink, or null.
SymlinkTracker.prototype.findInSymlinkTarget = function (entryPath, linkpath) {
  var dn = path.dirname(entryPath) || ''
  var lp = (linkpath || '').replace(/\\/g, '/')
  var parts = lp.split('/')
  var prefix = ''
  for (var i = 0; i < parts.length - 1; i++) {
    var part = parts[i]
    if (part === '..' || part === '.' || part === '') continue
    var candidate = (dn === '.' || !dn)
      ? (prefix ? prefix + '/' + part : part)
      : dn + '/' + (prefix ? prefix + '/' + part : part)
    candidate = candidate.replace(/\\/g, '/')
    if (this.has(candidate)) return candidate
    prefix = prefix ? prefix + '/' + part : part
  }
  return null
}

// Records a symlink declared at entryPath (tar-relative).
SymlinkTracker.prototype.record = function (entryPath) {
  var key = entryPath.replace(/\\/g, '/').replace(/\/+$/, '')
  this.seen[key] = true
}

module.exports = SymlinkTracker
