// give it a tarball and a path, and it'll dump the contents

module.exports = Extract

var tar = require("../tar.js")
  , fstream = require("fstream")
  , inherits = require("inherits")
  , path = require("path")
  , stripAbsolutePath = require("./strip-absolute-path.js")

function Extract (opts) {
  if (!(this instanceof Extract)) return new Extract(opts)
  tar.Parse.apply(this)

  if (typeof opts !== "object") {
    opts = { path: opts }
  }

  // better to drop in cwd? seems more standard.
  opts.path = opts.path || path.resolve("node-tar-extract")
  opts.type = "Directory"
  opts.Directory = true

  // similar to --strip or --strip-components
  opts.strip = +opts.strip
  if (!opts.strip || opts.strip <= 0) opts.strip = 0

  // prevent excessively deep nesting of subfolders
  // set to `Infinity` to remove this restriction
  this._maxDepth = typeof opts.maxDepth === 'number' ? opts.maxDepth : 1024

  this._fst = fstream.Writer(opts)

  var origAdd = this._fst.add
  this._fst.add = function (entry) {
    if (entry._rejected) return true
    return origAdd.apply(this, arguments)
  }

  this.pause()
  var me = this

  // Hardlinks in tarballs are relative to the root
  // of the tarball.  So, they need to be resolved against
  // the target directory in order to be created properly.
  me.on("entry", function (entry) {
    // if there's a "strip" argument, then strip off that many
    // path components.
    if (opts.strip) {
      var p = entry.path.split("/").slice(opts.strip).join("/")
      entry.path = entry.props.path = p
      if (entry.linkpath) {
        var lp = entry.linkpath.split("/").slice(opts.strip).join("/")
        entry.linkpath = entry.props.linkpath = lp
      }
    }

    if (isFinite(me._maxDepth)) {
      var depthParts = entry.path.split("/").filter(function(part) { return part })
      if (depthParts.length > me._maxDepth) {
        if (entry.warn) {
          entry.warn('TAR_ENTRY_ERROR', 'path excessively deep', {
            entry: entry,
            path: entry.path,
            depth: depthParts.length,
            maxDepth: me._maxDepth
          })
        }
        entry._rejected = true
        entry.abort()
        return
      }
    }

    // Normalize path separators for consistent checking
    var p = entry.path.replace(/\\/g, '/')

    // strip off the root
    var s = stripAbsolutePath(p)
    if (s[0]) {
      entry.path = s[1]
      entry.props.path = s[1]
      p = s[1]
      if (entry.warn) {
        entry.warn('stripping ' + s[0] + ' from absolute path', entry.path)
      }
    }

    // Check for path traversal attempts
    var parts = p.replace(/\\/g, '/').split('/')
    if (parts.indexOf('..') !== -1) {
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path contains \'..\'', {
          entry: entry,
          path: p
        })
      }
      return // Skip this entry
    }

    // Resolve the absolute path for this entry
    entry.absolute = path.resolve(opts.path, entry.path)

    // Defense in depth: ensure the resolved path doesn't escape the extraction directory
    // This should have been prevented above, but provides additional safety
    var extractPath = path.resolve(opts.path)
    var normalizedExtract = extractPath.replace(/\\/g, '/')
    var normalizedEntry = entry.absolute.replace(/\\/g, '/')

    if (normalizedEntry.indexOf(normalizedExtract + '/') !== 0 &&
      normalizedEntry !== normalizedExtract) {
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path escaped extraction target', {
          entry: entry,
          path: p,
          resolvedPath: normalizedEntry,
          cwd: normalizedExtract
        })
      }
      return // Skip this entry
    }
    if (entry.type === "Link") {
      entry.linkpath = entry.props.linkpath =
        path.join(opts.path, path.join("/", entry.props.linkpath))
    }

    if (entry.type === "SymbolicLink") {
      var dn = path.dirname(entry.path) || ""
      var linkpath = entry.props.linkpath
      var target = path.resolve(opts.path, dn, linkpath)
      if (target.indexOf(opts.path) !== 0) {
        linkpath = path.join(opts.path, path.join("/", linkpath))
      }
      entry.linkpath = entry.props.linkpath = linkpath
    }
  })

  this._fst.on("ready", function () {
    me.pipe(me._fst, { end: false })
    me.resume()
  })

  this._fst.on('error', function(err) {
    me.emit('error', err)
  })

  this._fst.on('drain', function() {
    me.emit('drain')
  })

  // this._fst.on("end", function () {
  //   console.error("\nEEEE Extract End", me._fst.path)
  // })

  this._fst.on("close", function () {
    // console.error("\nEEEE Extract End", me._fst.path)
    me.emit("finish")
    me.emit("end")
    me.emit("close")
  })
}

inherits(Extract, tar.Parse)

Extract.prototype._streamEnd = function () {
  var me = this
  if (!me._ended || me._entry) me.error("unexpected eof")
  me._fst.end()
  // my .end() is coming later.
}
