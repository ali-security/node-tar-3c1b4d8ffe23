// unix absolute paths are also absolute on win32, so we use this for both

// manually extract root from path (for Node 0.10 compatibility - path.parse doesn't exist)
// Returns the root portion of the path
function getRoot(p) {
    // Windows path with forward slashes: //foo/bar/...
    // Test case shows: //foo//bar//baz -> root is // (not //foo/bar/)
    // So we treat // as just a root of //
    // MUST check this BEFORE single / to avoid false match
    if (p.charAt(0) === '/' && p.charAt(1) === '/') {
        return '//'
    }

    // Unix absolute path
    if (p.charAt(0) === '/') {
        return '/'
    }

    // Windows UNC path with backslashes: \\server\share\...
    // Pattern: \\foo\bar\baz -> root is \\foo\bar\
    if (p.charAt(0) === '\\' && p.charAt(1) === '\\') {
        // Find server name (after \\)
        var idx = 2
        while (idx < p.length && p.charAt(idx) !== '\\' && p.charAt(idx) !== '/') {
            idx++
        }
        if (idx < p.length) {
            idx++ // include the separator
            // Find share name
            while (idx < p.length && p.charAt(idx) !== '\\' && p.charAt(idx) !== '/') {
                idx++
            }
            if (idx < p.length) {
                idx++ // include the separator
                return p.substr(0, idx)
            }
            // If no share separator found, return up to server
            return p.substr(0, idx)
        }
        return p.substr(0, 2) // just \\
    }

    // Windows drive letter: C:\ or C:/ or C:///
    // Test case: c:///a/b/c -> root is c:///
    if (p.length >= 3 && /^[a-zA-Z]:/.test(p)) {
        // Check if it's followed by \ or /
        if (p.charAt(2) === '\\' || p.charAt(2) === '/') {
            // Count consecutive slashes/backslashes
            var idx = 3
            var sep = p.charAt(2)
            while (idx < p.length && (p.charAt(idx) === '\\' || p.charAt(idx) === '/')) {
                idx++
            }
            return p.substr(0, idx)
        }
    }

    // No root found
    return ''
}

// manually check if path is absolute (for Node 0.10 compatibility)
// Unix absolute: starts with '/'
// Windows absolute: has a drive letter or UNC path
// Note: unix absolute paths are also absolute on win32
function isAbsolute(p) {
    if (p.charAt(0) === '/') return true
    if (p.charAt(0) === '\\' && p.charAt(1) === '\\') return true
    if (/^[a-zA-Z]:[\\\/]/.test(p)) return true
    return false
}

// returns [root, stripped]
module.exports = function (p) {
    var r = ''
    while (isAbsolute(p)) {
        var root = getRoot(p)
        if (!root) break
        p = p.substr(root.length)
        r += root
    }
    return [r, p]
}

