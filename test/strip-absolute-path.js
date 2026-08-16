var tap = require('tap')
var stripAbsolutePath = require('../lib/strip-absolute-path.js')

var cases = {
    '/': ['/', ''],
    '////': ['////', ''],
    'c:///a/b/c': ['c:///', 'a/b/c'],
    '\\\\foo\\bar\\baz': ['\\\\foo\\bar\\', 'baz'],
    '//foo//bar//baz': ['//', 'foo//bar//baz'],
    'c:\\c:\\c:\\c:\\\\d:\\e/f/g': ['c:\\c:\\c:\\c:\\\\d:\\', 'e/f/g'],
}

tap.test('strip absolute path', function (t) {
    var keys = Object.keys(cases)
    for (var i = 0; i < keys.length; i++) {
        var input = keys[i]
        var expected = cases[input]
        var root = expected[0]
        var stripped = expected[1]
        var result = stripAbsolutePath(input)
        t.equivalent(result, [root, stripped], input)
    }
    t.end()
})

