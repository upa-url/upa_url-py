import unittest
from upa_url import URLPattern

class TestURLPattern(unittest.TestCase):

    def test_construct_default(self):
        p = URLPattern()
        # properties
        self.assertEqual(p.protocol, '*')
        self.assertEqual(p.username, '*')
        self.assertEqual(p.password, '*')
        self.assertEqual(p.hostname, '*')
        self.assertEqual(p.port, '*')
        self.assertEqual(p.pathname, '*')
        self.assertEqual(p.search, '*')
        self.assertEqual(p.hash, '*')
        self.assertFalse(p.hasRegExpGroups)
        # test
        self.assertTrue(p.test())
        self.assertTrue(p.test('https://upa-url.github.io/docs/'))
        self.assertTrue(p.test('docs/', 'https://upa-url.github.io/'))
        self.assertTrue(p.test({'protocol': 'http', 'hostname': 'upa-url.github.io'}))
        # exec
        e = p.exec()
        self.assertEqual(e['inputs'], [{}])
        e = p.exec('https://upa-url.github.io/docs/')
        self.assertEqual(e['protocol'], {'input': 'https', 'groups': {'0': 'https'}})
        self.assertEqual(e['hostname'], {'input': 'upa-url.github.io', 'groups': {'0': 'upa-url.github.io'}})
        self.assertEqual(e['pathname'], {'input': '/docs/', 'groups': {'0': '/docs/'}})
        e = p.exec('docs/', 'https://upa-url.github.io/')
        self.assertEqual(e['protocol'], {'input': 'https', 'groups': {'0': 'https'}})
        self.assertEqual(e['hostname'], {'input': 'upa-url.github.io', 'groups': {'0': 'upa-url.github.io'}})
        self.assertEqual(e['pathname'], {'input': '/docs/', 'groups': {'0': '/docs/'}})
        e = p.exec({'protocol': 'http', 'hostname': 'upa-url.github.io'})
        self.assertEqual(e['protocol'], {'input': 'http', 'groups': {'0': 'http'}})
        self.assertEqual(e['hostname'], {'input': 'upa-url.github.io', 'groups': {'0': 'upa-url.github.io'}})

    def test_construct_with_init(self):
        p = URLPattern({'protocol': 'http', 'hostname': ':name.lt', 'pathname': '/(a*)'}, {'ignoreCase': True})
        # properties
        self.assertEqual(p.protocol, 'http')
        self.assertEqual(p.username, '*')
        self.assertEqual(p.password, '*')
        self.assertEqual(p.hostname, ':name.lt')
        self.assertEqual(p.port, '*')
        self.assertEqual(p.pathname, '/(a*)')
        self.assertEqual(p.search, '*')
        self.assertEqual(p.hash, '*')
        self.assertTrue(p.hasRegExpGroups)
        # test
        self.assertTrue(p.test('http://lrt.lt/aaa'))
        self.assertTrue(p.test('http://lrt.lt/AAA'))
        self.assertFalse(p.test('http://github.io/aaa'))

        p = URLPattern({'pathname': '/([[a-z]--a])'})
        # test
        self.assertFalse(p.test({'pathname': '/a'}))
        self.assertTrue(p.test({'pathname': '/z'}))
        # exec
        e = p.exec({'pathname': '/z'})
        self.assertEqual(e['pathname'], {'input': '/z', 'groups': {'0': 'z'}})

    def test_construct_with_inputStr(self):
        p = URLPattern('*://:host/:path')
        # properties
        self.assertEqual(p.protocol, '*')
        self.assertEqual(p.hostname, ':host')
        self.assertEqual(p.pathname, '/:path')
        # test
        self.assertTrue(p.test('http://host/path'))
        self.assertFalse(p.test('http://host.lt/path'))

    def test_construct_with_baseURL(self):
        p = URLPattern(':path', 'about:blank')
        # properties
        self.assertEqual(p.protocol, 'about')
        self.assertEqual(p.pathname, ':path')
        # test
        self.assertTrue(p.test('about:a.b.c'))
        # exec
        e = p.exec('about:a.b.c')
        self.assertEqual(e['protocol'], {'input': 'about', 'groups': {}})
        self.assertEqual(e['pathname'], {'input': 'a.b.c', 'groups': {'path': 'a.b.c'}})

    def test_construct_fails(self):
        self.assertRaises(RuntimeError, URLPattern, {'protocol': '.'})
        self.assertRaises(RuntimeError, URLPattern, {'pathname': '/(\\m)'})
        self.assertRaises(RuntimeError, URLPattern, 'ws://h^')
        self.assertRaises(RuntimeError, URLPattern, '', 'ws://h:p')

if __name__ == '__main__':
    unittest.main()
