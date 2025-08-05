import unittest
from upa_url import URL, URLSearchParams

class TestURL(unittest.TestCase):

    # canParse, parse, construct
    def test_parse(self):
        input = '/upa-url/upa'
        baseUrl = 'https://github.com/any'
        expected = 'https://github.com/upa-url/upa'
        self.assertTrue(URL.canParse(input, baseUrl))
        u = URL.parse(input, baseUrl)
        self.assertEqual(u.href, expected)
        u = URL(input, baseUrl)
        self.assertEqual(u.href, expected)

    def test_parse_fails(self):
        input = 'https://^^^/'
        self.assertFalse(URL.canParse(input))
        u = URL.parse(input)
        self.assertIsNone(u)
        self.assertRaises(RuntimeError, URL, input)

    # getters / setters
    def test_props(self):
        inputUrl = 'http://u:p@host:1234/pa/th?a=1#frag'
        u = URL(inputUrl)
        # getters
        self.assertEqual(str(u), inputUrl)
        self.assertEqual(u.href, inputUrl)
        self.assertEqual(u.origin, 'http://host:1234')
        self.assertEqual(u.protocol, 'http:')
        self.assertEqual(u.username, 'u')
        self.assertEqual(u.password, 'p')
        self.assertEqual(u.host, 'host:1234')
        self.assertEqual(u.hostname, 'host')
        self.assertEqual(u.port, '1234')
        self.assertEqual(u.pathname, '/pa/th')
        self.assertEqual(u.search, '?a=1')
        self.assertEqual(u.hash, '#frag')
        # setters
        u.href = 'ws://^^^/'
        self.assertEqual(u.href, inputUrl)
        u.href = 'ws://abc/'
        self.assertEqual(u.href, 'ws://abc/')
        u.protocol = 'http:'
        u.username = 'u'
        u.password = 'p'
        u.host = 'tsoh:4321'
        self.assertEqual(u.host, 'tsoh:4321')
        u.hostname = 'host'
        u.port = '1234'
        u.pathname = '/pa/th'
        u.search = '?a=1'
        u.hash = '#frag'
        self.assertEqual(str(u), inputUrl)

    # searchParams
    def test_search_params(self):
        u = URL('http://host?a=1')
        sp = u.searchParams
        sp.append('b', '2')
        self.assertEqual(list(sp), [('a', '1'), ('b', '2')])
        self.assertEqual(u.href, 'http://host/?a=1&b=2')

class TestURLSearchParams(unittest.TestCase):

    def test_construct(self):
        sp = URLSearchParams()
        self.assertEqual(list(sp), [])
        input = '?a=1&b=2'
        sp = URLSearchParams(input)
        self.assertEqual(list(sp), [('a', '1'), ('b', '2')])

    def test_functions(self):
        input = 'a=1&b=2'
        sp = URLSearchParams(input)
        self.assertEqual(str(sp), input)
        self.assertEqual(sp.size, 2)
        self.assertEqual(len(sp), 2)
        # manipulate
        sp.append('b', '3')
        self.assertEqual(str(sp), input + '&b=3')
        sp.delete('b', None)
        self.assertEqual(str(sp), 'a=1')
        sp.delete('a', '1')
        self.assertEqual(str(sp), '')

        sp = URLSearchParams('a=1&a=2&b=3')
        self.assertEqual(sp.get('a'), '1')
        self.assertIsNone(sp.get('Z'))
        self.assertEqual(sp.getAll('a'), ['1', '2'])
        self.assertEqual(sp.getAll('Z'), [])
        self.assertTrue(sp.has('a'))
        self.assertTrue(sp.has('a', None))
        self.assertTrue(sp.has('a', '2'))
        sp.set('b', '4')
        self.assertEqual(sp.getAll('b'), ['4'])
        sp.set('c', '5')
        self.assertEqual(sp.getAll('c'), ['5'])

        sp = URLSearchParams('b=2&a=1')
        self.assertEqual(list(sp), [('b', '2'), ('a', '1')])
        sp.sort()
        self.assertEqual(list(sp), [('a', '1'), ('b', '2')])

if __name__ == '__main__':
    unittest.main()
