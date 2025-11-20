import os
import unittest
from upa_url import PSL, URL

class TestPSL(unittest.TestCase):

    def test_psl_push(self):
        # push_line
        psl = PSL()
        psl.push_line('github.io')
        self.assertTrue(psl.finalize())
        self.assertEqual(psl.public_suffix('upa-url.github.io'), 'github.io')
        self.assertEqual(psl.public_suffix('abc.io'), 'io')

        # push
        psl = PSL()
        psl.push('githu')
        psl.push('b.io')
        psl.push(b'\ngov.lt')
        self.assertTrue(psl.finalize())
        self.assertEqual(psl.public_suffix('data.gov.lt'), 'gov.lt')
        self.assertEqual(psl.public_suffix('upa-url.github.io.'), 'github.io.')
        self.assertEqual(psl.public_suffix('abc.io.'), 'io.')

        # push error
        psl = PSL()
        psl.push('^.com')
        self.assertFalse(psl.finalize())

    def test_psl_construct(self):
        # Use constructor to load the list
        dir = os.path.dirname(os.path.realpath(__file__))
        psl = PSL(os.path.join(dir, 'PSL.dat'))
        # public suffix
        self.assertEqual(psl.public_suffix('any.org.uk'), 'org.uk')

        # Load error
        with self.assertRaises(RuntimeError):
            PSL(os.path.join(dir, 'no_such_file.dat'))

    def test_psl(self):
        # Load list
        dir = os.path.dirname(os.path.realpath(__file__))
        psl = PSL.load(os.path.join(dir, 'PSL.dat'))
        self.assertIsNotNone(psl)

        # URL for tests
        url = URL('https://upa-url.github.io/')

        # Test public suffix
        self.assertEqual(psl.public_suffix(url), 'github.io')
        self.assertEqual(psl.public_suffix('upa-url.github.io.'), 'github.io.')
        self.assertEqual(psl.public_suffix('ąž'), 'xn--2da6v')
        self.assertEqual(psl.public_suffix('ąž', ascii=False), 'ąž')

        # Test registrable domain
        self.assertEqual(psl.registrable_domain(url), 'upa-url.github.io')
        self.assertEqual(psl.registrable_domain('upa-url.github.io.'), 'upa-url.github.io.')
        self.assertEqual(psl.registrable_domain('upa.ąž'), 'upa.xn--2da6v')
        self.assertEqual(psl.registrable_domain('upa.ąž', ascii=False), 'upa.ąž')

if __name__ == '__main__':
    unittest.main()
