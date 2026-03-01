import copy
import unittest
import upa_url

class TestFunctions(unittest.TestCase):

    def test_url_from_file_path(self):
        url = upa_url.url_from_file_path('/c:/path', upa_url.file_path_format.posix)
        self.assertEqual(url.href, 'file:///c%3A/path')
        url = upa_url.url_from_file_path('c:\\path', upa_url.file_path_format.windows)
        self.assertEqual(url.href, 'file:///c:/path')
        # Non-absolute path
        with self.assertRaises(BaseException):
            upa_url.url_from_file_path('path')
        with self.assertRaises(BaseException):
            upa_url.url_from_file_path('path', upa_url.file_path_format.posix)
        with self.assertRaises(BaseException):
            upa_url.url_from_file_path('/path', upa_url.file_path_format.windows)

    def test_path_from_file_url(self):
        url = upa_url.URL('file:///c:/path')
        self.assertEqual(upa_url.path_from_file_url(url, upa_url.file_path_format.posix), '/c:/path')
        self.assertEqual(upa_url.path_from_file_url(url, upa_url.file_path_format.windows), 'c:\\path')
        url_str = 'file:///c%3A/path'
        self.assertEqual(upa_url.path_from_file_url(url_str, upa_url.file_path_format.posix), '/c:/path')
        self.assertEqual(upa_url.path_from_file_url(url_str, upa_url.file_path_format.windows), 'c:\\path')
        # The URL cannot be converted to an absolute path
        url = upa_url.URL('file:///path')
        with self.assertRaises(BaseException):
            upa_url.path_from_file_url(url, upa_url.file_path_format.windows)
        # Invalid URL
        url_str = 'file://^/path'
        with self.assertRaises(BaseException):
            upa_url.path_from_file_url(url_str)

if __name__ == '__main__':
    unittest.main()
