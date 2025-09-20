# upa_url package

This package provides Python bindings for [Upa URL](https://github.com/upa-url/upa) – a library compliant with the [WHATWG URL standard](https://url.spec.whatwg.org/). This is the same standard followed by modern browsers and JavaScript runtimes such as Bun, Deno, and Node.js.

This package is designed to be as close to the URL standard as possible. It uses the same class names ([URL](https://url.spec.whatwg.org/#url-class), [URLSearchParams](https://url.spec.whatwg.org/#interface-urlsearchparams)), their function names, the same function parameters, and the same behavior.

## Installation

```sh
pip install upa_url
```

If the binary wheel is not available for your platform, then you will need a C++ compiler that supports C++17 and CMake to build the Python package.

## Getting started

First, you need to import classes:
```python
from upa_url import URL, URLSearchParams
```

### URL class

The `URL` class provides a structured way to parse, manipulate, and serialize URLs.

An URL can be parsed using one of two methods:
1. Use the `URL` constructor. It throws an exception on error:
   ```python
   try:
       url = URL('https://upa-url.github.io/docs/')
       print(url.href)
   except Exception:
       print('URL parse error')
   ```
2. Use the `URL.parse` fucntion. It returns `None` on error:
   ```python
   url = URL.parse('docs', 'https://upa-url.github.io')
   if url is not None:
       print(url.href)
   ```
The components of the parsed URL object can be accessed using getters and setters: `href`, `origin` (only get value), `protocol`, `username`, `password`, `host`, `hostname`, `port`, `pathname`, `search` and `hash`. You can also get and change the search parameters using the `searchParams` getter, which returns the `URLSearchParams` object associated with the URL:
```python
url = URL.parse('https://example.org')
if url is not None:
    url.searchParams.append('lang', 'lt')
    print(url.href) # https://example.org/?lang=lt
```

To serialize a parsed URL, use either `url.href` or `str(url)`.

If you only need to check URL validity, then the `URL.canParse` function can be used:
```python
if URL.canParse('docs', 'https://upa-url.github.io'):
    print('URL is valid')
```

### URLSearchParams class

The `URLSearchParams` class provides a structured way to parse, manipulate, and serialize the query string of a URL.

An `URLSearchParams` object can be created by using a constructor:
1. To create empty: `params = URLSearchParams()`
2. Create from a string: `params = URLSearchParams('lang=lt&id=123')`
3. Create from a dictionary or a list:
   ```python
   params1 = URLSearchParams({'lang': 'lt', 'id': '123'})
   params2 = URLSearchParams([('lang', 'lt'), ['id', '123']])
   ```

Use `get` or `getAll` to retrieve parameter values:
```python
params = URLSearchParams('a=b&a=c&b=10')
print(params.get('a'))    # b
print(params.getAll('a')) # ['b', 'c']
```

To check for name and optionally value in parameters, use the `has` function:
```python
print(params.has('a'))      # True
print(params.has('a', 'c')) # True
print(params.has('c'))      # False
```

Iterate over all parameters:
```python
params = URLSearchParams('a=1&b=2')
# Get all name-value pairs:
for name, value in params:
    print(name, '=', value)
# Get all parameter names
for name in params.keys():
    print(name)
# Get all parameter values
for value in params.values():
    print(value)
```

Count parameters:
```python
print(params.size) # 2
print(len(params)) # 2
```

To serialize a `URLSearchParams` object, use `str(params)`.

There are functions to manipulate search parameters:
1. Add or replace parameters:
   ```python
   params = URLSearchParams('a=a')
   params.append('a', 'aa')
   params.append('b', 'bb')
   print(params) # a=a&a=aa&b=bb
   params.set('a', '1')
   print(params) # a=1&b=bb
   ```
2. Remove parameters:
   ```python
   params = URLSearchParams('a=a&a=aa&b=b&b=bb')
   params.delete('a')
   print(params) # b=b&b=bb
   params.delete('b', 'bb')
   print(params) # b=b
   ```
3. Sort parameters by name:
   ```python
   params = URLSearchParams('c=1&b=2&a=3')
   params.sort()
   print(params) # a=3&b=2&c=1
   ```

## License

This package is licensed under the [BSD 2-Clause License](https://opensource.org/license/bsd-2-clause/) (see `LICENSE` file).
