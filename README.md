# DuckDB URLPattern Extension

A DuckDB extension implementing the [WHATWG URLPattern API](https://urlpattern.spec.whatwg.org/) for powerful URL matching and extraction in SQL.

## Features

- **URLPATTERN Type** - Custom type for storing and validating URL patterns
- **Pattern Matching** - Test URLs against patterns with wildcards and named groups
- **Group Extraction** - Extract captured values from URLs
- **URL Parsing** - Parse URLs into components (protocol, host, path, query, etc.)
- **Query Parameters** - Extract and parse URL query parameters
- **URL Resolution** - Resolve relative URLs against base URLs
- **WHATWG Compliant** - Follows the official URLPattern specification
- **High Performance** - RE2 regex engine with pattern caching (~320k matches/sec)

## Quick Start

```sql
-- Load the extension
LOAD urlpattern;

-- Test if a URL matches a pattern
SELECT urlpattern_test('https://example.com/users/:id', 'https://example.com/users/123');
-- Returns: true

-- Extract a named group
SELECT urlpattern_extract('https://example.com/users/:id', 'https://example.com/users/123', 'id');
-- Returns: '123'

-- Get full match details
SELECT urlpattern_exec('https://example.com/users/:id', 'https://example.com/users/123');
-- Returns: {matched: true, pathname: '/users/123', groups: {id=123}, ...}

-- Store patterns in tables
CREATE TABLE routes (name VARCHAR, pattern URLPATTERN);
INSERT INTO routes VALUES ('users', 'https://api.example.com/users/:id');

SELECT name FROM routes
WHERE urlpattern_test(pattern, 'https://api.example.com/users/456');
```

## Installation

### Building from Source

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/teaguesterling/duckdb_urlpattern.git
cd duckdb_urlpattern

# Build (requires GCC 12+ for C++20 support)
GEN=ninja make release

# Run tests
make test
```

### Requirements

- CMake 3.15+
- GCC 12+ or Clang 15+ (C++20 required)
- Ninja (recommended) or Make

## Functions

### Pattern Matching

| Function | Description |
|----------|-------------|
| `urlpattern(pattern)` | Create a validated URLPATTERN |
| `urlpattern_init(...)` | Create pattern from components (supports path-only, ignore_case, base_url) |
| `urlpattern_test(pattern, url)` | Test if URL matches pattern |
| `urlpattern_exec(pattern, url)` | Execute pattern and return full match info |
| `urlpattern_extract(pattern, url, group)` | Extract a named group value |
| `urlpattern_pathname(pattern)` | Get pathname component of pattern |
| `urlpattern_protocol(pattern)` | Get protocol component of pattern |
| `urlpattern_hostname(pattern)` | Get hostname component of pattern |
| `urlpattern_port(pattern)` | Get port component of pattern |
| `urlpattern_search(pattern)` | Get search/query component of pattern |
| `urlpattern_hash(pattern)` | Get hash/fragment component of pattern |

### URL Parsing

| Function | Description |
|----------|-------------|
| `url_parse(url)` | Parse URL into struct with all components |
| `url_protocol(url)` | Get protocol (e.g., 'https:') |
| `url_host(url)` | Get host including port (e.g., 'example.com:8080') |
| `url_hostname(url)` | Get hostname without port |
| `url_port(url)` | Get port number |
| `url_pathname(url)` | Get path (e.g., '/users/123') |
| `url_search(url)` | Get query string including '?' |
| `url_hash(url)` | Get fragment including '#' |
| `url_origin(url)` | Get origin (protocol + host) |
| `url_username(url)` | Get username from URL |
| `url_password(url)` | Get password from URL |
| `url_href(url)` | Get normalized URL |
| `url_valid(url)` | Check if URL is valid |

### Query Parameters

| Function | Description |
|----------|-------------|
| `url_search_params(url)` | Get all query params as MAP |
| `url_search_param(url, name)` | Get single query parameter value |

### URL Resolution

| Function | Description |
|----------|-------------|
| `url_resolve(base, relative)` | Resolve relative URL against base |

## Path-Only Patterns

Patterns starting with `/` are automatically treated as pathname-only patterns, matching any protocol and hostname:

```sql
-- Simple path pattern (auto-detected)
SELECT urlpattern_test('/users/:id', 'https://example.com/users/123');
-- Returns: true

-- Works with any host
SELECT urlpattern_test('/api/*', 'http://localhost:8080/api/v1/users');
-- Returns: true

-- Extract named groups
SELECT urlpattern_extract('/users/:id', 'https://example.com/users/456', 'id');
-- Returns: '456'
```

For more control, use `urlpattern_init` to specify individual components:

```sql
-- Explicit pathname-only pattern
SELECT urlpattern_test(
    urlpattern_init(pathname := '/users/:id'),
    'https://example.com/users/123'
);

-- Combine hostname and pathname
SELECT urlpattern_test(
    urlpattern_init(
        hostname := '*.example.com',
        pathname := '/api/*'
    ),
    'https://api.example.com/api/users'
);

-- Restrict to specific protocol
SELECT urlpattern_test(
    urlpattern_init(protocol := 'https', pathname := '/secure/*'),
    'http://example.com/secure/data'  -- Returns false (wrong protocol)
);
```

Available parameters: `protocol`, `hostname`, `port`, `pathname`, `search`, `hash`, `username`, `password`, `ignore_case`, `base_url`

## Case-Insensitive Matching

Enable case-insensitive pattern matching with `ignore_case`:

```sql
-- Case-sensitive by default (returns false)
SELECT urlpattern_test(urlpattern_init(pathname := '/Users/:id'), 'https://example.com/users/123');

-- Case-insensitive matching (returns true)
SELECT urlpattern_test(
    urlpattern_init(pathname := '/Users/:id', ignore_case := true),
    'https://example.com/users/123'
);
```

## URL Parsing

Parse URLs into components (separate from pattern matching):

```sql
-- Parse URL into struct with all components
SELECT url_parse('https://user:pass@example.com:8080/path?q=test#section');
-- Returns: {href, origin, protocol, username, password, host, hostname, port, pathname, search, hash}

-- Individual component functions
SELECT url_protocol('https://example.com/path');  -- 'https:'
SELECT url_hostname('https://example.com:8080');  -- 'example.com'
SELECT url_pathname('https://example.com/users/123');  -- '/users/123'
SELECT url_search('https://example.com?q=test');  -- '?q=test'
SELECT url_hash('https://example.com#section');  -- '#section'

-- Validate URL
SELECT url_valid('https://example.com');  -- true
SELECT url_valid('not a url');  -- false
```

## Query Parameters

Extract query parameters from URLs:

```sql
-- Get all parameters as a MAP
SELECT url_search_params('https://example.com?page=5&sort=asc');
-- Returns: {page: '5', sort: 'asc'}

-- Get a single parameter
SELECT url_search_param('https://example.com?page=5&sort=asc', 'page');
-- Returns: '5'

-- Access map values
SELECT url_search_params('https://example.com?a=1&b=2')['a'];
-- Returns: '1'
```

## URL Resolution

Resolve relative URLs against a base URL:

```sql
-- Resolve relative path
SELECT url_resolve('https://example.com/docs/', '../api/users');
-- Returns: 'https://example.com/api/users'

-- Resolve with current directory
SELECT url_resolve('https://example.com/docs/', 'getting-started');
-- Returns: 'https://example.com/docs/getting-started'

-- Root-relative path
SELECT url_resolve('https://example.com/docs/guide/', '/api/v1');
-- Returns: 'https://example.com/api/v1'
```

## Pattern Syntax

```sql
-- Wildcards
'https://example.com/*'              -- Match any path
'https://*.example.com/*'            -- Match any subdomain

-- Named groups
'https://example.com/users/:id'      -- Capture :id
'https://:tenant.example.com/*'      -- Capture subdomain as :tenant

-- Multiple groups
'https://api.example.com/:version/:resource/:id'
```

## Documentation

Full documentation available at: https://duckdb-urlpattern.readthedocs.io/

## License

MIT License - see [LICENSE](LICENSE) for details.
