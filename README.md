# DuckDB URLPattern Extension

A DuckDB extension implementing the [WHATWG URLPattern API](https://urlpattern.spec.whatwg.org/) for powerful URL matching and extraction in SQL.

## Features

- **URLPATTERN Type** - Custom type for storing and validating URL patterns
- **Pattern Matching** - Test URLs against patterns with wildcards and named groups
- **Group Extraction** - Extract captured values from URLs
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

| Function | Description |
|----------|-------------|
| `urlpattern(pattern)` | Create a validated URLPATTERN |
| `urlpattern_test(pattern, url)` | Test if URL matches pattern |
| `urlpattern_exec(pattern, url)` | Execute pattern and return full match info |
| `urlpattern_extract(pattern, url, group)` | Extract a named group value |
| `urlpattern_pathname(pattern)` | Get pathname component |
| `urlpattern_protocol(pattern)` | Get protocol component |
| `urlpattern_hostname(pattern)` | Get hostname component |
| `urlpattern_port(pattern)` | Get port component |
| `urlpattern_search(pattern)` | Get search/query component |
| `urlpattern_hash(pattern)` | Get hash/fragment component |

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
