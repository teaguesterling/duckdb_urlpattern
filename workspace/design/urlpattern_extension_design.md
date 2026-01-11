# DuckDB URLPattern Extension Design

## Overview

This document outlines the design for a DuckDB extension that implements the [WHATWG URLPattern API](https://urlpattern.spec.whatwg.org/). The extension provides pattern-based URL matching capabilities, enabling users to test URLs against patterns and extract matched components.

## Background

### URLPattern API

The URLPattern API defines a syntax for creating URL pattern matchers. It is based on the [path-to-regexp](https://github.com/pillarjs/path-to-regexp) library and provides:

- **Pattern matching** against full URLs or individual URL components
- **Named capture groups** for extracting URL parts (`:id`, `:name`)
- **Wildcards** (`*`) for flexible matching
- **Modifiers** (`?`, `+`, `*`) for optional and repeating segments
- **Regular expression constraints** for precise matching

### URL Components

URLPattern operates on 8 URL components:

| Component | Example | Description |
|-----------|---------|-------------|
| `protocol` | `https` | URL scheme |
| `username` | `user` | Authentication username |
| `password` | `pass` | Authentication password |
| `hostname` | `example.com` | Domain name or IP |
| `port` | `8080` | Port number |
| `pathname` | `/api/v1/users` | Path to resource |
| `search` | `?q=test` | Query string |
| `hash` | `#section` | Fragment identifier |

### Implementation Reference

The [Ada URL library](https://github.com/ada-url/ada) provides a C++ URLPattern implementation that passes WHATWG web-platform tests. This extension will leverage Ada's implementation as the core parsing and matching engine.

**Important**: Ada requires an external regex engine (std::regex has ReDoS vulnerabilities). DuckDB already vendors Google RE2 in `third_party/re2/` with a wrapper in `duckdb_re2` namespace - we will use this existing dependency.

**Scope**: This extension implements URLPattern only. URL parsing/extraction is out of scope (see [netquack](https://duckdb.org/community_extensions/extensions/netquack) for that functionality).

---

## DuckDB Types

### 1. URLPATTERN Type

A custom DuckDB type representing a compiled URL pattern.

```sql
-- Type definition
URLPATTERN
```

**Internal representation**: The pattern is stored as a VARCHAR containing the normalized pattern string. The actual compilation happens at execution time (similar to how REGEXP works in DuckDB).

**Alternative consideration**: Store as a STRUCT containing both the original pattern and pre-compiled metadata. This would enable faster repeated matching but increases storage overhead.

```sql
-- Internal STRUCT representation (alternative)
STRUCT(
    pattern VARCHAR,           -- Original pattern string
    protocol VARCHAR,          -- Normalized protocol pattern
    username VARCHAR,          -- Normalized username pattern
    password VARCHAR,          -- Normalized password pattern
    hostname VARCHAR,          -- Normalized hostname pattern
    port VARCHAR,              -- Normalized port pattern
    pathname VARCHAR,          -- Normalized pathname pattern
    search VARCHAR,            -- Normalized search pattern
    hash VARCHAR,              -- Normalized hash pattern
    ignore_case BOOLEAN        -- Case sensitivity flag
)
```

### 2. URLPATTERN_RESULT Type

Result of executing a pattern match (returned by `urlpattern_exec`).

```sql
-- Match result for a single component
STRUCT(
    input VARCHAR,                              -- The matched input string
    groups MAP(VARCHAR, VARCHAR)                -- Captured named/numbered groups
)

-- Full match result
STRUCT(
    matched BOOLEAN,                            -- Whether the match succeeded
    protocol STRUCT(input VARCHAR, groups MAP(VARCHAR, VARCHAR)),
    username STRUCT(input VARCHAR, groups MAP(VARCHAR, VARCHAR)),
    password STRUCT(input VARCHAR, groups MAP(VARCHAR, VARCHAR)),
    hostname STRUCT(input VARCHAR, groups MAP(VARCHAR, VARCHAR)),
    port STRUCT(input VARCHAR, groups MAP(VARCHAR, VARCHAR)),
    pathname STRUCT(input VARCHAR, groups MAP(VARCHAR, VARCHAR)),
    search STRUCT(input VARCHAR, groups MAP(VARCHAR, VARCHAR)),
    hash STRUCT(input VARCHAR, groups MAP(VARCHAR, VARCHAR))
)
```

---

## DuckDB Functions

### Pattern Construction

#### `urlpattern(pattern [, base_url] [, options])`

Creates a URLPATTERN from a pattern string.

```sql
-- Signatures
urlpattern(pattern VARCHAR) -> URLPATTERN
urlpattern(pattern VARCHAR, base_url VARCHAR) -> URLPATTERN
urlpattern(pattern VARCHAR, options STRUCT(ignore_case BOOLEAN)) -> URLPATTERN
urlpattern(pattern VARCHAR, base_url VARCHAR, options STRUCT(ignore_case BOOLEAN)) -> URLPATTERN
```

**Examples**:
```sql
-- Simple pathname pattern
SELECT urlpattern('/books/:id');

-- Full URL pattern
SELECT urlpattern('https://example.com/api/:version/*');

-- Pattern with base URL
SELECT urlpattern('/users/:id', 'https://api.example.com');

-- Case-insensitive matching
SELECT urlpattern('/Products/:id', {'ignore_case': true});
```

#### `urlpattern_init(protocol, hostname, pathname, ...)`

Creates a URLPATTERN from individual component patterns (object syntax).

```sql
-- Signature
urlpattern_init(
    protocol VARCHAR DEFAULT '*',
    username VARCHAR DEFAULT '*',
    password VARCHAR DEFAULT '*',
    hostname VARCHAR DEFAULT '*',
    port VARCHAR DEFAULT '*',
    pathname VARCHAR DEFAULT '*',
    search VARCHAR DEFAULT '*',
    hash VARCHAR DEFAULT '*',
    ignore_case BOOLEAN DEFAULT false
) -> URLPATTERN
```

**Examples**:
```sql
-- Match any protocol, specific hostname and pathname
SELECT urlpattern_init(
    hostname := 'example.com',
    pathname := '/api/:version/:resource'
);

-- Match HTTP or HTTPS
SELECT urlpattern_init(
    protocol := 'http{s}?',
    hostname := '*.example.com'
);
```

---

### Pattern Matching

#### `urlpattern_test(pattern, url [, base_url])`

Tests if a URL matches the pattern. Returns `BOOLEAN`.

```sql
-- Signatures
urlpattern_test(pattern URLPATTERN, url VARCHAR) -> BOOLEAN
urlpattern_test(pattern URLPATTERN, url VARCHAR, base_url VARCHAR) -> BOOLEAN
urlpattern_test(pattern VARCHAR, url VARCHAR) -> BOOLEAN  -- convenience overload
```

**Examples**:
```sql
-- Basic matching
SELECT urlpattern_test(urlpattern('/books/:id'), 'https://example.com/books/123');
-- Returns: true

SELECT urlpattern_test(urlpattern('/books/:id'), 'https://example.com/users/123');
-- Returns: false

-- Inline pattern (convenience)
SELECT urlpattern_test('/api/*', 'https://example.com/api/v1/users');
-- Returns: true

-- Filter URLs in a table
SELECT url
FROM web_logs
WHERE urlpattern_test('/api/:version/users/:id', url);
```

#### `urlpattern_exec(pattern, url [, base_url])`

Executes pattern matching and returns captured groups. Returns `URLPATTERN_RESULT` or `NULL` if no match.

```sql
-- Signatures
urlpattern_exec(pattern URLPATTERN, url VARCHAR) -> URLPATTERN_RESULT
urlpattern_exec(pattern URLPATTERN, url VARCHAR, base_url VARCHAR) -> URLPATTERN_RESULT
urlpattern_exec(pattern VARCHAR, url VARCHAR) -> URLPATTERN_RESULT  -- convenience
```

**Examples**:
```sql
-- Extract captured groups
SELECT urlpattern_exec('/users/:id/posts/:post_id', 'https://example.com/users/42/posts/100');
-- Returns: {
--   matched: true,
--   pathname: {
--     input: '/users/42/posts/100',
--     groups: {'id': '42', 'post_id': '100'}
--   },
--   ...
-- }

-- Access specific groups
SELECT urlpattern_exec('/users/:id', url).pathname.groups['id'] as user_id
FROM web_logs;

-- Extract hostname subdomain
SELECT urlpattern_exec(
    urlpattern_init(hostname := ':subdomain.example.com'),
    'https://api.example.com/test'
).hostname.groups['subdomain'];
-- Returns: 'api'
```

---

### Pattern Component Accessors

These functions return the normalized pattern string for each URL component.

```sql
urlpattern_protocol(pattern URLPATTERN) -> VARCHAR
urlpattern_username(pattern URLPATTERN) -> VARCHAR
urlpattern_password(pattern URLPATTERN) -> VARCHAR
urlpattern_hostname(pattern URLPATTERN) -> VARCHAR
urlpattern_port(pattern URLPATTERN) -> VARCHAR
urlpattern_pathname(pattern URLPATTERN) -> VARCHAR
urlpattern_search(pattern URLPATTERN) -> VARCHAR
urlpattern_hash(pattern URLPATTERN) -> VARCHAR
```

**Examples**:
```sql
SELECT urlpattern_pathname(urlpattern('https://example.com/api/:version/*'));
-- Returns: '/api/:version/*'

SELECT urlpattern_hostname(urlpattern('https://*.example.com/'));
-- Returns: '*.example.com'
```

#### `urlpattern_has_regexp_groups(pattern)`

Returns whether the pattern contains regular expression groups.

```sql
urlpattern_has_regexp_groups(pattern URLPATTERN) -> BOOLEAN
```

**Examples**:
```sql
SELECT urlpattern_has_regexp_groups(urlpattern('/books/:id'));
-- Returns: false

SELECT urlpattern_has_regexp_groups(urlpattern('/books/(\\d+)'));
-- Returns: true
```

---

### Convenience Extraction Functions

These functions combine pattern matching with immediate group extraction for common use cases.

#### `urlpattern_extract(pattern, url, group_name)`

Extracts a single named group from the pathname (most common use case).

```sql
urlpattern_extract(pattern VARCHAR, url VARCHAR, group_name VARCHAR) -> VARCHAR
```

**Examples**:
```sql
SELECT urlpattern_extract('/users/:id', url, 'id') as user_id
FROM web_logs;

-- Equivalent to:
SELECT urlpattern_exec('/users/:id', url).pathname.groups['id'] as user_id
FROM web_logs;
```

#### `urlpattern_extract_all(pattern, url)`

Extracts all named groups from the pathname as a MAP.

```sql
urlpattern_extract_all(pattern VARCHAR, url VARCHAR) -> MAP(VARCHAR, VARCHAR)
```

**Examples**:
```sql
SELECT urlpattern_extract_all('/api/:version/:resource/:id', url) as params
FROM web_logs;
-- Returns: {'version': 'v1', 'resource': 'users', 'id': '123'}
```

---

### Cast Functions

#### VARCHAR to URLPATTERN

Implicit cast for convenience in function arguments.

```sql
-- These are equivalent:
SELECT urlpattern_test(urlpattern('/api/*'), url);
SELECT urlpattern_test('/api/*', url);  -- VARCHAR auto-cast to URLPATTERN
```

#### URLPATTERN to VARCHAR

Returns the normalized pattern string representation.

```sql
SELECT CAST(urlpattern('/api/:id') AS VARCHAR);
-- Returns: normalized pattern string
```

---

## Function Summary Table

| Function | Return Type | Description |
|----------|-------------|-------------|
| `urlpattern(pattern, [base_url], [options])` | `URLPATTERN` | Create pattern from string |
| `urlpattern_init(protocol, hostname, ...)` | `URLPATTERN` | Create pattern from components |
| `urlpattern_test(pattern, url, [base_url])` | `BOOLEAN` | Test if URL matches |
| `urlpattern_exec(pattern, url, [base_url])` | `URLPATTERN_RESULT` | Execute match, return groups |
| `urlpattern_protocol(pattern)` | `VARCHAR` | Get protocol pattern |
| `urlpattern_username(pattern)` | `VARCHAR` | Get username pattern |
| `urlpattern_password(pattern)` | `VARCHAR` | Get password pattern |
| `urlpattern_hostname(pattern)` | `VARCHAR` | Get hostname pattern |
| `urlpattern_port(pattern)` | `VARCHAR` | Get port pattern |
| `urlpattern_pathname(pattern)` | `VARCHAR` | Get pathname pattern |
| `urlpattern_search(pattern)` | `VARCHAR` | Get search pattern |
| `urlpattern_hash(pattern)` | `VARCHAR` | Get hash pattern |
| `urlpattern_has_regexp_groups(pattern)` | `BOOLEAN` | Check for regexp groups |
| `urlpattern_extract(pattern, url, group)` | `VARCHAR` | Extract single group |
| `urlpattern_extract_all(pattern, url)` | `MAP(VARCHAR,VARCHAR)` | Extract all groups |

---

## Implementation Architecture

### Dependencies

1. **Ada URL Library** (v3.0+) - C++ URLPattern implementation
   - WHATWG compliant
   - Web-platform test compatible
   - Header-only option available

2. **DuckDB's Vendored RE2** (`third_party/re2/`, `duckdb_re2` namespace)
   - Already included in DuckDB - no additional dependency
   - No ReDoS vulnerabilities
   - Linear time matching
   - Wrapper API: `duckdb_re2::Regex`, `RegexMatch()`, `RegexSearch()`

### Regex Provider Implementation

Ada requires a regex provider conforming to this interface. We'll implement it using DuckDB's RE2 wrapper:

```cpp
#include "duckdb/common/re2_regex.hpp"

class duckdb_re2_regex_provider {
public:
    using regex_type = duckdb_re2::Regex;

    static std::optional<regex_type> create_instance(
        std::string_view pattern,
        bool ignore_case
    ) {
        auto options = ignore_case
            ? duckdb_re2::RegexOptions::CASE_INSENSITIVE
            : duckdb_re2::RegexOptions::NONE;
        try {
            return regex_type(std::string(pattern), options);
        } catch (...) {
            return std::nullopt;
        }
    }

    static std::optional<std::vector<std::optional<std::string>>> regex_search(
        std::string_view input,
        const regex_type& pattern
    ) {
        duckdb_re2::Match match;
        if (!duckdb_re2::RegexSearch(std::string(input), match, pattern)) {
            return std::nullopt;
        }
        std::vector<std::optional<std::string>> groups;
        for (auto& group : match.groups) {
            groups.push_back(group.text);
        }
        return groups;
    }

    static bool regex_match(
        std::string_view input,
        const regex_type& pattern
    ) {
        return duckdb_re2::RegexMatch(std::string(input), pattern);
    }
};
```

### Extension Structure

```
src/
├── include/
│   ├── urlpattern_extension.hpp       # Extension class definition
│   ├── urlpattern_type.hpp            # URLPATTERN type definition
│   ├── urlpattern_functions.hpp       # Function declarations
│   └── duckdb_re2_regex_provider.hpp  # DuckDB RE2 adapter for Ada
├── urlpattern_extension.cpp           # Extension entry point
├── urlpattern_type.cpp                # Type registration & casts
└── urlpattern_functions.cpp           # Function implementations
```

---

## Usage Examples

### Web Log Analysis

```sql
-- Load extension
LOAD urlpattern;

-- Create a table of URL patterns for route classification
CREATE TABLE routes (
    name VARCHAR,
    pattern URLPATTERN
);

INSERT INTO routes VALUES
    ('user_profile', urlpattern('/users/:id')),
    ('user_posts', urlpattern('/users/:id/posts')),
    ('api_resource', urlpattern('/api/:version/:resource/:id?'));

-- Classify URLs from access logs
SELECT
    l.url,
    r.name as route,
    urlpattern_extract(r.pattern, l.url, 'id') as resource_id
FROM access_logs l
LEFT JOIN routes r ON urlpattern_test(r.pattern, l.url);
```

### API Analytics

```sql
-- Extract API version distribution
SELECT
    urlpattern_extract('/api/:version/*', url, 'version') as api_version,
    COUNT(*) as request_count
FROM api_logs
WHERE urlpattern_test('/api/:version/*', url)
GROUP BY 1;
```

### URL Validation

```sql
-- Find URLs matching a specific pattern
SELECT url
FROM links
WHERE urlpattern_test(
    urlpattern_init(
        protocol := 'https',
        hostname := '*.example.com',
        pathname := '/secure/*'
    ),
    url
);
```

### Extract Multiple Parameters

```sql
-- Parse complex URLs into structured data
SELECT
    url,
    (urlpattern_exec('/products/:category/:id', url)).pathname.groups as params
FROM product_urls;
```

---

## Open Questions

1. **Pattern Caching**: Should compiled patterns be cached per-query or per-connection?
   - Per-query: Simpler, but recompiles for each row
   - Per-connection: Faster for repeated patterns, but more complex state management

2. **Error Handling**: How should invalid patterns be handled?
   - Option A: Return NULL (silent failure)
   - Option B: Raise exception (strict)
   - Option C: Configurable via extension setting

3. **Pattern Normalization**: Should the URLPATTERN type store original or normalized patterns?
   - Original: Preserves user intent
   - Normalized: Enables pattern comparison/deduplication

4. **Aggregate Functions**: Should we add pattern-based aggregations?
   - `urlpattern_count(pattern, url)` - Count matching URLs
   - `urlpattern_collect(pattern, url, group)` - Collect group values

## Design Decisions

1. **URL Type**: Out of scope. This extension focuses on URLPattern only. For URL parsing/extraction, see [netquack](https://duckdb.org/community_extensions/extensions/netquack).

2. **Regex Engine**: Use DuckDB's vendored RE2 (`duckdb_re2` namespace) - no additional dependencies required.

---

## References

- [WHATWG URLPattern Specification](https://urlpattern.spec.whatwg.org/)
- [MDN URLPattern API](https://developer.mozilla.org/en-US/docs/Web/API/URL_Pattern_API)
- [Ada URL Library](https://github.com/ada-url/ada)
- [Google RE2](https://github.com/google/re2)
- [path-to-regexp](https://github.com/pillarjs/path-to-regexp)
