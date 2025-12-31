# API Reference

Complete reference for all types and functions provided by the URLPattern extension.

## URLPATTERN Type

The extension provides a custom `URLPATTERN` type for storing and working with URL patterns.

### Creating URLPATTERNs

**Constructor:**
```sql
urlpattern(pattern VARCHAR) → URLPATTERN
```

Creates a validated URLPATTERN from a string. Throws an error if the pattern is invalid.

```sql
-- Create a URLPATTERN explicitly
SELECT urlpattern('https://example.com/users/:id');

-- Use in table definitions
CREATE TABLE routes (
    name VARCHAR,
    pattern URLPATTERN
);

INSERT INTO routes VALUES
    ('users', 'https://example.com/users/:id'),
    ('posts', 'https://example.com/posts/:slug');
```

### Implicit Casting

VARCHAR strings are automatically cast to URLPATTERN when passed to functions expecting the type:

```sql
-- Both of these work:
SELECT urlpattern_test(urlpattern('https://example.com/*'), 'https://example.com/test');
SELECT urlpattern_test('https://example.com/*', 'https://example.com/test');
```

The implicit cast validates the pattern - invalid patterns will throw an error.

### Type Checking

```sql
SELECT typeof(urlpattern('https://example.com/*'));
-- Returns: URLPATTERN
```

---

## Pattern Matching

### urlpattern_test

Tests whether a URL matches a pattern.

**Signature:**
```sql
urlpattern_test(pattern URLPATTERN, url VARCHAR) → BOOLEAN
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `pattern` | URLPATTERN | The URLPattern to match against (VARCHAR is implicitly cast) |
| `url` | VARCHAR | The URL to test |

**Returns:** `BOOLEAN` - `true` if the URL matches the pattern, `false` otherwise.

**Examples:**

```sql
-- Basic wildcard matching
SELECT urlpattern_test('https://example.com/*', 'https://example.com/test');
-- Returns: true

-- Named group matching
SELECT urlpattern_test('https://example.com/users/:id', 'https://example.com/users/123');
-- Returns: true

-- Non-matching URL
SELECT urlpattern_test('https://example.com/users/:id', 'https://example.com/posts/123');
-- Returns: false

-- Protocol mismatch
SELECT urlpattern_test('https://example.com/*', 'http://example.com/test');
-- Returns: false
```

**Notes:**

- The pattern must be a valid URLPattern string
- Both protocol and hostname are matched by default
- Use `*` for wildcards in any component

---

## Full Pattern Execution

### urlpattern_exec

Executes a pattern against a URL and returns complete match information including all captured groups.

**Signature:**
```sql
urlpattern_exec(pattern URLPATTERN, url VARCHAR) → STRUCT
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `pattern` | URLPATTERN | The URLPattern to match against (VARCHAR is implicitly cast) |
| `url` | VARCHAR | The URL to test |

**Returns:** A `STRUCT` with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `matched` | BOOLEAN | Whether the URL matched the pattern |
| `protocol` | VARCHAR | The matched protocol value |
| `hostname` | VARCHAR | The matched hostname value |
| `port` | VARCHAR | The matched port value |
| `pathname` | VARCHAR | The matched pathname value |
| `search` | VARCHAR | The matched search/query value |
| `hash` | VARCHAR | The matched hash/fragment value |
| `groups` | MAP(VARCHAR, VARCHAR) | All captured named groups from all URL components |

**Examples:**

```sql
-- Basic execution with group extraction
SELECT urlpattern_exec(
    'https://example.com/users/:id',
    'https://example.com/users/123'
);
-- Returns: {'matched': true, 'protocol': 'https', 'hostname': 'example.com',
--           'port': '', 'pathname': '/users/123', 'search': '', 'hash': '',
--           'groups': {id=123}}

-- Access specific fields
SELECT (urlpattern_exec(
    'https://example.com/users/:id',
    'https://example.com/users/123'
)).matched;
-- Returns: true

-- Extract a specific group
SELECT (urlpattern_exec(
    'https://example.com/users/:id',
    'https://example.com/users/123'
)).groups['id'];
-- Returns: '123'

-- Multiple groups from different URL components
SELECT (urlpattern_exec(
    'https://:tenant.example.com/api/:version/*',
    'https://acme.example.com/api/v2/users'
)).groups;
-- Returns: {tenant=acme, version=v2}

-- Non-matching URL
SELECT (urlpattern_exec(
    'https://example.com/users/:id',
    'https://example.com/posts/123'
)).matched;
-- Returns: false
```

**Notes:**

- Returns `NULL` if either input is `NULL`
- When `matched` is `false`, all other fields are empty strings and `groups` is an empty map
- Groups from all URL components (protocol, hostname, port, pathname, search, hash) are merged into a single map
- Numeric/positional groups (like `0` for full component match) are excluded from the `groups` map

---

## Group Extraction

### urlpattern_extract

Extracts a named group's value from a URL that matches a pattern.

**Signature:**
```sql
urlpattern_extract(pattern URLPATTERN, url VARCHAR, group_name VARCHAR) → VARCHAR
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `pattern` | URLPATTERN | The URLPattern containing named groups (VARCHAR is implicitly cast) |
| `url` | VARCHAR | The URL to extract from |
| `group_name` | VARCHAR | The name of the group to extract |

**Returns:** `VARCHAR` - The captured value, or empty string if not found.

**Examples:**

```sql
-- Extract user ID
SELECT urlpattern_extract(
    'https://example.com/users/:id',
    'https://example.com/users/123',
    'id'
);
-- Returns: '123'

-- Extract from multiple groups
SELECT urlpattern_extract(
    'https://example.com/api/:version/:resource',
    'https://example.com/api/v1/users',
    'version'
);
-- Returns: 'v1'

-- Extract from hostname
SELECT urlpattern_extract(
    'https://:subdomain.example.com/*',
    'https://api.example.com/test',
    'subdomain'
);
-- Returns: 'api'
```

**Notes:**

- The group name must match a `:name` pattern in the pattern string
- Returns empty string if the group doesn't exist or URL doesn't match
- Groups can be in any URL component (pathname, hostname, etc.)

---

## Pattern Component Accessors

These functions parse a URLPattern and return the pattern string for a specific component.

### urlpattern_pathname

Returns the pathname component of a pattern.

**Signature:**
```sql
urlpattern_pathname(pattern URLPATTERN) → VARCHAR
```

**Example:**
```sql
SELECT urlpattern_pathname('https://example.com/users/:id/*');
-- Returns: '/users/:id/*'
```

---

### urlpattern_protocol

Returns the protocol component of a pattern.

**Signature:**
```sql
urlpattern_protocol(pattern URLPATTERN) → VARCHAR
```

**Example:**
```sql
SELECT urlpattern_protocol('https://example.com/*');
-- Returns: 'https'
```

---

### urlpattern_hostname

Returns the hostname component of a pattern.

**Signature:**
```sql
urlpattern_hostname(pattern URLPATTERN) → VARCHAR
```

**Example:**
```sql
SELECT urlpattern_hostname('https://*.example.com/*');
-- Returns: '*.example.com'
```

---

### urlpattern_port

Returns the port component of a pattern.

**Signature:**
```sql
urlpattern_port(pattern URLPATTERN) → VARCHAR
```

**Example:**
```sql
SELECT urlpattern_port('https://example.com:8080/*');
-- Returns: '8080'

-- When no port is specified
SELECT urlpattern_port('https://example.com/*');
-- Returns: '' (empty string)
```

---

### urlpattern_search

Returns the search (query string) component of a pattern.

**Signature:**
```sql
urlpattern_search(pattern URLPATTERN) → VARCHAR
```

**Example:**
```sql
SELECT urlpattern_search('https://example.com/search?q=:query');
-- Returns: 'q=:query'
```

---

### urlpattern_hash

Returns the hash (fragment) component of a pattern.

**Signature:**
```sql
urlpattern_hash(pattern URLPATTERN) → VARCHAR
```

**Example:**
```sql
SELECT urlpattern_hash('https://example.com/page#section');
-- Returns: 'section'
```

---

## Error Handling

All functions throw an `InvalidInputException` when given an invalid pattern:

```sql
-- Invalid pattern syntax
SELECT urlpattern_test('https://[invalid', 'https://example.com');
-- Error: Invalid URL pattern: https://[invalid
```

## Function Summary

| Function | Purpose | Return Type |
|----------|---------|-------------|
| `urlpattern` | Create URLPATTERN from string | URLPATTERN |
| `urlpattern_test` | Test if URL matches pattern | BOOLEAN |
| `urlpattern_exec` | Execute pattern and return full match info | STRUCT |
| `urlpattern_extract` | Extract named group value | VARCHAR |
| `urlpattern_pathname` | Get pathname from pattern | VARCHAR |
| `urlpattern_protocol` | Get protocol from pattern | VARCHAR |
| `urlpattern_hostname` | Get hostname from pattern | VARCHAR |
| `urlpattern_port` | Get port from pattern | VARCHAR |
| `urlpattern_search` | Get search/query from pattern | VARCHAR |
| `urlpattern_hash` | Get hash/fragment from pattern | VARCHAR |
