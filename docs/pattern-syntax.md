# Pattern Syntax

The URLPattern syntax follows the [WHATWG URLPattern specification](https://urlpattern.spec.whatwg.org/). This guide covers the pattern syntax you can use with this extension.

## URL Components

A URL pattern can match against all components of a URL:

```
protocol://username:password@hostname:port/pathname?search#hash
```

When you provide a full URL pattern like `https://example.com/users/:id`, the pattern is parsed into components that are matched independently.

## Basic Patterns

### Literal Matching

Exact string matching:

```sql
-- Matches only this exact URL
SELECT urlpattern_test(
    'https://example.com/about',
    'https://example.com/about'
);  -- true

SELECT urlpattern_test(
    'https://example.com/about',
    'https://example.com/contact'
);  -- false
```

### Wildcards (`*`)

The `*` wildcard matches any sequence of characters (including empty):

```sql
-- Matches any path under /api/
SELECT urlpattern_test('https://example.com/api/*', 'https://example.com/api/users');  -- true
SELECT urlpattern_test('https://example.com/api/*', 'https://example.com/api/v1/users');  -- true
SELECT urlpattern_test('https://example.com/api/*', 'https://example.com/api/');  -- true
```

Multiple wildcards:

```sql
-- Matches /api/{version}/users/{id}
SELECT urlpattern_test(
    'https://example.com/api/*/users/*',
    'https://example.com/api/v1/users/123'
);  -- true
```

## Named Groups

### Basic Named Groups (`:name`)

Named groups capture a single path segment (up to the next `/`):

```sql
-- :id captures '123'
SELECT urlpattern_test(
    'https://example.com/users/:id',
    'https://example.com/users/123'
);  -- true

-- Extract the captured value
SELECT urlpattern_extract(
    'https://example.com/users/:id',
    'https://example.com/users/123',
    'id'
);  -- '123'
```

### Multiple Named Groups

```sql
SELECT urlpattern_extract(
    'https://example.com/api/:version/:resource/:id',
    'https://example.com/api/v2/posts/456',
    'version'
);  -- 'v2'

SELECT urlpattern_extract(
    'https://example.com/api/:version/:resource/:id',
    'https://example.com/api/v2/posts/456',
    'resource'
);  -- 'posts'

SELECT urlpattern_extract(
    'https://example.com/api/:version/:resource/:id',
    'https://example.com/api/v2/posts/456',
    'id'
);  -- '456'
```

### Named Groups in Other Components

Named groups work in any URL component:

```sql
-- Hostname
SELECT urlpattern_extract(
    'https://:subdomain.example.com/*',
    'https://api.example.com/test',
    'subdomain'
);  -- 'api'

-- Protocol (less common but supported)
SELECT urlpattern_test(
    ':protocol://example.com/*',
    'https://example.com/test'
);  -- true
```

## Component-Specific Patterns

### Protocol

```sql
-- Match only HTTPS
SELECT urlpattern_test('https://example.com/*', 'https://example.com/test');  -- true
SELECT urlpattern_test('https://example.com/*', 'http://example.com/test');   -- false

-- Match any protocol
SELECT urlpattern_test('*://example.com/*', 'https://example.com/test');  -- true
SELECT urlpattern_test('*://example.com/*', 'http://example.com/test');   -- true
```

### Hostname

```sql
-- Exact hostname
SELECT urlpattern_test('https://example.com/*', 'https://example.com/test');      -- true
SELECT urlpattern_test('https://example.com/*', 'https://api.example.com/test');  -- false

-- Wildcard subdomain
SELECT urlpattern_test('https://*.example.com/*', 'https://api.example.com/test');   -- true
SELECT urlpattern_test('https://*.example.com/*', 'https://www.example.com/test');   -- true
SELECT urlpattern_test('https://*.example.com/*', 'https://example.com/test');       -- false (no subdomain)
```

### Port

```sql
-- Specific port
SELECT urlpattern_test('https://example.com:8080/*', 'https://example.com:8080/test');  -- true
SELECT urlpattern_test('https://example.com:8080/*', 'https://example.com:3000/test');  -- false

-- Any port
SELECT urlpattern_test('https://example.com:*/*', 'https://example.com:8080/test');  -- true
```

### Pathname

```sql
-- Single segment wildcard
SELECT urlpattern_test('https://example.com/users/:id', 'https://example.com/users/123');      -- true
SELECT urlpattern_test('https://example.com/users/:id', 'https://example.com/users/123/edit'); -- false

-- Multi-segment wildcard
SELECT urlpattern_test('https://example.com/files/*', 'https://example.com/files/a/b/c.txt');  -- true
```

### Search (Query String)

```sql
-- Wildcard query
SELECT urlpattern_test('https://example.com/search?*', 'https://example.com/search?q=test');  -- true

-- Specific query pattern
SELECT urlpattern_test(
    'https://example.com/search?q=:query',
    'https://example.com/search?q=hello'
);  -- true
```

### Hash (Fragment)

```sql
-- Any hash
SELECT urlpattern_test('https://example.com/page#*', 'https://example.com/page#section1');  -- true

-- Specific hash
SELECT urlpattern_test('https://example.com/page#top', 'https://example.com/page#top');     -- true
SELECT urlpattern_test('https://example.com/page#top', 'https://example.com/page#bottom');  -- false
```

## Pattern Matching Rules

### Segment Boundaries

Named groups (`:name`) match a single segment by default:

- In pathnames, segments are separated by `/`
- In hostnames, segments are separated by `.`

```sql
-- :id matches only one segment
SELECT urlpattern_test('https://example.com/users/:id', 'https://example.com/users/123');       -- true
SELECT urlpattern_test('https://example.com/users/:id', 'https://example.com/users/123/posts'); -- false
```

### Greedy vs Non-Greedy

The `*` wildcard is greedy and matches as much as possible:

```sql
-- * matches 'a/b/c'
SELECT urlpattern_test('https://example.com/*', 'https://example.com/a/b/c');  -- true
```

## Best Practices

1. **Use full URL patterns** for `urlpattern_test` to ensure all components are matched:
   ```sql
   -- Good: explicit about protocol and host
   SELECT urlpattern_test('https://example.com/api/*', url);

   -- May not work as expected with urlpattern_test
   SELECT urlpattern_test('/api/*', url);
   ```

2. **Use named groups for extraction** rather than trying to parse URLs manually:
   ```sql
   -- Good: use named groups
   SELECT urlpattern_extract('https://example.com/users/:id', url, 'id');

   -- Avoid: manual string parsing
   SELECT split_part(url, '/', 5);
   ```

3. **Be specific about what you want to match** to avoid false positives:
   ```sql
   -- Too broad: matches any path
   SELECT urlpattern_test('https://example.com/*', url);

   -- Better: specific to API endpoints
   SELECT urlpattern_test('https://example.com/api/:version/*', url);
   ```
