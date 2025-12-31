# DuckDB URLPattern Extension

A DuckDB extension that implements the [WHATWG URLPattern API](https://urlpattern.spec.whatwg.org/) for powerful URL matching and extraction directly in SQL.

## Overview

The URLPattern API provides a web-standard way to match URLs against patterns, similar to how routing works in web frameworks. This extension brings that capability to DuckDB, enabling you to:

- **Match URLs** against patterns with wildcards and named groups
- **Extract components** from URLs using named capture groups
- **Inspect patterns** to retrieve their individual components

## Quick Start

```sql
-- Load the extension
LOAD urlpattern;

-- Test if a URL matches a pattern
SELECT urlpattern_test(
    'https://example.com/users/:id',
    'https://example.com/users/123'
);
-- Returns: true

-- Extract a named group from a URL
SELECT urlpattern_extract(
    'https://example.com/users/:id',
    'https://example.com/users/123',
    'id'
);
-- Returns: '123'
```

## Features

| Feature | Description |
|---------|-------------|
| **URLPATTERN Type** | Custom type for storing and validating URL patterns |
| **Pattern Matching** | Test URLs against patterns with `urlpattern_test()` |
| **Full Execution** | Get complete match results with `urlpattern_exec()` |
| **Group Extraction** | Extract named groups with `urlpattern_extract()` |
| **Component Accessors** | Get pattern components like pathname, hostname, etc. |
| **WHATWG Compliant** | Follows the official URLPattern specification |
| **High Performance** | Uses RE2 regex engine for efficient matching |

## Use Cases

### API Route Analysis

Analyze API access logs to understand usage patterns:

```sql
SELECT
    urlpattern_extract(
        'https://api.example.com/:version/:resource/:id',
        request_url,
        'resource'
    ) as resource,
    COUNT(*) as requests
FROM access_logs
WHERE urlpattern_test('https://api.example.com/:version/:resource/:id', request_url)
GROUP BY resource
ORDER BY requests DESC;
```

### URL Classification

Classify URLs into categories based on their structure:

```sql
SELECT
    url,
    CASE
        WHEN urlpattern_test('https://example.com/blog/*', url) THEN 'blog'
        WHEN urlpattern_test('https://example.com/products/:id', url) THEN 'product'
        WHEN urlpattern_test('https://example.com/users/:id/*', url) THEN 'user'
        ELSE 'other'
    END as category
FROM urls;
```

### Multi-tenant URL Parsing

Extract tenant information from subdomain patterns:

```sql
SELECT
    urlpattern_extract(
        'https://:tenant.example.com/*',
        url,
        'tenant'
    ) as tenant_id,
    url
FROM requests;
```

### Storing Patterns in Tables

Use the URLPATTERN type to store validated patterns:

```sql
CREATE TABLE routes (
    name VARCHAR,
    pattern URLPATTERN
);

INSERT INTO routes VALUES
    ('users', 'https://api.example.com/users/:id'),
    ('posts', 'https://api.example.com/posts/:slug');

-- Find matching route for a URL
SELECT name
FROM routes
WHERE urlpattern_test(pattern, 'https://api.example.com/users/123');
```

## Next Steps

- [Installation Guide](installation.md) - How to install the extension
- [Pattern Syntax](pattern-syntax.md) - Learn the URLPattern syntax
- [API Reference](api-reference.md) - Complete function documentation
- [Examples](examples.md) - More usage examples
