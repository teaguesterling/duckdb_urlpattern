# Examples

Real-world examples of using the URLPattern extension for common tasks.

## Web Analytics

### Categorize Page Views

Classify URLs into content categories:

```sql
CREATE TABLE page_views (
    id INTEGER,
    url VARCHAR,
    timestamp TIMESTAMP
);

-- Categorize pages
SELECT
    url,
    CASE
        WHEN urlpattern_test('https://example.com/', url) THEN 'home'
        WHEN urlpattern_test('https://example.com/blog/*', url) THEN 'blog'
        WHEN urlpattern_test('https://example.com/products/:id', url) THEN 'product'
        WHEN urlpattern_test('https://example.com/categories/:category/*', url) THEN 'category'
        WHEN urlpattern_test('https://example.com/users/:id/*', url) THEN 'user_profile'
        ELSE 'other'
    END as page_category
FROM page_views;
```

### Aggregate by URL Pattern

Count views per pattern:

```sql
SELECT
    CASE
        WHEN urlpattern_test('https://example.com/products/:id', url) THEN '/products/:id'
        WHEN urlpattern_test('https://example.com/blog/:slug', url) THEN '/blog/:slug'
        WHEN urlpattern_test('https://example.com/users/:id', url) THEN '/users/:id'
        ELSE url
    END as pattern,
    COUNT(*) as views
FROM page_views
GROUP BY pattern
ORDER BY views DESC;
```

## API Log Analysis

### Extract API Versions

Analyze API usage by version:

```sql
CREATE TABLE api_logs (
    request_id VARCHAR,
    url VARCHAR,
    method VARCHAR,
    status_code INTEGER,
    response_time_ms INTEGER
);

SELECT
    urlpattern_extract(
        'https://api.example.com/:version/*',
        url,
        'version'
    ) as api_version,
    COUNT(*) as requests,
    AVG(response_time_ms) as avg_response_time
FROM api_logs
WHERE urlpattern_test('https://api.example.com/:version/*', url)
GROUP BY api_version
ORDER BY requests DESC;
```

### Resource Usage Analysis

Find most accessed resources:

```sql
SELECT
    urlpattern_extract(
        'https://api.example.com/v:version/:resource/*',
        url,
        'resource'
    ) as resource,
    COUNT(*) as requests,
    SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
FROM api_logs
WHERE urlpattern_test('https://api.example.com/v:version/:resource/*', url)
GROUP BY resource
ORDER BY requests DESC
LIMIT 10;
```

### Slow Endpoint Detection

Find slow API endpoints:

```sql
SELECT
    urlpattern_extract('https://api.example.com/:version/:resource/:id', url, 'resource') as resource,
    urlpattern_extract('https://api.example.com/:version/:resource/:id', url, 'version') as version,
    AVG(response_time_ms) as avg_time,
    MAX(response_time_ms) as max_time,
    COUNT(*) as requests
FROM api_logs
WHERE urlpattern_test('https://api.example.com/:version/:resource/:id', url)
  AND response_time_ms > 1000
GROUP BY resource, version
ORDER BY avg_time DESC;
```

## Multi-tenant Applications

### Extract Tenant from Subdomain

```sql
CREATE TABLE requests (
    id INTEGER,
    url VARCHAR,
    user_id INTEGER
);

SELECT
    urlpattern_extract(
        'https://:tenant.app.example.com/*',
        url,
        'tenant'
    ) as tenant,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(*) as total_requests
FROM requests
WHERE urlpattern_test('https://:tenant.app.example.com/*', url)
GROUP BY tenant;
```

### Tenant-Specific Path Analysis

```sql
SELECT
    urlpattern_extract('https://:tenant.app.example.com/*', url, 'tenant') as tenant,
    urlpattern_pathname(url) as path,
    COUNT(*) as hits
FROM requests
WHERE urlpattern_test('https://:tenant.app.example.com/*', url)
GROUP BY tenant, path
ORDER BY tenant, hits DESC;
```

## E-commerce

### Product Category Analysis

```sql
CREATE TABLE product_views (
    url VARCHAR,
    user_id INTEGER,
    session_id VARCHAR
);

SELECT
    urlpattern_extract(
        'https://shop.example.com/category/:category/product/:product_id',
        url,
        'category'
    ) as category,
    COUNT(*) as views,
    COUNT(DISTINCT user_id) as unique_viewers
FROM product_views
WHERE urlpattern_test(
    'https://shop.example.com/category/:category/product/:product_id',
    url
)
GROUP BY category
ORDER BY views DESC;
```

### Shopping Funnel Analysis

Track user journey through the shopping funnel:

```sql
WITH funnel_steps AS (
    SELECT
        session_id,
        MAX(CASE WHEN urlpattern_test('https://shop.example.com/products/*', url) THEN 1 ELSE 0 END) as viewed_product,
        MAX(CASE WHEN urlpattern_test('https://shop.example.com/cart', url) THEN 1 ELSE 0 END) as added_to_cart,
        MAX(CASE WHEN urlpattern_test('https://shop.example.com/checkout/*', url) THEN 1 ELSE 0 END) as started_checkout,
        MAX(CASE WHEN urlpattern_test('https://shop.example.com/order/confirmation/:id', url) THEN 1 ELSE 0 END) as completed
    FROM page_views
    GROUP BY session_id
)
SELECT
    COUNT(*) as total_sessions,
    SUM(viewed_product) as viewed_product,
    SUM(added_to_cart) as added_to_cart,
    SUM(started_checkout) as started_checkout,
    SUM(completed) as completed
FROM funnel_steps;
```

## URL Validation and Filtering

### Filter Valid API URLs

```sql
SELECT *
FROM raw_urls
WHERE urlpattern_test('https://api.example.com/v:version/:resource/*', url);
```

### Validate URL Structure

```sql
SELECT
    url,
    urlpattern_test('https://*.example.com/*', url) as is_valid_domain,
    urlpattern_test('https://example.com/api/v:version/*', url) as is_api_url,
    urlpattern_test('https://example.com/static/*', url) as is_static_asset
FROM urls;
```

## Data Extraction

### Parse URLs into Components

```sql
SELECT
    url,
    urlpattern_protocol(url) as protocol,
    urlpattern_hostname(url) as hostname,
    urlpattern_pathname(url) as pathname
FROM urls
WHERE urlpattern_test('https://*/*', url);
```

### Extract IDs for Joining

```sql
-- Extract product IDs from URLs to join with product table
SELECT
    pv.url,
    urlpattern_extract(
        'https://example.com/products/:id',
        pv.url,
        'id'
    )::INTEGER as product_id,
    p.name,
    p.price
FROM product_views pv
JOIN products p ON p.id = urlpattern_extract(
    'https://example.com/products/:id',
    pv.url,
    'id'
)::INTEGER
WHERE urlpattern_test('https://example.com/products/:id', pv.url);
```

## Combining with Other DuckDB Features

### With Window Functions

```sql
SELECT
    urlpattern_extract('https://example.com/users/:id/*', url, 'id') as user_id,
    url,
    timestamp,
    ROW_NUMBER() OVER (
        PARTITION BY urlpattern_extract('https://example.com/users/:id/*', url, 'id')
        ORDER BY timestamp
    ) as visit_number
FROM page_views
WHERE urlpattern_test('https://example.com/users/:id/*', url);
```

### With CTEs for Complex Analysis

```sql
WITH api_calls AS (
    SELECT
        url,
        urlpattern_extract('https://api.example.com/:version/:resource/:id', url, 'version') as version,
        urlpattern_extract('https://api.example.com/:version/:resource/:id', url, 'resource') as resource,
        urlpattern_extract('https://api.example.com/:version/:resource/:id', url, 'id') as entity_id,
        response_time_ms
    FROM api_logs
    WHERE urlpattern_test('https://api.example.com/:version/:resource/:id', url)
),
resource_stats AS (
    SELECT
        resource,
        version,
        COUNT(*) as calls,
        AVG(response_time_ms) as avg_time,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_time
    FROM api_calls
    GROUP BY resource, version
)
SELECT *
FROM resource_stats
WHERE p95_time > 500
ORDER BY p95_time DESC;
```
