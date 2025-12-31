# Installation

## Requirements

- DuckDB v1.0.0 or later
- GCC 12+ or Clang 14+ (for building from source)

## Installing from Binary

Once the extension is published, you can install it directly in DuckDB:

```sql
INSTALL urlpattern;
LOAD urlpattern;
```

## Building from Source

### Prerequisites

1. **Clone the repository with submodules:**

```bash
git clone --recurse-submodules https://github.com/your-username/duckdb_urlpattern.git
cd duckdb_urlpattern
```

2. **Ensure you have the required compiler:**

The extension requires GCC 12+ or Clang 14+ due to C++20 requirements from the Ada URL library.

```bash
# Check your GCC version
gcc --version

# On Ubuntu, install GCC 12 if needed
sudo apt install gcc-12 g++-12
```

### Building

Build the extension using make:

```bash
# Using system default compiler (if GCC 12+)
make

# Or specify the compiler explicitly
CC=/usr/bin/gcc-12 CXX=/usr/bin/g++-12 make
```

This will:

1. Build DuckDB (if not already built)
2. Install dependencies via vcpkg (Ada URL library)
3. Build the urlpattern extension

### Build Output

After building, you'll find:

- `build/release/extension/urlpattern/urlpattern.duckdb_extension` - The loadable extension
- `build/release/duckdb` - DuckDB CLI with the extension

### Loading the Extension

```sql
-- Load from the build directory
LOAD 'build/release/extension/urlpattern/urlpattern.duckdb_extension';

-- Or if using the built-in DuckDB CLI
LOAD urlpattern;
```

## Verifying Installation

Test that the extension is working:

```sql
SELECT urlpattern_test('https://example.com/*', 'https://example.com/test');
```

Expected output:

```
┌──────────────────────────────────────────────────────────────────────┐
│ urlpattern_test('https://example.com/*', 'https://example.com/test') │
│                               boolean                                │
├──────────────────────────────────────────────────────────────────────┤
│ true                                                                 │
└──────────────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Compiler Version Error

If you see errors about unsupported C++ features:

```
error: 'consteval' is not valid in this context
```

You need GCC 12+ or Clang 14+. Specify the compiler explicitly:

```bash
CC=/usr/bin/gcc-12 CXX=/usr/bin/g++-12 make
```

### Missing Dependencies

If vcpkg fails to install dependencies, ensure you have:

```bash
# On Ubuntu/Debian
sudo apt install curl zip unzip tar pkg-config

# On macOS
brew install curl zip unzip pkg-config
```

### Extension Not Found

If DuckDB can't find the extension, use the full path:

```sql
LOAD '/full/path/to/urlpattern.duckdb_extension';
```
