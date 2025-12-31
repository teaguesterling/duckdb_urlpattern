#define DUCKDB_EXTENSION_MAIN

#include "urlpattern_extension.hpp"
#include "duckdb_re2_regex_provider.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/cast/cast_function_set.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"

// Include Ada headers - use the main header which includes everything in correct order
#include <ada.h>

namespace duckdb {

// Type alias for our URLPattern with DuckDB's RE2 provider
using URLPatternType = ada::url_pattern<DuckDBRe2RegexProvider>;

//------------------------------------------------------------------------------
// Pattern Cache - Local state for caching compiled patterns
//------------------------------------------------------------------------------
struct URLPatternLocalState : public FunctionLocalState {
    // Cache of compiled patterns keyed by pattern string
    unordered_map<string, shared_ptr<URLPatternType>> cache;

    // Get or create a compiled pattern
    shared_ptr<URLPatternType> GetPattern(const string_t &pattern_str) {
        string key(pattern_str.GetData(), pattern_str.GetSize());

        auto it = cache.find(key);
        if (it != cache.end()) {
            return it->second;
        }

        // Parse and cache the pattern
        auto pattern_result = ada::parse_url_pattern<DuckDBRe2RegexProvider>(
            std::string_view(pattern_str.GetData(), pattern_str.GetSize()),
            nullptr,
            nullptr
        );

        if (!pattern_result) {
            throw InvalidInputException("Invalid URL pattern: %s", pattern_str.GetString());
        }

        auto pattern_ptr = make_shared_ptr<URLPatternType>(std::move(pattern_result.value()));
        cache[key] = pattern_ptr;
        return pattern_ptr;
    }
};

static unique_ptr<FunctionLocalState> InitURLPatternLocalState(ExpressionState &state,
                                                                const BoundFunctionExpression &expr,
                                                                FunctionData *bind_data) {
    return make_uniq<URLPatternLocalState>();
}

//------------------------------------------------------------------------------
// URLPATTERN Type Definition
//------------------------------------------------------------------------------
static constexpr const char *URLPATTERN_TYPE_NAME = "URLPATTERN";

// Create the URLPATTERN logical type (VARCHAR-backed with alias)
static LogicalType UrlpatternType() {
    auto type = LogicalType(LogicalTypeId::VARCHAR);
    type.SetAlias(URLPATTERN_TYPE_NAME);
    return type;
}

// Check if a type is URLPATTERN
static bool IsUrlpatternType(const LogicalType &type) {
    return type.id() == LogicalTypeId::VARCHAR &&
           type.HasAlias() &&
           type.GetAlias() == URLPATTERN_TYPE_NAME;
}

// Validate a pattern string - returns true if valid
static bool ValidateUrlpattern(const string_t &pattern_str) {
    auto pattern_result = ada::parse_url_pattern<DuckDBRe2RegexProvider>(
        std::string_view(pattern_str.GetData(), pattern_str.GetSize()),
        nullptr,
        nullptr
    );
    return pattern_result.has_value();
}

//------------------------------------------------------------------------------
// urlpattern(pattern VARCHAR) -> URLPATTERN
// Constructor function that validates and creates a URLPATTERN
//------------------------------------------------------------------------------
static void UrlpatternConstructorFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];

    UnaryExecutor::Execute<string_t, string_t>(
        pattern_vector, result, args.size(),
        [&](string_t pattern_str) {
            // Validate the pattern
            if (!ValidateUrlpattern(pattern_str)) {
                throw InvalidInputException("Invalid URL pattern: %s", pattern_str.GetString());
            }
            // Return the pattern string (the type is URLPATTERN due to function return type)
            return StringVector::AddString(result, pattern_str);
        }
    );
}

//------------------------------------------------------------------------------
// Cast function: VARCHAR -> URLPATTERN
//------------------------------------------------------------------------------
static bool CastVarcharToUrlpattern(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
    UnaryExecutor::Execute<string_t, string_t>(
        source, result, count,
        [&](string_t pattern_str) {
            // Validate the pattern during cast
            if (!ValidateUrlpattern(pattern_str)) {
                throw InvalidInputException("Invalid URL pattern: %s", pattern_str.GetString());
            }
            return StringVector::AddString(result, pattern_str);
        }
    );
    return true;
}

//------------------------------------------------------------------------------
// urlpattern_test(pattern VARCHAR, url VARCHAR) -> BOOLEAN
// Tests if a URL matches a pattern
//------------------------------------------------------------------------------
static void UrlpatternTestFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &url_vector = args.data[1];

    // Get the local state with pattern cache
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    BinaryExecutor::Execute<string_t, string_t, bool>(
        pattern_vector, url_vector, result, args.size(),
        [&](string_t pattern_str, string_t url_str) {
            // Get cached pattern (or parse and cache if not found)
            auto pattern = local_state.GetPattern(pattern_str);

            // Test the URL against the pattern
            std::string url(url_str.GetData(), url_str.GetSize());
            auto test_result = pattern->test(url, nullptr);

            if (!test_result) {
                throw InvalidInputException("URL pattern test failed");
            }
            return test_result.value();
        }
    );
}

//------------------------------------------------------------------------------
// urlpattern_extract(pattern VARCHAR, url VARCHAR, group_name VARCHAR) -> VARCHAR
// Extracts a named group from the pathname match
//------------------------------------------------------------------------------
static void UrlpatternExtractFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &url_vector = args.data[1];
    auto &group_vector = args.data[2];

    // Get the local state with pattern cache
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    TernaryExecutor::Execute<string_t, string_t, string_t, string_t>(
        pattern_vector, url_vector, group_vector, result, args.size(),
        [&](string_t pattern_str, string_t url_str, string_t group_str) {
            // Get cached pattern (or parse and cache if not found)
            auto pattern = local_state.GetPattern(pattern_str);

            // Execute the pattern against the URL
            std::string url(url_str.GetData(), url_str.GetSize());
            auto exec_result = pattern->exec(url, nullptr);

            // exec returns tl::expected<std::optional<url_pattern_result>, errors>
            if (!exec_result.has_value()) {
                throw InvalidInputException("URL pattern exec failed");
            }

            const auto& match_opt = exec_result.value();
            if (!match_opt.has_value()) {
                // No match - return NULL
                return string_t();
            }

            const auto& match = match_opt.value();

            // Get the group name
            std::string group_name(group_str.GetData(), group_str.GetSize());

            // Helper to check a component for the group
            auto check_component = [&](const auto& component) -> std::optional<std::string> {
                auto iter = component.groups.find(group_name);
                if (iter != component.groups.end() && iter->second.has_value()) {
                    return iter->second.value();
                }
                return std::nullopt;
            };

            // Look for the group in pathname (most common use case)
            if (auto val = check_component(match.pathname)) {
                return StringVector::AddString(result, *val);
            }
            if (auto val = check_component(match.protocol)) {
                return StringVector::AddString(result, *val);
            }
            if (auto val = check_component(match.hostname)) {
                return StringVector::AddString(result, *val);
            }
            if (auto val = check_component(match.port)) {
                return StringVector::AddString(result, *val);
            }
            if (auto val = check_component(match.search)) {
                return StringVector::AddString(result, *val);
            }
            if (auto val = check_component(match.hash)) {
                return StringVector::AddString(result, *val);
            }

            // Group not found
            return string_t();
        }
    );
}

//------------------------------------------------------------------------------
// urlpattern_pathname(pattern VARCHAR) -> VARCHAR
// Returns the pathname component of a pattern
//------------------------------------------------------------------------------
static void UrlpatternPathnameFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    UnaryExecutor::Execute<string_t, string_t>(
        pattern_vector, result, args.size(),
        [&](string_t pattern_str) {
            auto pattern = local_state.GetPattern(pattern_str);
            auto sv = pattern->get_pathname();
            return StringVector::AddString(result, sv.data(), sv.size());
        }
    );
}

//------------------------------------------------------------------------------
// urlpattern_protocol(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternProtocolFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    UnaryExecutor::Execute<string_t, string_t>(
        pattern_vector, result, args.size(),
        [&](string_t pattern_str) {
            auto pattern = local_state.GetPattern(pattern_str);
            auto sv = pattern->get_protocol();
            return StringVector::AddString(result, sv.data(), sv.size());
        }
    );
}

//------------------------------------------------------------------------------
// urlpattern_hostname(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternHostnameFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    UnaryExecutor::Execute<string_t, string_t>(
        pattern_vector, result, args.size(),
        [&](string_t pattern_str) {
            auto pattern = local_state.GetPattern(pattern_str);
            auto sv = pattern->get_hostname();
            return StringVector::AddString(result, sv.data(), sv.size());
        }
    );
}

//------------------------------------------------------------------------------
// urlpattern_port(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternPortFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    UnaryExecutor::Execute<string_t, string_t>(
        pattern_vector, result, args.size(),
        [&](string_t pattern_str) {
            auto pattern = local_state.GetPattern(pattern_str);
            auto sv = pattern->get_port();
            return StringVector::AddString(result, sv.data(), sv.size());
        }
    );
}

//------------------------------------------------------------------------------
// urlpattern_search(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternSearchFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    UnaryExecutor::Execute<string_t, string_t>(
        pattern_vector, result, args.size(),
        [&](string_t pattern_str) {
            auto pattern = local_state.GetPattern(pattern_str);
            auto sv = pattern->get_search();
            return StringVector::AddString(result, sv.data(), sv.size());
        }
    );
}

//------------------------------------------------------------------------------
// urlpattern_hash(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternHashFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    UnaryExecutor::Execute<string_t, string_t>(
        pattern_vector, result, args.size(),
        [&](string_t pattern_str) {
            auto pattern = local_state.GetPattern(pattern_str);
            auto sv = pattern->get_hash();
            return StringVector::AddString(result, sv.data(), sv.size());
        }
    );
}

//------------------------------------------------------------------------------
// urlpattern_exec(pattern VARCHAR, url VARCHAR) -> STRUCT
// Executes a pattern against a URL and returns full match results
// Returns: STRUCT(matched BOOLEAN, protocol VARCHAR, hostname VARCHAR,
//                 port VARCHAR, pathname VARCHAR, search VARCHAR, hash VARCHAR,
//                 groups MAP(VARCHAR, VARCHAR))
//------------------------------------------------------------------------------

// Helper to collect all groups from a component result
// Skip numeric keys (like "0") which are implicit full-match groups per component
static void CollectGroups(const ada::url_pattern_component_result& component,
                          vector<Value>& keys, vector<Value>& values) {
    for (const auto& [name, value] : component.groups) {
        if (value.has_value()) {
            // Skip numeric keys - these are implicit positional captures
            // that would be duplicated across components
            bool is_numeric = !name.empty() && std::all_of(name.begin(), name.end(), ::isdigit);
            if (!is_numeric) {
                keys.push_back(Value(name));
                values.push_back(Value(value.value()));
            }
        }
    }
}

static void UrlpatternExecFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &pattern_vector = args.data[0];
    auto &url_vector = args.data[1];

    // Get the local state with pattern cache
    auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

    auto &child_entries = StructVector::GetEntries(result);
    auto &matched_vec = *child_entries[0];      // BOOLEAN
    auto &protocol_vec = *child_entries[1];     // VARCHAR
    auto &hostname_vec = *child_entries[2];     // VARCHAR
    auto &port_vec = *child_entries[3];         // VARCHAR
    auto &pathname_vec = *child_entries[4];     // VARCHAR
    auto &search_vec = *child_entries[5];       // VARCHAR
    auto &hash_vec = *child_entries[6];         // VARCHAR
    auto &groups_vec = *child_entries[7];       // MAP(VARCHAR, VARCHAR)

    UnifiedVectorFormat pattern_data, url_data;
    pattern_vector.ToUnifiedFormat(args.size(), pattern_data);
    url_vector.ToUnifiedFormat(args.size(), url_data);

    auto patterns = UnifiedVectorFormat::GetData<string_t>(pattern_data);
    auto urls = UnifiedVectorFormat::GetData<string_t>(url_data);

    for (idx_t i = 0; i < args.size(); i++) {
        auto pattern_idx = pattern_data.sel->get_index(i);
        auto url_idx = url_data.sel->get_index(i);

        // Handle NULL inputs
        if (!pattern_data.validity.RowIsValid(pattern_idx) ||
            !url_data.validity.RowIsValid(url_idx)) {
            FlatVector::SetNull(result, i, true);
            continue;
        }

        auto pattern_str = patterns[pattern_idx];
        auto url_str = urls[url_idx];

        // Get cached pattern (or parse and cache if not found)
        auto pattern = local_state.GetPattern(pattern_str);

        // Execute the pattern against the URL
        std::string url(url_str.GetData(), url_str.GetSize());
        auto exec_result = pattern->exec(url, nullptr);

        if (!exec_result.has_value()) {
            throw InvalidInputException("URL pattern exec failed");
        }

        const auto& match_opt = exec_result.value();

        if (!match_opt.has_value()) {
            // No match - set matched to false and other fields to empty
            FlatVector::GetData<bool>(matched_vec)[i] = false;
            FlatVector::GetData<string_t>(protocol_vec)[i] = StringVector::AddString(protocol_vec, "");
            FlatVector::GetData<string_t>(hostname_vec)[i] = StringVector::AddString(hostname_vec, "");
            FlatVector::GetData<string_t>(port_vec)[i] = StringVector::AddString(port_vec, "");
            FlatVector::GetData<string_t>(pathname_vec)[i] = StringVector::AddString(pathname_vec, "");
            FlatVector::GetData<string_t>(search_vec)[i] = StringVector::AddString(search_vec, "");
            FlatVector::GetData<string_t>(hash_vec)[i] = StringVector::AddString(hash_vec, "");
            // Empty map
            groups_vec.SetValue(i, Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, {}, {}));
            continue;
        }

        const auto& match = match_opt.value();

        // Set matched to true
        FlatVector::GetData<bool>(matched_vec)[i] = true;

        // Set component inputs
        FlatVector::GetData<string_t>(protocol_vec)[i] = StringVector::AddString(protocol_vec, match.protocol.input);
        FlatVector::GetData<string_t>(hostname_vec)[i] = StringVector::AddString(hostname_vec, match.hostname.input);
        FlatVector::GetData<string_t>(port_vec)[i] = StringVector::AddString(port_vec, match.port.input);
        FlatVector::GetData<string_t>(pathname_vec)[i] = StringVector::AddString(pathname_vec, match.pathname.input);
        FlatVector::GetData<string_t>(search_vec)[i] = StringVector::AddString(search_vec, match.search.input);
        FlatVector::GetData<string_t>(hash_vec)[i] = StringVector::AddString(hash_vec, match.hash.input);

        // Collect all groups from all components into a single map
        vector<Value> keys;
        vector<Value> values;
        CollectGroups(match.protocol, keys, values);
        CollectGroups(match.username, keys, values);
        CollectGroups(match.password, keys, values);
        CollectGroups(match.hostname, keys, values);
        CollectGroups(match.port, keys, values);
        CollectGroups(match.pathname, keys, values);
        CollectGroups(match.search, keys, values);
        CollectGroups(match.hash, keys, values);

        // Set the groups map
        groups_vec.SetValue(i, Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR,
                                          std::move(keys), std::move(values)));
    }

    result.SetVectorType(VectorType::FLAT_VECTOR);
}

// Define the return type for urlpattern_exec
static LogicalType GetUrlpatternExecReturnType() {
    child_list_t<LogicalType> struct_children;
    struct_children.push_back(make_pair("matched", LogicalType::BOOLEAN));
    struct_children.push_back(make_pair("protocol", LogicalType::VARCHAR));
    struct_children.push_back(make_pair("hostname", LogicalType::VARCHAR));
    struct_children.push_back(make_pair("port", LogicalType::VARCHAR));
    struct_children.push_back(make_pair("pathname", LogicalType::VARCHAR));
    struct_children.push_back(make_pair("search", LogicalType::VARCHAR));
    struct_children.push_back(make_pair("hash", LogicalType::VARCHAR));
    struct_children.push_back(make_pair("groups", LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)));
    return LogicalType::STRUCT(struct_children);
}

//------------------------------------------------------------------------------
// Extension loading
//------------------------------------------------------------------------------
static void LoadInternal(ExtensionLoader &loader) {
    // Get the URLPATTERN type
    auto urlpattern_type = UrlpatternType();

    // Register the URLPATTERN type
    loader.RegisterType(URLPATTERN_TYPE_NAME, urlpattern_type);

    // Register VARCHAR -> URLPATTERN cast (implicit, with validation)
    loader.RegisterCastFunction(LogicalType::VARCHAR, urlpattern_type,
                                BoundCastInfo(CastVarcharToUrlpattern), 1);

    // Register urlpattern() constructor function
    auto urlpattern_constructor_func = ScalarFunction(
        "urlpattern",
        {LogicalType::VARCHAR},
        urlpattern_type,
        UrlpatternConstructorFunction
    );
    loader.RegisterFunction(urlpattern_constructor_func);

    // Register urlpattern_test function (accepts URLPATTERN)
    auto urlpattern_test_func = ScalarFunction(
        "urlpattern_test",
        {urlpattern_type, LogicalType::VARCHAR},
        LogicalType::BOOLEAN,
        UrlpatternTestFunction
    );
    urlpattern_test_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_test_func);

    // Register urlpattern_extract function (accepts URLPATTERN)
    auto urlpattern_extract_func = ScalarFunction(
        "urlpattern_extract",
        {urlpattern_type, LogicalType::VARCHAR, LogicalType::VARCHAR},
        LogicalType::VARCHAR,
        UrlpatternExtractFunction
    );
    urlpattern_extract_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_extract_func);

    // Register accessor functions (accept URLPATTERN)
    auto urlpattern_pathname_func = ScalarFunction(
        "urlpattern_pathname",
        {urlpattern_type},
        LogicalType::VARCHAR,
        UrlpatternPathnameFunction
    );
    urlpattern_pathname_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_pathname_func);

    auto urlpattern_protocol_func = ScalarFunction(
        "urlpattern_protocol",
        {urlpattern_type},
        LogicalType::VARCHAR,
        UrlpatternProtocolFunction
    );
    urlpattern_protocol_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_protocol_func);

    auto urlpattern_hostname_func = ScalarFunction(
        "urlpattern_hostname",
        {urlpattern_type},
        LogicalType::VARCHAR,
        UrlpatternHostnameFunction
    );
    urlpattern_hostname_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_hostname_func);

    auto urlpattern_port_func = ScalarFunction(
        "urlpattern_port",
        {urlpattern_type},
        LogicalType::VARCHAR,
        UrlpatternPortFunction
    );
    urlpattern_port_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_port_func);

    auto urlpattern_search_func = ScalarFunction(
        "urlpattern_search",
        {urlpattern_type},
        LogicalType::VARCHAR,
        UrlpatternSearchFunction
    );
    urlpattern_search_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_search_func);

    auto urlpattern_hash_func = ScalarFunction(
        "urlpattern_hash",
        {urlpattern_type},
        LogicalType::VARCHAR,
        UrlpatternHashFunction
    );
    urlpattern_hash_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_hash_func);

    // Register urlpattern_exec function (accepts URLPATTERN)
    auto urlpattern_exec_func = ScalarFunction(
        "urlpattern_exec",
        {urlpattern_type, LogicalType::VARCHAR},
        GetUrlpatternExecReturnType(),
        UrlpatternExecFunction
    );
    urlpattern_exec_func.init_local_state = InitURLPatternLocalState;
    loader.RegisterFunction(urlpattern_exec_func);
}

void UrlpatternExtension::Load(ExtensionLoader &loader) {
    LoadInternal(loader);
}

std::string UrlpatternExtension::Name() {
    return "urlpattern";
}

std::string UrlpatternExtension::Version() const {
#ifdef EXT_VERSION_URLPATTERN
    return EXT_VERSION_URLPATTERN;
#else
    return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(urlpattern, loader) {
    duckdb::LoadInternal(loader);
}

}
