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
#include "duckdb/planner/expression/bound_function_expression.hpp"

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

	// Check if a pattern string looks like a path-only pattern
	// Returns true for patterns starting with / that don't look like full URLs
	static bool IsPathOnlyPattern(const std::string &pattern) {
		if (pattern.empty()) {
			return false;
		}
		// Starts with / and doesn't have :// (not a full URL)
		if (pattern[0] == '/') {
			return pattern.find("://") == std::string::npos;
		}
		return false;
	}

	// Get or create a compiled pattern from a string
	// Handles:
	// - Regular URL patterns (e.g., "https://example.com/*")
	// - Init-based patterns (prefixed with "init:")
	// - Path-only patterns (e.g., "/users/:id") - auto-detected
	// - File URLs (e.g., "file:///path/to/file")
	shared_ptr<URLPatternType> GetPattern(const string_t &pattern_str) {
		string key(pattern_str.GetData(), pattern_str.GetSize());

		auto it = cache.find(key);
		if (it != cache.end()) {
			return it->second;
		}

		// Check if this is an init-based pattern (created by urlpattern_init)
		if (key.rfind("init:", 0) == 0) {
			// Parse the init string back into a url_pattern_init struct
			ada::url_pattern_init init;
			bool ignore_case = false;
			std::string_view remaining(key.data() + 5, key.size() - 5); // Skip "init:"

			while (!remaining.empty()) {
				// Find the next component (format: "X=value;")
				auto eq_pos = remaining.find('=');
				if (eq_pos == std::string_view::npos)
					break;

				char component = remaining[0];
				remaining.remove_prefix(eq_pos + 1);

				auto semi_pos = remaining.find(';');
				if (semi_pos == std::string_view::npos)
					break;

				std::string value(remaining.substr(0, semi_pos));
				remaining.remove_prefix(semi_pos + 1);

				switch (component) {
				case 'P':
					init.protocol = value;
					break;
				case 'U':
					init.username = value;
					break;
				case 'W':
					init.password = value;
					break;
				case 'H':
					init.hostname = value;
					break;
				case 'O':
					init.port = value;
					break;
				case 'A':
					init.pathname = value;
					break;
				case 'S':
					init.search = value;
					break;
				case 'F':
					init.hash = value;
					break;
				case 'B':
					init.base_url = value;
					break;
				case 'I':
					ignore_case = (value == "1");
					break;
				}
			}

			return GetPatternFromInit(init, key, ignore_case);
		}

		// Check if this is a path-only pattern (starts with / but no protocol)
		if (IsPathOnlyPattern(key)) {
			ada::url_pattern_init init;
			init.pathname = key;
			return GetPatternFromInit(init, "init:A=" + key + ";");
		}

		// Parse as a regular URL pattern string
		auto pattern_result = ada::parse_url_pattern<DuckDBRe2RegexProvider>(
		    std::string_view(pattern_str.GetData(), pattern_str.GetSize()), nullptr, nullptr);

		if (!pattern_result) {
			throw InvalidInputException("Invalid URL pattern: %s", pattern_str.GetString());
		}

		auto pattern_ptr = make_shared_ptr<URLPatternType>(std::move(pattern_result.value()));
		cache[key] = pattern_ptr;
		return pattern_ptr;
	}

	// Get or create a compiled pattern from a url_pattern_init struct
	shared_ptr<URLPatternType> GetPatternFromInit(const ada::url_pattern_init &init, const string &cache_key,
	                                              bool ignore_case = false) {
		auto it = cache.find(cache_key);
		if (it != cache.end()) {
			return it->second;
		}

		// Always set up options explicitly to ensure consistent behavior across platforms
		ada::url_pattern_options options;
		options.ignore_case = ignore_case;

		// Parse using the init struct (base_url is already in init if provided)
		auto pattern_result = ada::parse_url_pattern<DuckDBRe2RegexProvider>(
		    ada::url_pattern_init(init), nullptr, &options);

		if (!pattern_result) {
			throw InvalidInputException("Invalid URL pattern components");
		}

		auto pattern_ptr = make_shared_ptr<URLPatternType>(std::move(pattern_result.value()));
		cache[cache_key] = pattern_ptr;
		return pattern_ptr;
	}
};

static unique_ptr<FunctionLocalState>
InitURLPatternLocalState(ExpressionState &state, const BoundFunctionExpression &expr, FunctionData *bind_data) {
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
	return type.id() == LogicalTypeId::VARCHAR && type.HasAlias() && type.GetAlias() == URLPATTERN_TYPE_NAME;
}

// Check if a pattern string looks like a path-only pattern (standalone function)
static bool IsPathOnlyPatternStatic(const std::string &pattern) {
	if (pattern.empty()) {
		return false;
	}
	// Starts with / and doesn't have :// (not a full URL)
	if (pattern[0] == '/') {
		return pattern.find("://") == std::string::npos;
	}
	return false;
}

// Validate a pattern string - returns true if valid
// Handles path-only patterns (e.g., "/users/:id") as well as full URL patterns
static bool ValidateUrlpattern(const string_t &pattern_str) {
	std::string pattern(pattern_str.GetData(), pattern_str.GetSize());

	// Path-only patterns are valid if they can be parsed as pathname
	if (IsPathOnlyPatternStatic(pattern)) {
		ada::url_pattern_init init;
		init.pathname = pattern;
		auto pattern_result = ada::parse_url_pattern<DuckDBRe2RegexProvider>(
		    ada::url_pattern_init(init), nullptr, nullptr);
		return pattern_result.has_value();
	}

	// Regular URL pattern
	auto pattern_result = ada::parse_url_pattern<DuckDBRe2RegexProvider>(
	    std::string_view(pattern_str.GetData(), pattern_str.GetSize()), nullptr, nullptr);
	return pattern_result.has_value();
}

//------------------------------------------------------------------------------
// urlpattern(pattern VARCHAR) -> URLPATTERN
// Constructor function that validates and creates a URLPATTERN
//------------------------------------------------------------------------------
static void UrlpatternConstructorFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &pattern_vector = args.data[0];

	UnaryExecutor::Execute<string_t, string_t>(pattern_vector, result, args.size(), [&](string_t pattern_str) {
		// Validate the pattern
		if (!ValidateUrlpattern(pattern_str)) {
			throw InvalidInputException("Invalid URL pattern: %s", pattern_str.GetString());
		}
		// Return the pattern string (the type is URLPATTERN due to function return type)
		return StringVector::AddString(result, pattern_str);
	});
}

//------------------------------------------------------------------------------
// Cast function: VARCHAR -> URLPATTERN
//------------------------------------------------------------------------------
static bool CastVarcharToUrlpattern(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	UnaryExecutor::Execute<string_t, string_t>(source, result, count, [&](string_t pattern_str) {
		// Validate the pattern during cast
		if (!ValidateUrlpattern(pattern_str)) {
			throw InvalidInputException("Invalid URL pattern: %s", pattern_str.GetString());
		}
		return StringVector::AddString(result, pattern_str);
	});
	return true;
}

//------------------------------------------------------------------------------
// urlpattern_init - Named parameter bind data
//------------------------------------------------------------------------------
struct UrlpatternInitBindData : public FunctionData {
	// Indices for each parameter (-1 if not provided)
	idx_t protocol_idx = DConstants::INVALID_INDEX;
	idx_t username_idx = DConstants::INVALID_INDEX;
	idx_t password_idx = DConstants::INVALID_INDEX;
	idx_t hostname_idx = DConstants::INVALID_INDEX;
	idx_t port_idx = DConstants::INVALID_INDEX;
	idx_t pathname_idx = DConstants::INVALID_INDEX;
	idx_t search_idx = DConstants::INVALID_INDEX;
	idx_t hash_idx = DConstants::INVALID_INDEX;
	idx_t ignore_case_idx = DConstants::INVALID_INDEX;
	idx_t base_url_idx = DConstants::INVALID_INDEX;

	unique_ptr<FunctionData> Copy() const override {
		auto copy = make_uniq<UrlpatternInitBindData>();
		copy->protocol_idx = protocol_idx;
		copy->username_idx = username_idx;
		copy->password_idx = password_idx;
		copy->hostname_idx = hostname_idx;
		copy->port_idx = port_idx;
		copy->pathname_idx = pathname_idx;
		copy->search_idx = search_idx;
		copy->hash_idx = hash_idx;
		copy->ignore_case_idx = ignore_case_idx;
		copy->base_url_idx = base_url_idx;
		return copy;
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<UrlpatternInitBindData>();
		return protocol_idx == other.protocol_idx && username_idx == other.username_idx &&
		       password_idx == other.password_idx && hostname_idx == other.hostname_idx &&
		       port_idx == other.port_idx && pathname_idx == other.pathname_idx && search_idx == other.search_idx &&
		       hash_idx == other.hash_idx && ignore_case_idx == other.ignore_case_idx &&
		       base_url_idx == other.base_url_idx;
	}
};

static unique_ptr<FunctionData> UrlpatternInitBind(ClientContext &context, ScalarFunction &bound_function,
                                                   vector<unique_ptr<Expression>> &arguments) {
	auto bind_data = make_uniq<UrlpatternInitBindData>();

	for (idx_t i = 0; i < arguments.size(); i++) {
		auto &arg = arguments[i];
		if (!arg->alias.empty()) {
			if (arg->alias == "protocol") {
				bind_data->protocol_idx = i;
			} else if (arg->alias == "username") {
				bind_data->username_idx = i;
			} else if (arg->alias == "password") {
				bind_data->password_idx = i;
			} else if (arg->alias == "hostname") {
				bind_data->hostname_idx = i;
			} else if (arg->alias == "port") {
				bind_data->port_idx = i;
			} else if (arg->alias == "pathname") {
				bind_data->pathname_idx = i;
			} else if (arg->alias == "search") {
				bind_data->search_idx = i;
			} else if (arg->alias == "hash") {
				bind_data->hash_idx = i;
			} else if (arg->alias == "ignore_case") {
				bind_data->ignore_case_idx = i;
			} else if (arg->alias == "base_url" || arg->alias == "base") {
				bind_data->base_url_idx = i;
			} else {
				throw BinderException("Unknown parameter '%s' for urlpattern_init. Valid parameters: protocol, "
				                      "username, password, hostname, port, pathname, search, hash, ignore_case, base_url",
				                      arg->alias);
			}
		}
	}

	return bind_data;
}

//------------------------------------------------------------------------------
// urlpattern_init(protocol, username, password, hostname, port, pathname, search, hash, ignore_case, base_url) -> URLPATTERN
// Creates a URLPattern from individual components (supports path-only patterns)
//------------------------------------------------------------------------------
static void UrlpatternInitFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &bind_data = state.expr.Cast<BoundFunctionExpression>().bind_info->Cast<UrlpatternInitBindData>();
	auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

	// Helper to get optional string from argument
	auto get_optional_string = [&](idx_t param_idx, idx_t row_idx) -> std::optional<std::string> {
		if (param_idx == DConstants::INVALID_INDEX) {
			return std::nullopt;
		}
		auto &vec = args.data[param_idx];
		if (FlatVector::IsNull(vec, row_idx)) {
			return std::nullopt;
		}
		auto str = FlatVector::GetData<string_t>(vec)[row_idx];
		return std::string(str.GetData(), str.GetSize());
	};

	// Helper to get optional bool from argument
	auto get_optional_bool = [&](idx_t param_idx, idx_t row_idx) -> std::optional<bool> {
		if (param_idx == DConstants::INVALID_INDEX) {
			return std::nullopt;
		}
		auto &vec = args.data[param_idx];
		if (FlatVector::IsNull(vec, row_idx)) {
			return std::nullopt;
		}
		// Handle both boolean and string "true"/"false"
		if (vec.GetType().id() == LogicalTypeId::BOOLEAN) {
			return FlatVector::GetData<bool>(vec)[row_idx];
		} else {
			auto str = FlatVector::GetData<string_t>(vec)[row_idx];
			std::string s(str.GetData(), str.GetSize());
			return s == "true" || s == "1" || s == "TRUE";
		}
	};

	for (idx_t i = 0; i < args.size(); i++) {
		// Build the url_pattern_init struct
		ada::url_pattern_init init;
		init.protocol = get_optional_string(bind_data.protocol_idx, i);
		init.username = get_optional_string(bind_data.username_idx, i);
		init.password = get_optional_string(bind_data.password_idx, i);
		init.hostname = get_optional_string(bind_data.hostname_idx, i);
		init.port = get_optional_string(bind_data.port_idx, i);
		init.pathname = get_optional_string(bind_data.pathname_idx, i);
		init.search = get_optional_string(bind_data.search_idx, i);
		init.hash = get_optional_string(bind_data.hash_idx, i);
		init.base_url = get_optional_string(bind_data.base_url_idx, i);

		// Get ignore_case option
		bool ignore_case = get_optional_bool(bind_data.ignore_case_idx, i).value_or(false);

		// Build a cache key from the components
		std::string cache_key = "init:";
		if (init.protocol)
			cache_key += "P=" + *init.protocol + ";";
		if (init.username)
			cache_key += "U=" + *init.username + ";";
		if (init.password)
			cache_key += "W=" + *init.password + ";";
		if (init.hostname)
			cache_key += "H=" + *init.hostname + ";";
		if (init.port)
			cache_key += "O=" + *init.port + ";";
		if (init.pathname)
			cache_key += "A=" + *init.pathname + ";";
		if (init.search)
			cache_key += "S=" + *init.search + ";";
		if (init.hash)
			cache_key += "F=" + *init.hash + ";";
		if (init.base_url)
			cache_key += "B=" + *init.base_url + ";";
		if (ignore_case)
			cache_key += "I=1;";

		// Parse the pattern to validate it
		auto pattern = local_state.GetPatternFromInit(init, cache_key, ignore_case);

		// Return the cache key as the pattern identifier
		// This allows the pattern to be reused with other functions
		FlatVector::GetData<string_t>(result)[i] = StringVector::AddString(result, cache_key);
	}
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

	BinaryExecutor::Execute<string_t, string_t, bool>(pattern_vector, url_vector, result, args.size(),
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
	                                                  });
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

		    const auto &match_opt = exec_result.value();
		    if (!match_opt.has_value()) {
			    // No match - return NULL
			    return string_t();
		    }

		    const auto &match = match_opt.value();

		    // Get the group name
		    std::string group_name(group_str.GetData(), group_str.GetSize());

		    // Helper to check a component for the group
		    auto check_component = [&](const auto &component) -> std::optional<std::string> {
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
	    });
}

//------------------------------------------------------------------------------
// urlpattern_pathname(pattern VARCHAR) -> VARCHAR
// Returns the pathname component of a pattern
//------------------------------------------------------------------------------
static void UrlpatternPathnameFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &pattern_vector = args.data[0];
	auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

	UnaryExecutor::Execute<string_t, string_t>(pattern_vector, result, args.size(), [&](string_t pattern_str) {
		auto pattern = local_state.GetPattern(pattern_str);
		auto sv = pattern->get_pathname();
		return StringVector::AddString(result, sv.data(), sv.size());
	});
}

//------------------------------------------------------------------------------
// urlpattern_protocol(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternProtocolFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &pattern_vector = args.data[0];
	auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

	UnaryExecutor::Execute<string_t, string_t>(pattern_vector, result, args.size(), [&](string_t pattern_str) {
		auto pattern = local_state.GetPattern(pattern_str);
		auto sv = pattern->get_protocol();
		return StringVector::AddString(result, sv.data(), sv.size());
	});
}

//------------------------------------------------------------------------------
// urlpattern_hostname(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternHostnameFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &pattern_vector = args.data[0];
	auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

	UnaryExecutor::Execute<string_t, string_t>(pattern_vector, result, args.size(), [&](string_t pattern_str) {
		auto pattern = local_state.GetPattern(pattern_str);
		auto sv = pattern->get_hostname();
		return StringVector::AddString(result, sv.data(), sv.size());
	});
}

//------------------------------------------------------------------------------
// urlpattern_port(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternPortFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &pattern_vector = args.data[0];
	auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

	UnaryExecutor::Execute<string_t, string_t>(pattern_vector, result, args.size(), [&](string_t pattern_str) {
		auto pattern = local_state.GetPattern(pattern_str);
		auto sv = pattern->get_port();
		return StringVector::AddString(result, sv.data(), sv.size());
	});
}

//------------------------------------------------------------------------------
// urlpattern_search(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternSearchFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &pattern_vector = args.data[0];
	auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

	UnaryExecutor::Execute<string_t, string_t>(pattern_vector, result, args.size(), [&](string_t pattern_str) {
		auto pattern = local_state.GetPattern(pattern_str);
		auto sv = pattern->get_search();
		return StringVector::AddString(result, sv.data(), sv.size());
	});
}

//------------------------------------------------------------------------------
// urlpattern_hash(pattern VARCHAR) -> VARCHAR
//------------------------------------------------------------------------------
static void UrlpatternHashFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &pattern_vector = args.data[0];
	auto &local_state = ExecuteFunctionState::GetFunctionState(state)->Cast<URLPatternLocalState>();

	UnaryExecutor::Execute<string_t, string_t>(pattern_vector, result, args.size(), [&](string_t pattern_str) {
		auto pattern = local_state.GetPattern(pattern_str);
		auto sv = pattern->get_hash();
		return StringVector::AddString(result, sv.data(), sv.size());
	});
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
static void CollectGroups(const ada::url_pattern_component_result &component, vector<Value> &keys,
                          vector<Value> &values) {
	for (const auto &[name, value] : component.groups) {
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
	auto &matched_vec = *child_entries[0];  // BOOLEAN
	auto &protocol_vec = *child_entries[1]; // VARCHAR
	auto &hostname_vec = *child_entries[2]; // VARCHAR
	auto &port_vec = *child_entries[3];     // VARCHAR
	auto &pathname_vec = *child_entries[4]; // VARCHAR
	auto &search_vec = *child_entries[5];   // VARCHAR
	auto &hash_vec = *child_entries[6];     // VARCHAR
	auto &groups_vec = *child_entries[7];   // MAP(VARCHAR, VARCHAR)

	UnifiedVectorFormat pattern_data, url_data;
	pattern_vector.ToUnifiedFormat(args.size(), pattern_data);
	url_vector.ToUnifiedFormat(args.size(), url_data);

	auto patterns = UnifiedVectorFormat::GetData<string_t>(pattern_data);
	auto urls = UnifiedVectorFormat::GetData<string_t>(url_data);

	for (idx_t i = 0; i < args.size(); i++) {
		auto pattern_idx = pattern_data.sel->get_index(i);
		auto url_idx = url_data.sel->get_index(i);

		// Handle NULL inputs
		if (!pattern_data.validity.RowIsValid(pattern_idx) || !url_data.validity.RowIsValid(url_idx)) {
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

		const auto &match_opt = exec_result.value();

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

		const auto &match = match_opt.value();

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
		groups_vec.SetValue(i,
		                    Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values)));
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
// URL Parsing Functions - Parse actual URLs (not patterns)
//------------------------------------------------------------------------------

// Helper to parse a URL and return the result
static tl::expected<ada::url_aggregator, ada::errors> ParseUrl(const string_t &url_str,
                                                                const string_t *base_url_str = nullptr) {
	std::string_view url_view(url_str.GetData(), url_str.GetSize());

	if (base_url_str) {
		std::string_view base_view(base_url_str->GetData(), base_url_str->GetSize());
		auto base_result = ada::parse<ada::url_aggregator>(base_view, nullptr);
		if (!base_result) {
			return tl::unexpected(base_result.error());
		}
		return ada::parse<ada::url_aggregator>(url_view, &base_result.value());
	}

	return ada::parse<ada::url_aggregator>(url_view, nullptr);
}

// url_protocol(url) -> VARCHAR
static void UrlProtocolFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto protocol = url_result->get_protocol();
		return StringVector::AddString(result, protocol.data(), protocol.size());
	});
}

// url_host(url) -> VARCHAR (includes port if present)
static void UrlHostFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto host = url_result->get_host();
		return StringVector::AddString(result, host.data(), host.size());
	});
}

// url_hostname(url) -> VARCHAR (excludes port)
static void UrlHostnameFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto hostname = url_result->get_hostname();
		return StringVector::AddString(result, hostname.data(), hostname.size());
	});
}

// url_port(url) -> VARCHAR
static void UrlPortFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto port = url_result->get_port();
		return StringVector::AddString(result, port.data(), port.size());
	});
}

// url_pathname(url) -> VARCHAR
static void UrlPathnameFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto pathname = url_result->get_pathname();
		return StringVector::AddString(result, pathname.data(), pathname.size());
	});
}

// url_search(url) -> VARCHAR (the query string including ?)
static void UrlSearchFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto search = url_result->get_search();
		return StringVector::AddString(result, search.data(), search.size());
	});
}

// url_hash(url) -> VARCHAR (the fragment including #)
static void UrlHashFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto hash = url_result->get_hash();
		return StringVector::AddString(result, hash.data(), hash.size());
	});
}

// url_username(url) -> VARCHAR
static void UrlUsernameFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto username = url_result->get_username();
		return StringVector::AddString(result, username.data(), username.size());
	});
}

// url_password(url) -> VARCHAR
static void UrlPasswordFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto password = url_result->get_password();
		return StringVector::AddString(result, password.data(), password.size());
	});
}

// url_origin(url) -> VARCHAR
static void UrlOriginFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto origin = url_result->get_origin();
		return StringVector::AddString(result, origin);
	});
}

// url_href(url) -> VARCHAR (normalized URL)
static void UrlHrefFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			return string_t();
		}
		auto href = url_result->get_href();
		return StringVector::AddString(result, href.data(), href.size());
	});
}

// url_valid(url) -> BOOLEAN
static void UrlValidFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, bool>(args.data[0], result, args.size(), [&](string_t url_str) {
		auto url_result = ParseUrl(url_str);
		return url_result.has_value();
	});
}

// Define the return type for url_parse
static LogicalType GetUrlParseReturnType() {
	child_list_t<LogicalType> struct_children;
	struct_children.push_back(make_pair("href", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("origin", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("protocol", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("username", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("password", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("host", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("hostname", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("port", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("pathname", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("search", LogicalType::VARCHAR));
	struct_children.push_back(make_pair("hash", LogicalType::VARCHAR));
	return LogicalType::STRUCT(struct_children);
}

// url_parse(url) -> STRUCT
static void UrlParseFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &url_vector = args.data[0];

	auto &child_entries = StructVector::GetEntries(result);
	auto &href_vec = *child_entries[0];
	auto &origin_vec = *child_entries[1];
	auto &protocol_vec = *child_entries[2];
	auto &username_vec = *child_entries[3];
	auto &password_vec = *child_entries[4];
	auto &host_vec = *child_entries[5];
	auto &hostname_vec = *child_entries[6];
	auto &port_vec = *child_entries[7];
	auto &pathname_vec = *child_entries[8];
	auto &search_vec = *child_entries[9];
	auto &hash_vec = *child_entries[10];

	UnifiedVectorFormat url_data;
	url_vector.ToUnifiedFormat(args.size(), url_data);
	auto urls = UnifiedVectorFormat::GetData<string_t>(url_data);

	for (idx_t i = 0; i < args.size(); i++) {
		auto url_idx = url_data.sel->get_index(i);

		if (!url_data.validity.RowIsValid(url_idx)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		auto url_str = urls[url_idx];
		auto url_result = ParseUrl(url_str);

		if (!url_result) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		auto &url = url_result.value();

		auto href = url.get_href();
		auto origin = url.get_origin();
		auto protocol = url.get_protocol();
		auto username = url.get_username();
		auto password = url.get_password();
		auto host = url.get_host();
		auto hostname = url.get_hostname();
		auto port = url.get_port();
		auto pathname = url.get_pathname();
		auto search = url.get_search();
		auto hash = url.get_hash();

		FlatVector::GetData<string_t>(href_vec)[i] = StringVector::AddString(href_vec, href.data(), href.size());
		FlatVector::GetData<string_t>(origin_vec)[i] = StringVector::AddString(origin_vec, origin);
		FlatVector::GetData<string_t>(protocol_vec)[i] =
		    StringVector::AddString(protocol_vec, protocol.data(), protocol.size());
		FlatVector::GetData<string_t>(username_vec)[i] =
		    StringVector::AddString(username_vec, username.data(), username.size());
		FlatVector::GetData<string_t>(password_vec)[i] =
		    StringVector::AddString(password_vec, password.data(), password.size());
		FlatVector::GetData<string_t>(host_vec)[i] = StringVector::AddString(host_vec, host.data(), host.size());
		FlatVector::GetData<string_t>(hostname_vec)[i] =
		    StringVector::AddString(hostname_vec, hostname.data(), hostname.size());
		FlatVector::GetData<string_t>(port_vec)[i] = StringVector::AddString(port_vec, port.data(), port.size());
		FlatVector::GetData<string_t>(pathname_vec)[i] =
		    StringVector::AddString(pathname_vec, pathname.data(), pathname.size());
		FlatVector::GetData<string_t>(search_vec)[i] =
		    StringVector::AddString(search_vec, search.data(), search.size());
		FlatVector::GetData<string_t>(hash_vec)[i] = StringVector::AddString(hash_vec, hash.data(), hash.size());
	}

	result.SetVectorType(VectorType::FLAT_VECTOR);
}

//------------------------------------------------------------------------------
// Query Parameter Parsing
//------------------------------------------------------------------------------

// Helper to parse query string into key-value pairs
static vector<pair<string, string>> ParseQueryString(std::string_view query) {
	vector<pair<string, string>> params;

	// Skip leading ? if present
	if (!query.empty() && query[0] == '?') {
		query.remove_prefix(1);
	}

	while (!query.empty()) {
		// Find the next & or end
		auto amp_pos = query.find('&');
		std::string_view param = (amp_pos == std::string_view::npos) ? query : query.substr(0, amp_pos);

		if (!param.empty()) {
			// Find = separator
			auto eq_pos = param.find('=');
			if (eq_pos == std::string_view::npos) {
				// Key only, no value
				params.emplace_back(std::string(param), "");
			} else {
				params.emplace_back(std::string(param.substr(0, eq_pos)), std::string(param.substr(eq_pos + 1)));
			}
		}

		if (amp_pos == std::string_view::npos) {
			break;
		}
		query.remove_prefix(amp_pos + 1);
	}

	return params;
}

// url_search_params(url) -> MAP(VARCHAR, VARCHAR)
static void UrlSearchParamsFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &url_vector = args.data[0];
	UnifiedVectorFormat url_data;
	url_vector.ToUnifiedFormat(args.size(), url_data);
	auto urls = UnifiedVectorFormat::GetData<string_t>(url_data);

	for (idx_t i = 0; i < args.size(); i++) {
		auto url_idx = url_data.sel->get_index(i);

		if (!url_data.validity.RowIsValid(url_idx)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		auto url_str = urls[url_idx];
		auto url_result = ParseUrl(url_str);

		vector<Value> keys;
		vector<Value> values;

		if (url_result) {
			auto search = url_result->get_search();
			auto params = ParseQueryString(search);

			for (const auto &[key, val] : params) {
				keys.push_back(Value(key));
				values.push_back(Value(val));
			}
		}

		result.SetValue(i, Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values)));
	}
}

// url_search_param(url, name) -> VARCHAR
static void UrlSearchParamFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &url_vector = args.data[0];
	auto &name_vector = args.data[1];

	UnifiedVectorFormat url_data, name_data;
	url_vector.ToUnifiedFormat(args.size(), url_data);
	name_vector.ToUnifiedFormat(args.size(), name_data);

	auto urls = UnifiedVectorFormat::GetData<string_t>(url_data);
	auto names = UnifiedVectorFormat::GetData<string_t>(name_data);

	for (idx_t i = 0; i < args.size(); i++) {
		auto url_idx = url_data.sel->get_index(i);
		auto name_idx = name_data.sel->get_index(i);

		if (!url_data.validity.RowIsValid(url_idx) || !name_data.validity.RowIsValid(name_idx)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		auto url_str = urls[url_idx];
		auto name_str = names[name_idx];

		auto url_result = ParseUrl(url_str);
		if (!url_result) {
			FlatVector::SetNull(result, i, true);
			continue;
		}

		auto search = url_result->get_search();
		auto params = ParseQueryString(search);
		std::string name(name_str.GetData(), name_str.GetSize());

		bool found = false;
		for (const auto &[key, val] : params) {
			if (key == name) {
				FlatVector::GetData<string_t>(result)[i] = StringVector::AddString(result, val);
				found = true;
				break;
			}
		}

		if (!found) {
			FlatVector::SetNull(result, i, true);
		}
	}
}

//------------------------------------------------------------------------------
// URL Resolution
//------------------------------------------------------------------------------

// url_resolve(base, relative) -> VARCHAR
static void UrlResolveFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(), [&](string_t base_str, string_t relative_str) {
		    auto url_result = ParseUrl(relative_str, &base_str);
		    if (!url_result) {
			    return string_t();
		    }
		    auto href = url_result->get_href();
		    return StringVector::AddString(result, href.data(), href.size());
	    });
}

//------------------------------------------------------------------------------
// URL Building and Modification
//------------------------------------------------------------------------------

// Bind data for url_build and url_modify - tracks parameter positions
struct UrlBuildBindData : public FunctionData {
	// For url_modify: index of the base URL (first positional arg)
	idx_t url_idx = DConstants::INVALID_INDEX;

	// Named parameter indices
	idx_t protocol_idx = DConstants::INVALID_INDEX;
	idx_t username_idx = DConstants::INVALID_INDEX;
	idx_t password_idx = DConstants::INVALID_INDEX;
	idx_t hostname_idx = DConstants::INVALID_INDEX;
	idx_t port_idx = DConstants::INVALID_INDEX;
	idx_t pathname_idx = DConstants::INVALID_INDEX;
	idx_t search_idx = DConstants::INVALID_INDEX;
	idx_t search_params_idx = DConstants::INVALID_INDEX;
	idx_t hash_idx = DConstants::INVALID_INDEX;
	idx_t encode_idx = DConstants::INVALID_INDEX;

	// Whether this is url_modify (has base URL) or url_build
	bool is_modify = false;

	unique_ptr<FunctionData> Copy() const override {
		auto copy = make_uniq<UrlBuildBindData>();
		copy->url_idx = url_idx;
		copy->protocol_idx = protocol_idx;
		copy->username_idx = username_idx;
		copy->password_idx = password_idx;
		copy->hostname_idx = hostname_idx;
		copy->port_idx = port_idx;
		copy->pathname_idx = pathname_idx;
		copy->search_idx = search_idx;
		copy->search_params_idx = search_params_idx;
		copy->hash_idx = hash_idx;
		copy->encode_idx = encode_idx;
		copy->is_modify = is_modify;
		return copy;
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<UrlBuildBindData>();
		return url_idx == other.url_idx && protocol_idx == other.protocol_idx && username_idx == other.username_idx &&
		       password_idx == other.password_idx && hostname_idx == other.hostname_idx &&
		       port_idx == other.port_idx && pathname_idx == other.pathname_idx && search_idx == other.search_idx &&
		       search_params_idx == other.search_params_idx && hash_idx == other.hash_idx &&
		       encode_idx == other.encode_idx && is_modify == other.is_modify;
	}
};

// URL encode a string (percent-encoding)
static std::string UrlEncode(const std::string &value) {
	std::string encoded;
	encoded.reserve(value.size() * 3); // Worst case: every char encoded

	for (unsigned char c : value) {
		// Unreserved characters: A-Z, a-z, 0-9, -, _, ., ~
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~') {
			encoded += c;
		} else {
			// Percent-encode
			encoded += '%';
			static const char hex[] = "0123456789ABCDEF";
			encoded += hex[(c >> 4) & 0x0F];
			encoded += hex[c & 0x0F];
		}
	}
	return encoded;
}

// Build query string from MAP
static std::string BuildQueryString(const Value &map_value, bool encode) {
	if (map_value.IsNull()) {
		return "";
	}

	auto &children = MapValue::GetChildren(map_value);
	if (children.empty()) {
		return "";
	}

	std::string query = "?";
	bool first = true;

	for (const auto &entry : children) {
		auto &struct_children = StructValue::GetChildren(entry);
		auto key = struct_children[0].GetValue<string>();
		auto val = struct_children[1].GetValue<string>();

		if (!first) {
			query += "&";
		}
		first = false;

		if (encode) {
			query += UrlEncode(key) + "=" + UrlEncode(val);
		} else {
			query += key + "=" + val;
		}
	}

	return query;
}

static unique_ptr<FunctionData> UrlBuildBind(ClientContext &context, ScalarFunction &bound_function,
                                             vector<unique_ptr<Expression>> &arguments) {
	auto bind_data = make_uniq<UrlBuildBindData>();
	bind_data->is_modify = false;

	for (idx_t i = 0; i < arguments.size(); i++) {
		auto &arg = arguments[i];
		if (!arg->alias.empty()) {
			if (arg->alias == "protocol") {
				bind_data->protocol_idx = i;
			} else if (arg->alias == "username") {
				bind_data->username_idx = i;
			} else if (arg->alias == "password") {
				bind_data->password_idx = i;
			} else if (arg->alias == "hostname") {
				bind_data->hostname_idx = i;
			} else if (arg->alias == "port") {
				bind_data->port_idx = i;
			} else if (arg->alias == "pathname") {
				bind_data->pathname_idx = i;
			} else if (arg->alias == "search") {
				bind_data->search_idx = i;
			} else if (arg->alias == "search_params") {
				bind_data->search_params_idx = i;
			} else if (arg->alias == "hash") {
				bind_data->hash_idx = i;
			} else if (arg->alias == "encode") {
				bind_data->encode_idx = i;
			} else {
				throw BinderException("Unknown parameter '%s' for url_build. Valid parameters: protocol, "
				                      "username, password, hostname, port, pathname, search, search_params, hash, encode",
				                      arg->alias);
			}
		}
	}

	// Check that search and search_params are not both provided
	if (bind_data->search_idx != DConstants::INVALID_INDEX &&
	    bind_data->search_params_idx != DConstants::INVALID_INDEX) {
		throw BinderException("Cannot specify both 'search' and 'search_params' - they are mutually exclusive");
	}

	return bind_data;
}

static unique_ptr<FunctionData> UrlModifyBind(ClientContext &context, ScalarFunction &bound_function,
                                              vector<unique_ptr<Expression>> &arguments) {
	auto bind_data = make_uniq<UrlBuildBindData>();
	bind_data->is_modify = true;

	// First unnamed argument is the URL to modify
	bool found_url = false;

	for (idx_t i = 0; i < arguments.size(); i++) {
		auto &arg = arguments[i];
		if (arg->alias.empty()) {
			// Positional argument - should be the URL
			if (!found_url) {
				bind_data->url_idx = i;
				found_url = true;
			} else {
				throw BinderException("url_modify takes exactly one positional argument (the URL to modify)");
			}
		} else if (arg->alias == "protocol") {
			bind_data->protocol_idx = i;
		} else if (arg->alias == "username") {
			bind_data->username_idx = i;
		} else if (arg->alias == "password") {
			bind_data->password_idx = i;
		} else if (arg->alias == "hostname") {
			bind_data->hostname_idx = i;
		} else if (arg->alias == "port") {
			bind_data->port_idx = i;
		} else if (arg->alias == "pathname") {
			bind_data->pathname_idx = i;
		} else if (arg->alias == "search") {
			bind_data->search_idx = i;
		} else if (arg->alias == "search_params") {
			bind_data->search_params_idx = i;
		} else if (arg->alias == "hash") {
			bind_data->hash_idx = i;
		} else if (arg->alias == "encode") {
			bind_data->encode_idx = i;
		} else {
			throw BinderException("Unknown parameter '%s' for url_modify. Valid parameters: protocol, "
			                      "username, password, hostname, port, pathname, search, search_params, hash, encode",
			                      arg->alias);
		}
	}

	if (!found_url) {
		throw BinderException("url_modify requires a URL as the first argument");
	}

	// Check that search and search_params are not both provided
	if (bind_data->search_idx != DConstants::INVALID_INDEX &&
	    bind_data->search_params_idx != DConstants::INVALID_INDEX) {
		throw BinderException("Cannot specify both 'search' and 'search_params' - they are mutually exclusive");
	}

	return bind_data;
}

// Core URL building logic used by both url_build and url_modify
static void UrlBuildCore(DataChunk &args, ExpressionState &state, Vector &result, bool is_modify) {
	auto &bind_data = state.expr.Cast<BoundFunctionExpression>().bind_info->Cast<UrlBuildBindData>();

	// Helper to get optional string from argument
	auto get_optional_string = [&](idx_t param_idx, idx_t row_idx) -> std::optional<std::string> {
		if (param_idx == DConstants::INVALID_INDEX) {
			return std::nullopt;
		}
		auto &vec = args.data[param_idx];
		if (FlatVector::IsNull(vec, row_idx)) {
			return std::nullopt;
		}
		auto str = FlatVector::GetData<string_t>(vec)[row_idx];
		return std::string(str.GetData(), str.GetSize());
	};

	// Helper to get optional bool from argument
	auto get_optional_bool = [&](idx_t param_idx, idx_t row_idx) -> std::optional<bool> {
		if (param_idx == DConstants::INVALID_INDEX) {
			return std::nullopt;
		}
		auto &vec = args.data[param_idx];
		if (FlatVector::IsNull(vec, row_idx)) {
			return std::nullopt;
		}
		if (vec.GetType().id() == LogicalTypeId::BOOLEAN) {
			return FlatVector::GetData<bool>(vec)[row_idx];
		} else {
			auto str = FlatVector::GetData<string_t>(vec)[row_idx];
			std::string s(str.GetData(), str.GetSize());
			return s == "true" || s == "1" || s == "TRUE";
		}
	};

	// Helper to get MAP value from argument
	auto get_map_value = [&](idx_t param_idx, idx_t row_idx) -> Value {
		if (param_idx == DConstants::INVALID_INDEX) {
			return Value();
		}
		auto &vec = args.data[param_idx];
		if (FlatVector::IsNull(vec, row_idx)) {
			return Value();
		}
		return vec.GetValue(row_idx);
	};

	for (idx_t i = 0; i < args.size(); i++) {
		// Get encode option (default true)
		bool encode = get_optional_bool(bind_data.encode_idx, i).value_or(true);

		// Get component values
		auto protocol = get_optional_string(bind_data.protocol_idx, i);
		auto username = get_optional_string(bind_data.username_idx, i);
		auto password = get_optional_string(bind_data.password_idx, i);
		auto hostname = get_optional_string(bind_data.hostname_idx, i);
		auto port = get_optional_string(bind_data.port_idx, i);
		auto pathname = get_optional_string(bind_data.pathname_idx, i);
		auto search = get_optional_string(bind_data.search_idx, i);
		auto hash = get_optional_string(bind_data.hash_idx, i);
		auto search_params = get_map_value(bind_data.search_params_idx, i);

		// For url_modify, start with parsed base URL
		std::string base_protocol, base_username, base_password, base_hostname, base_port, base_pathname, base_search,
		    base_hash;

		if (is_modify) {
			auto base_url_str = get_optional_string(bind_data.url_idx, i);
			if (!base_url_str) {
				FlatVector::SetNull(result, i, true);
				continue;
			}

			string_t url_st(base_url_str->data(), base_url_str->size());
			auto url_result = ParseUrl(url_st);
			if (!url_result) {
				FlatVector::SetNull(result, i, true);
				continue;
			}

			// Extract current components
			auto &url = url_result.value();
			auto proto = url.get_protocol();
			base_protocol = std::string(proto.data(), proto.size());
			// Remove trailing : from protocol
			if (!base_protocol.empty() && base_protocol.back() == ':') {
				base_protocol.pop_back();
			}
			auto uname = url.get_username();
			base_username = std::string(uname.data(), uname.size());
			auto pwd = url.get_password();
			base_password = std::string(pwd.data(), pwd.size());
			auto hname = url.get_hostname();
			base_hostname = std::string(hname.data(), hname.size());
			auto prt = url.get_port();
			base_port = std::string(prt.data(), prt.size());
			auto pth = url.get_pathname();
			base_pathname = std::string(pth.data(), pth.size());
			auto srch = url.get_search();
			base_search = std::string(srch.data(), srch.size());
			auto hsh = url.get_hash();
			base_hash = std::string(hsh.data(), hsh.size());
		}

		// Use provided values or fall back to base (for modify) or empty (for build)
		std::string final_protocol = protocol.value_or(is_modify ? base_protocol : "");
		std::string final_username = username.value_or(is_modify ? base_username : "");
		std::string final_password = password.value_or(is_modify ? base_password : "");
		std::string final_hostname = hostname.value_or(is_modify ? base_hostname : "");
		std::string final_port = port.value_or(is_modify ? base_port : "");
		std::string final_pathname = pathname.value_or(is_modify ? base_pathname : "");
		std::string final_hash = hash.value_or(is_modify ? base_hash : "");

		// Handle search/search_params
		std::string final_search;
		if (!search_params.IsNull()) {
			final_search = BuildQueryString(search_params, encode);
		} else if (search.has_value()) {
			final_search = search.value();
			// Ensure it starts with ?
			if (!final_search.empty() && final_search[0] != '?') {
				final_search = "?" + final_search;
			}
		} else if (is_modify) {
			final_search = base_search;
		}

		// Ensure hash starts with #
		if (!final_hash.empty() && final_hash[0] != '#') {
			final_hash = "#" + final_hash;
		}

		// Build the URL string
		std::string url_str;

		// Protocol
		if (!final_protocol.empty()) {
			url_str += final_protocol + "://";
		}

		// Username:password@
		if (!final_username.empty()) {
			if (encode) {
				url_str += UrlEncode(final_username);
			} else {
				url_str += final_username;
			}
			if (!final_password.empty()) {
				url_str += ":";
				if (encode) {
					url_str += UrlEncode(final_password);
				} else {
					url_str += final_password;
				}
			}
			url_str += "@";
		}

		// Hostname
		url_str += final_hostname;

		// Port
		if (!final_port.empty()) {
			url_str += ":" + final_port;
		}

		// Pathname
		if (!final_pathname.empty()) {
			if (final_pathname[0] != '/' && !final_hostname.empty()) {
				url_str += "/";
			}
			url_str += final_pathname;
		} else if (!final_hostname.empty()) {
			// Ensure at least a / for the path if we have a host
			url_str += "/";
		}

		// Search/query
		url_str += final_search;

		// Hash/fragment
		url_str += final_hash;

		// For url_build with no protocol, just return the constructed path-like URL
		// For url_modify or url_build with protocol, validate it can be parsed
		if (!final_protocol.empty()) {
			string_t test_url(url_str.data(), url_str.size());
			auto test_result = ParseUrl(test_url);
			if (!test_result) {
				FlatVector::SetNull(result, i, true);
				continue;
			}
		}

		FlatVector::GetData<string_t>(result)[i] = StringVector::AddString(result, url_str);
	}
}

// url_build(protocol := ..., hostname := ..., ...) -> VARCHAR
static void UrlBuildFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UrlBuildCore(args, state, result, false);
}

// url_modify(url, protocol := ..., hostname := ..., ...) -> VARCHAR
static void UrlModifyFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UrlBuildCore(args, state, result, true);
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
	loader.RegisterCastFunction(LogicalType::VARCHAR, urlpattern_type, BoundCastInfo(CastVarcharToUrlpattern), 1);

	// Register urlpattern() constructor function
	auto urlpattern_constructor_func =
	    ScalarFunction("urlpattern", {LogicalType::VARCHAR}, urlpattern_type, UrlpatternConstructorFunction);
	loader.RegisterFunction(urlpattern_constructor_func);

	// Register urlpattern_init() function for component-based patterns (supports path-only patterns)
	// Usage: urlpattern_init(pathname := '/users/:id')
	//        urlpattern_init(protocol := 'https', hostname := '*.example.com', pathname := '/api/*')
	auto urlpattern_init_func = ScalarFunction("urlpattern_init", {}, urlpattern_type, UrlpatternInitFunction,
	                                           UrlpatternInitBind, nullptr, nullptr, InitURLPatternLocalState);
	urlpattern_init_func.varargs = LogicalType::ANY;  // Accept VARCHAR and BOOLEAN parameters
	urlpattern_init_func.null_handling = FunctionNullHandling::SPECIAL_HANDLING;
	loader.RegisterFunction(urlpattern_init_func);

	// Register urlpattern_test function (accepts URLPATTERN)
	auto urlpattern_test_func = ScalarFunction("urlpattern_test", {urlpattern_type, LogicalType::VARCHAR},
	                                           LogicalType::BOOLEAN, UrlpatternTestFunction);
	urlpattern_test_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_test_func);

	// Register urlpattern_extract function (accepts URLPATTERN)
	auto urlpattern_extract_func =
	    ScalarFunction("urlpattern_extract", {urlpattern_type, LogicalType::VARCHAR, LogicalType::VARCHAR},
	                   LogicalType::VARCHAR, UrlpatternExtractFunction);
	urlpattern_extract_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_extract_func);

	// Register accessor functions (accept URLPATTERN)
	auto urlpattern_pathname_func =
	    ScalarFunction("urlpattern_pathname", {urlpattern_type}, LogicalType::VARCHAR, UrlpatternPathnameFunction);
	urlpattern_pathname_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_pathname_func);

	auto urlpattern_protocol_func =
	    ScalarFunction("urlpattern_protocol", {urlpattern_type}, LogicalType::VARCHAR, UrlpatternProtocolFunction);
	urlpattern_protocol_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_protocol_func);

	auto urlpattern_hostname_func =
	    ScalarFunction("urlpattern_hostname", {urlpattern_type}, LogicalType::VARCHAR, UrlpatternHostnameFunction);
	urlpattern_hostname_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_hostname_func);

	auto urlpattern_port_func =
	    ScalarFunction("urlpattern_port", {urlpattern_type}, LogicalType::VARCHAR, UrlpatternPortFunction);
	urlpattern_port_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_port_func);

	auto urlpattern_search_func =
	    ScalarFunction("urlpattern_search", {urlpattern_type}, LogicalType::VARCHAR, UrlpatternSearchFunction);
	urlpattern_search_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_search_func);

	auto urlpattern_hash_func =
	    ScalarFunction("urlpattern_hash", {urlpattern_type}, LogicalType::VARCHAR, UrlpatternHashFunction);
	urlpattern_hash_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_hash_func);

	// Register urlpattern_exec function (accepts URLPATTERN)
	auto urlpattern_exec_func = ScalarFunction("urlpattern_exec", {urlpattern_type, LogicalType::VARCHAR},
	                                           GetUrlpatternExecReturnType(), UrlpatternExecFunction);
	urlpattern_exec_func.init_local_state = InitURLPatternLocalState;
	loader.RegisterFunction(urlpattern_exec_func);

	//--------------------------------------------------------------------------
	// URL Parsing Functions
	//--------------------------------------------------------------------------

	// url_parse(url) -> STRUCT
	loader.RegisterFunction(
	    ScalarFunction("url_parse", {LogicalType::VARCHAR}, GetUrlParseReturnType(), UrlParseFunction));

	// Individual component functions
	loader.RegisterFunction(
	    ScalarFunction("url_protocol", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlProtocolFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_host", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlHostFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_hostname", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlHostnameFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_port", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlPortFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_pathname", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlPathnameFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_search", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlSearchFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_hash", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlHashFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_username", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlUsernameFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_password", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlPasswordFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_origin", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlOriginFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_href", {LogicalType::VARCHAR}, LogicalType::VARCHAR, UrlHrefFunction));
	loader.RegisterFunction(
	    ScalarFunction("url_valid", {LogicalType::VARCHAR}, LogicalType::BOOLEAN, UrlValidFunction));

	//--------------------------------------------------------------------------
	// Query Parameter Functions
	//--------------------------------------------------------------------------

	// url_search_params(url) -> MAP
	loader.RegisterFunction(ScalarFunction("url_search_params", {LogicalType::VARCHAR},
	                                       LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR),
	                                       UrlSearchParamsFunction));

	// url_search_param(url, name) -> VARCHAR
	loader.RegisterFunction(ScalarFunction("url_search_param", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, UrlSearchParamFunction));

	//--------------------------------------------------------------------------
	// URL Resolution
	//--------------------------------------------------------------------------

	// url_resolve(base, relative) -> VARCHAR
	loader.RegisterFunction(ScalarFunction("url_resolve", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, UrlResolveFunction));

	//--------------------------------------------------------------------------
	// URL Building and Modification
	//--------------------------------------------------------------------------

	// url_build(protocol := ..., hostname := ..., ...) -> VARCHAR
	auto url_build_func = ScalarFunction("url_build", {}, LogicalType::VARCHAR, UrlBuildFunction, UrlBuildBind);
	url_build_func.varargs = LogicalType::ANY;
	url_build_func.null_handling = FunctionNullHandling::SPECIAL_HANDLING;
	loader.RegisterFunction(url_build_func);

	// url_modify(url, protocol := ..., hostname := ..., ...) -> VARCHAR
	auto url_modify_func = ScalarFunction("url_modify", {}, LogicalType::VARCHAR, UrlModifyFunction, UrlModifyBind);
	url_modify_func.varargs = LogicalType::ANY;
	url_modify_func.null_handling = FunctionNullHandling::SPECIAL_HANDLING;
	loader.RegisterFunction(url_modify_func);
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
