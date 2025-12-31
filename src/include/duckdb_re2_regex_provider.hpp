#pragma once

#include "duckdb/common/re2_regex.hpp"
#include "re2/re2.h"  // For RE2::ok() check
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace duckdb {

// Wrapper for duckdb_re2::Regex that is default-constructible
// Ada's url_pattern requires the regex_type to be default-constructible
class Re2RegexWrapper {
public:
    Re2RegexWrapper() = default;
    Re2RegexWrapper(const Re2RegexWrapper&) = default;
    Re2RegexWrapper(Re2RegexWrapper&&) = default;
    Re2RegexWrapper& operator=(const Re2RegexWrapper&) = default;
    Re2RegexWrapper& operator=(Re2RegexWrapper&&) = default;

    explicit Re2RegexWrapper(std::shared_ptr<duckdb_re2::Regex> regex)
        : regex_(std::move(regex)) {}

    const duckdb_re2::Regex& get() const {
        if (!regex_) {
            throw std::runtime_error("Accessing invalid regex");
        }
        return *regex_;
    }

    bool valid() const {
        return regex_ != nullptr;
    }

private:
    std::shared_ptr<duckdb_re2::Regex> regex_;
};

// Regex provider for Ada URLPattern using DuckDB's vendored RE2
// Implements the ada::url_pattern_regex::regex_concept interface
class DuckDBRe2RegexProvider {
public:
    using regex_type = Re2RegexWrapper;

    // Create a regex instance from a pattern string
    // Returns nullopt if the pattern is invalid
    static std::optional<regex_type> create_instance(std::string_view pattern, bool ignore_case) {
        auto options = ignore_case
            ? duckdb_re2::RegexOptions::CASE_INSENSITIVE
            : duckdb_re2::RegexOptions::NONE;
        try {
            auto regex = std::make_shared<duckdb_re2::Regex>(std::string(pattern), options);
            // Check if the pattern compiled successfully
            if (!regex->GetRegex().ok()) {
                return std::nullopt;
            }
            return regex_type(std::move(regex));
        } catch (...) {
            return std::nullopt;
        }
    }

    // Search for the pattern in the input and return captured groups
    // Returns nullopt if no match is found
    // NOTE: Ada expects only capturing groups (starting from index 1), not group 0 (full match)
    static std::optional<std::vector<std::optional<std::string>>> regex_search(
        std::string_view input,
        const regex_type& pattern
    ) {
        if (!pattern.valid()) {
            return std::nullopt;
        }

        duckdb_re2::Match match;
        std::string input_str(input);

        if (!duckdb_re2::RegexSearch(input_str, match, pattern.get())) {
            return std::nullopt;
        }

        // Skip group 0 (full match) - Ada expects only capturing groups
        std::vector<std::optional<std::string>> groups;
        if (match.groups.size() > 1) {
            groups.reserve(match.groups.size() - 1);
            for (size_t i = 1; i < match.groups.size(); ++i) {
                groups.push_back(match.groups[i].text);
            }
        }
        return groups;
    }

    // Test if the input fully matches the pattern
    static bool regex_match(std::string_view input, const regex_type& pattern) {
        if (!pattern.valid()) {
            return false;
        }
        return duckdb_re2::RegexMatch(std::string(input), pattern.get());
    }
};

} // namespace duckdb
