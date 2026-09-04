#pragma once

#include "duckdb.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

// v2.0 split vector.hpp: FlatVector / StructVector moved into their own headers.
// Include them when present so the shims below can name them unconditionally.
#if __has_include("duckdb/common/vector/flat_vector.hpp")
#include "duckdb/common/vector/flat_vector.hpp"
#endif
#if __has_include("duckdb/common/vector/struct_vector.hpp")
#include "duckdb/common/vector/struct_vector.hpp"
#endif

#include <type_traits>
#include <utility>

// Compatibility shims for building against BOTH the pinned stable DuckDB
// (v1.5.x, what this extension ships against) and DuckDB main (the v2.0 line,
// what community-extensions' `test_against_latest` builds against).
//
// FEATURE DETECTION, NOT VERSION NUMBERS. A version macro says when a thing
// changed; a probe says whether it changed here. The probe keeps working when a
// change is backported, reverted, or lands on a different branch than expected.
// Each change is probed SEPARATELY -- tying several to one macro silently picks
// the wrong branch if they ever land in different releases.

// duckdb::Identifier replaced std::string as the name type in table-function and
// COPY bind signatures. urlpattern registers neither, so nothing here uses
// CompatName yet; it is kept so this header stays a drop-in match for the rest of
// the fleet's copies.
#if __has_include("duckdb/common/identifier.hpp")
#define DUCKDB_HAS_IDENTIFIER 1
#include "duckdb/common/identifier.hpp"
#endif

namespace duckdb {

// --- bind-signature name type -------------------------------------------------
#ifdef DUCKDB_HAS_IDENTIFIER
using CompatName = Identifier;
inline string CompatNameStr(const Identifier &id) {
	return id.GetIdentifierName();
}
inline Identifier CompatMakeName(string name) {
	return Identifier(std::move(name));
}
#else
using CompatName = string;
inline string CompatNameStr(const string &name) {
	return name;
}
inline string CompatMakeName(string name) {
	return name;
}
#endif

// --- LogicalType alias ---------------------------------------------------------
// v1.5: void SetAlias(string)                -- mutates in place
// v2.0: LogicalType WithAlias(string) const  -- returns a copy, never mutating a
//       type whose type-info is shared. SetAlias is REMOVED, not deprecated.
// `if constexpr` discards the untaken branch only inside a template, hence the
// template parameter.
template <class T, class = void>
struct CompatHasWithAlias : std::false_type {};
template <class T>
struct CompatHasWithAlias<T, decltype(void(std::declval<const T &>().WithAlias(string())))> : std::true_type {};

// Tag-dispatched rather than `if constexpr`, because the ENTRY POINT below is
// deliberately NOT a template and `if constexpr` only discards the untaken branch
// inside one. Tag dispatch has the property that actually matters here: only the
// selected overload is instantiated, so the branch naming the absent member is
// never compiled.
template <class TYPE>
inline LogicalType CompatWithAliasImpl(TYPE type, string alias, std::true_type) {
	return type.WithAlias(std::move(alias));
}
template <class TYPE>
inline LogicalType CompatWithAliasImpl(TYPE type, string alias, std::false_type) {
	type.SetAlias(std::move(alias));
	return type;
}

// The entry point takes a concrete LogicalType. A `template <class TYPE =
// LogicalType>` form looks equivalent but is not: the default template argument
// is inert because deduction wins, so the very natural call
//
//     CompatWithAlias(LogicalType::VARCHAR, "urlpattern")
//
// deduces TYPE = LogicalTypeId -- `LogicalType::VARCHAR` is a static constexpr
// LogicalTypeId (types.hpp), NOT a LogicalType -- and then hard-errors inside the
// shim with "request for member 'SetAlias' in 'type', which is of non-class type
// 'duckdb::LogicalTypeId'". That fires on the PINNED v1.5 build, not on v2.0. A
// concrete parameter restores the implicit LogicalTypeId -> LogicalType
// conversion at the call site; only the Impl overloads stay templated.
inline LogicalType CompatWithAlias(LogicalType type, string alias) {
	return CompatWithAliasImpl(std::move(type), std::move(alias), CompatHasWithAlias<LogicalType>());
}

// --- Vector::ToUnifiedFormat ---------------------------------------------------
// v2.0 dropped the count parameter. NOTE the polarity of this probe: v2.0 KEPT the
// count-taking overload as [[deprecated]], so probing for *that* would find it on
// both lines and always take the deprecated path. Probe for the count-FREE
// overload, which exists only on v2.0.
template <class T, class = void>
struct CompatToUnifiedWithoutCount : std::false_type {};
template <class T>
struct CompatToUnifiedWithoutCount<T, decltype(void(std::declval<T &>().ToUnifiedFormat(
                                          std::declval<UnifiedVectorFormat &>())))> : std::true_type {};

template <class VEC = Vector>
inline void CompatToUnifiedFormat(VEC &vec, idx_t count, UnifiedVectorFormat &data) {
	if constexpr (CompatToUnifiedWithoutCount<VEC>::value) {
		(void)count;
		vec.ToUnifiedFormat(data);
	} else {
		vec.ToUnifiedFormat(count, data);
	}
}

// --- FlatVector mutable data ---------------------------------------------------
// v1.5: FlatVector::GetData<T>(vec)         returns T*
// v2.0: FlatVector::GetData<T>(vec)         returns const T*
//       FlatVector::GetDataMutable<T>(vec)  returns T*
// Writing through the v2.0 read accessor is a compile error ("passing 'const
// duckdb::string_t' as 'this' argument discards qualifiers"), which is the point
// of the split -- so the WRITE path must ask for mutability explicitly.
template <class T, class = void>
struct CompatHasFlatGetDataMutable : std::false_type {};
template <class T>
struct CompatHasFlatGetDataMutable<T, decltype(void(T::template GetDataMutable<bool>(std::declval<Vector &>())))>
    : std::true_type {};

template <class VALUE, class FV = FlatVector>
inline VALUE *CompatFlatDataMutable(Vector &vec) {
	if constexpr (CompatHasFlatGetDataMutable<FV>::value) {
		return FV::template GetDataMutable<VALUE>(vec);
	} else {
		return FV::template GetData<VALUE>(vec);
	}
}

// --- StructVector::GetEntries element type -------------------------------------
// v1.5: vector<unique_ptr<Vector>> &  -- children reached through `*entries[i]`
// v2.0: vector<Vector> &              -- children ARE Vectors; `*entries[i]` is a
//                                        compile error ("no match for operator*").
// One spelling for both: CompatVectorRef(entries[i]).
template <class ENTRY>
inline Vector &CompatVectorRef(ENTRY &entry) {
	if constexpr (std::is_same<typename std::decay<ENTRY>::type, Vector>::value) {
		return entry;
	} else {
		return *entry;
	}
}

// --- BoundFunctionExpression::bind_info -----------------------------------------
// v1.5: public field `bind_info`
// v2.0: private, reached through BindInfo() / BindInfoMutable().
template <class T, class = void>
struct CompatHasBindInfoAccessor : std::false_type {};
template <class T>
struct CompatHasBindInfoAccessor<T, decltype(void(std::declval<const T &>().BindInfo()))> : std::true_type {};

template <class EXPR = BoundFunctionExpression>
inline const FunctionData &CompatBindInfo(const EXPR &expr) {
	if constexpr (CompatHasBindInfoAccessor<EXPR>::value) {
		return *expr.BindInfo();
	} else {
		return *expr.bind_info;
	}
}

// --- SimpleFunction::varargs ----------------------------------------------------
// v1.5 exposes `varargs` as a public field and has no setter; v2.0 moves it into
// FunctionSignature behind SetVarArgs/GetVarArgs. (`null_handling` and
// `init_local_state` moved the same way, but those already have setters on v1.5,
// so their call sites just use SetNullHandling/SetInitStateCallback directly.)
template <class T, class = void>
struct CompatHasSetVarArgs : std::false_type {};
template <class T>
struct CompatHasSetVarArgs<T, decltype(void(std::declval<T &>().SetVarArgs(std::declval<LogicalType>())))>
    : std::true_type {};

template <class FUNC>
inline void CompatSetVarArgs(FUNC &func, LogicalType varargs) {
	if constexpr (CompatHasSetVarArgs<FUNC>::value) {
		func.SetVarArgs(std::move(varargs));
	} else {
		func.varargs = std::move(varargs);
	}
}

// --- argument-alias capture ------------------------------------------------------
// v1.5 always recorded the alias of a named argument (`f(x := 1)`) on the bound
// child expression, so a bind callback could read it back with GetAlias(). v2.0
// made that opt-in via FunctionProperties::capture_argument_aliases, defaulting
// OFF -- so a function that derives named parameters from argument aliases sees
// EMPTY aliases on v2.0 unless it asks for the legacy behaviour. This is a silent
// RUNTIME change, not a compile error, which is why it is opted into explicitly.
// No-op where the property does not exist (v1.5 already behaves this way).
template <class T, class = void>
struct CompatHasCaptureArgumentAliases : std::false_type {};
template <class T>
struct CompatHasCaptureArgumentAliases<T, decltype(void(std::declval<T &>().SetCaptureArgumentAliases(true)))>
    : std::true_type {};

template <class FUNC>
inline void CompatCaptureArgumentAliases(FUNC &func) {
	if constexpr (CompatHasCaptureArgumentAliases<FUNC>::value) {
		func.SetCaptureArgumentAliases(true);
	} else {
		(void)func;
	}
}

// --- scalar bind callback shape ---------------------------------------------------
// v1.5: unique_ptr<FunctionData>(ClientContext &, ScalarFunction &, vector<unique_ptr<Expression>> &)
// v2.0: unique_ptr<FunctionData>(BindScalarFunctionInput &)
//
// The CALLBACK's own signature changed, so no wrapper object can paper over it --
// the function has to have a different shape on each line. CompatScalarBind is a
// variadic trampoline: converting it to `bind_scalar_function_t` deduces ARGS from
// whichever signature that typedef currently names, and the overloaded accessor
// below pulls the argument list out of either shape. Deduction is on `ARGS &...`
// (not `ARGS &&...`): every parameter of both signatures is an lvalue reference,
// and a forwarding reference does not deduce against one outside a call context.
namespace compat_bind_detail {

// v1.5 shape.
inline vector<unique_ptr<Expression>> &BindArguments(ClientContext &, ScalarFunction &,
                                                     vector<unique_ptr<Expression>> &arguments) {
	return arguments;
}

// v2.0 shape. SFINAE-constrained so it is never considered on v1.5.
template <class INPUT>
inline auto BindArguments(INPUT &input) -> decltype(input.GetArguments()) {
	return input.GetArguments();
}

} // namespace compat_bind_detail

using compat_bind_body_t = unique_ptr<FunctionData> (*)(vector<unique_ptr<Expression>> &arguments);

template <compat_bind_body_t BODY, class... ARGS>
inline unique_ptr<FunctionData> CompatScalarBind(ARGS &...args) {
	return BODY(compat_bind_detail::BindArguments(args...));
}

} // namespace duckdb
