#pragma once

#include "duckdb.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
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
// The element type of the bind out-parameter, DERIVED from DuckDB rather than
// guessed from a header probe.
//
// `__has_include("duckdb/common/identifier.hpp")` is NOT a safe proxy for this
// change, and using it is a time bomb. identifier.hpp was BACKPORTED to the v1.5
// stable branch WITHOUT changing table_function_bind_t, so on the v1.5 branch tip
// the header exists while the bind signature still wants vector<string>. Three
// heads, verified:
//
//   v1.5-variegata @ b155d6f63c (our pin)  no identifier.hpp   bind: vector<string>
//   v1.5-variegata @ branch tip            HAS identifier.hpp  bind: vector<string>
//   main (v2.0)                            HAS identifier.hpp  bind: vector<Identifier>
//
// A header-keyed probe is right today only because our pin predates the backport;
// the next submodule bump would silently flip CompatName to Identifier on a DuckDB
// that still wants strings. Reading the type off input_table_names is exact on all
// three by construction, because it IS the bind out-parameter's element type
// (table_function.hpp:110 on the pin, :123 on main).
//
// urlpattern registers no table functions and no COPY function, so nothing here
// uses CompatName yet; it is kept so this header stays a drop-in match for the
// rest of the fleet's copies -- which is exactly why it must not carry a probe
// that is wrong on a version we have not bumped to yet.
using CompatName = typename std::remove_reference<decltype(
    std::declval<TableFunctionBindInput &>().input_table_names)>::type::value_type;

inline string CompatNameStr(const string &name) {
	return name;
}
#ifdef DUCKDB_HAS_IDENTIFIER
// Gated on the header only to declare the overload, never to decide CompatName.
inline string CompatNameStr(const Identifier &id) {
	return id.GetIdentifierName();
}
#endif
inline CompatName CompatMakeName(string name) {
	return CompatName(std::move(name));
}

// Standing guard: if CompatName ever resolves to a type the overloads above do not
// cover -- e.g. Identifier on a build where identifier.hpp was not found, so the
// Identifier overload was never declared -- this fails at compile time instead of
// silently selecting the wrong conversion.
static_assert(std::is_same<decltype(CompatNameStr(std::declval<const CompatName &>())), string>::value,
              "CompatNameStr must accept the derived CompatName on every DuckDB line");

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

// --- variadic declaration: *args and **kwargs -----------------------------------
// v1.5 says "accepts extra arguments of this type" with ONE public field,
// `SimpleFunction::varargs`, and there is no setter. Named arguments (`f(x := 1)`)
// arrive as an ALIAS on each bound child expression.
//
// v2.0 removes the field and splits the idea into two parameter KINDS on
// FunctionSignature (function.hpp:125-133, mirroring Python):
//     AddArgs(name, type)    -> VAR_POSITIONAL, "*args"
//     AddKwargs(name, type)  -> VAR_KEYWORD,    "**kwargs" -- receives every named
//                               argument that matches no other parameter
// and the names stop being aliases: the binder passes them to the bind callback via
// BindFunctionInput (GetArgumentNames() on v2.0, GetArgumentName(idx) on main),
// and ONLY if the function opts in with
// FunctionProperties::requires_expression_names.
//
// Which kind a function wants is a semantic choice, not a mechanical rename, and
// getting it wrong COMPILES. `url_build(protocol := 'https')` is a keyword
// argument, so url_build wants **kwargs; declaring *args would build fine and then
// refuse every call. DuckDB's own `union_value` is the same shape -- named
// arguments, no positional ones -- and is declared exactly this way:
//     fun.GetSignature().AddKwargs("kwargs", LogicalType::ANY);
//     fun.GetProperties().SetRequiresExpressionNames(true);
// (extension/core_functions/scalar/union/union_value.cpp). url_modify takes one
// positional URL *and* named components, so it declares both; VAR_POSITIONAL and
// VAR_KEYWORD coexist, each found by its own independent lookup
// (FunctionSignature::GetArgs / GetKwargs).
//
// The probe is on GetSignature(), not on AddArgs/AddKwargs: it is the v2.0-only
// entry point, and probing the thing we are about to call keeps the two branches
// from both being viable.
template <class T, class = void>
struct CompatHasGetSignature : std::false_type {};
template <class T>
struct CompatHasGetSignature<T, decltype(void(std::declval<T &>().GetSignature()))> : std::true_type {};

//! The name given to the VAR_POSITIONAL parameter on v2.0. A positional argument
//! has no caller-supplied name, so CompatArgumentNames reports it as EMPTY -- the
//! v1.5 spelling -- and bind bodies stay written one way for both lines.
static constexpr const char *CompatVarArgsName = "args";

// A note on why neither function below ever writes the word `Identifier`.
// AddArgs/AddKwargs take an `Identifier`, whose `const char *` constructor is
// implicit by design ("literals in the source are identifiers by intent") while its
// `const string &` one is explicit. Naming the type would be the obvious spelling and
// it BREAKS v1.5: `Identifier` does not exist there, and inside a template it is a
// NON-DEPENDENT name, so two-phase lookup requires a declaration at definition time
// even though the call sits in a discarded `if constexpr` branch. Measured, not
// guessed -- it cost a v1.5 build with
//   "there are no arguments to 'Identifier' that depend on a template parameter".
// Passing the literal keeps the name out of the template entirely.
//! Declare "accepts extra POSITIONAL arguments of this type" (*args).
template <class FUNC>
inline void CompatSetVarArgs(FUNC &func, LogicalType varargs) {
	if constexpr (CompatHasGetSignature<FUNC>::value) {
		func.GetSignature().AddArgs(CompatVarArgsName, std::move(varargs));
	} else {
		func.varargs = std::move(varargs);
	}
}

//! Declare "accepts arbitrary NAMED arguments of this type" (**kwargs), and ask the
//! binder to resolve their names. On v1.5 both halves are the one varargs field
//! plus aliases, which are always captured.
template <class FUNC>
inline void CompatSetKwargs(FUNC &func, LogicalType kwargs) {
	if constexpr (CompatHasGetSignature<FUNC>::value) {
		func.GetSignature().AddKwargs("kwargs", std::move(kwargs));
		func.GetProperties().SetRequiresExpressionNames(true);
	} else {
		func.varargs = std::move(kwargs);
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

//! The caller-supplied name of every argument, parallel to the argument list, with
//! an EMPTY string where the argument was passed positionally.
//!
//! This exists because the NAMES moved while the arguments did not. On v1.5 a named
//! argument's name is an alias on the bound child, readable with GetAlias(); on v2.0
//! and later aliases are empty and the binder supplies names through
//! BindFunctionInput -- GetArgumentNames() on v2.0, GetArgumentName(idx) on main.
//! That is a SILENT runtime difference -- a bind body that reads GetAlias() compiles
//! on v2.0 and then sees every argument as positional -- so all THREE sources are
//! resolved here, once, and every bind body reads this one list.
using compat_arg_names_t = vector<string>;

namespace compat_bind_detail {

// v1.5 shape: the names are the children's aliases.
inline compat_arg_names_t BindArgumentNames(ClientContext &, ScalarFunction &,
                                            vector<unique_ptr<Expression>> &arguments) {
	compat_arg_names_t names;
	names.reserve(arguments.size());
	for (auto &arg : arguments) {
		// static_cast, not an implicit conversion: GetAlias() yields `string` on v1.5
		// and `Identifier` on v2.0, and Identifier's operator const string & is
		// explicit. This overload is never CALLED on v2.0 -- aliases are empty there --
		// but it is a plain inline function, so it is still COMPILED on both lines.
		names.push_back(static_cast<string>(arg->GetAlias()));
	}
	return names;
}

// v2.0 shape. SFINAE-constrained so it is never considered on v1.5.
template <class INPUT>
inline auto BindArgumentNames(INPUT &input) -> decltype(input.GetArgumentNames(), compat_arg_names_t()) {
	auto &arguments = input.GetArguments();
	compat_arg_names_t names(arguments.size());
	auto argument_names = input.GetArgumentNames();
	if (!argument_names) {
		// Names unavailable: every argument reads as positional, which is what the
		// absence of a name means.
		return names;
	}
	for (idx_t i = 0; i < names.size() && i < argument_names->size(); i++) {
		const string &name = argument_names->operator[](i).GetIdentifierName();
		// A positional argument is reported under the VAR_POSITIONAL parameter's own
		// name. The caller never wrote that name, so normalise it back to empty and
		// keep "empty means positional" true on both lines.
		if (name != CompatVarArgsName) {
			names[i] = name;
		}
	}
	return names;
}

// duckdb main (v2.1-bound) shape. SFINAE-constrained on the INDEXED accessor, so
// it is never considered on v1.5 or on v2.0.
//
// main replaced the bulk accessor with a per-argument one:
//     v2.0  optional_ptr<const vector<Identifier>> GetArgumentNames() const
//     main  const Identifier &GetArgumentName(idx_t arg_idx) const
// (duckdb src/include/duckdb/function/function.hpp:700 on v2.0-cyanoptera and
// :713 on main, read 2026-10-30.) Found by this repo's main canary, run
// 41115557061: without this overload the v2.0 template drops out of the overload
// set and CompatScalarBind below has no viable BindArgumentNames to call.
//
// Two differences from the v2.0 overload, both taken from upstream's own doc
// comment and not guessed:
//   * there is no "names unavailable" case. Every index has a name, so the
//     optional_ptr check above has no counterpart here.
//   * "*args" ALREADY reads as an empty name upstream, so the CompatVarArgsName
//     normalisation the v2.0 overload needs is not needed and is not repeated.
//     Upstream: "the parameter name for standard and keyword-only parameters, the
//     name the caller wrote for **kwargs, and an empty name for *args".
//
// The two templates are mutually exclusive BY CONSTRUCTION: v2.0 has only the bulk
// accessor, main has only the indexed one. They take the same parameter list and
// differ only in their trailing return type, so partial ordering cannot separate
// them -- if some future duckdb ever carries BOTH, this call becomes an AMBIGUITY
// error rather than silently picking one. That is the loud failure we want, and
// the fix then is to delete the overload for the line we no longer build.
template <class INPUT>
inline auto BindArgumentNames(INPUT &input) -> decltype(input.GetArgumentName(idx_t(0)), compat_arg_names_t()) {
	auto &arguments = input.GetArguments();
	compat_arg_names_t names(arguments.size());
	for (idx_t i = 0; i < names.size(); i++) {
		names[i] = input.GetArgumentName(i).GetIdentifierName();
	}
	return names;
}

} // namespace compat_bind_detail

using compat_bind_body_t = unique_ptr<FunctionData> (*)(vector<unique_ptr<Expression>> &arguments,
                                                        const compat_arg_names_t &arg_names);

template <compat_bind_body_t BODY, class... ARGS>
inline unique_ptr<FunctionData> CompatScalarBind(ARGS &...args) {
	const auto arg_names = compat_bind_detail::BindArgumentNames(args...);
	return BODY(compat_bind_detail::BindArguments(args...), arg_names);
}

} // namespace duckdb
