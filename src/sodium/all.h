#pragma once
#include "sodium/common.h"

namespace cultlang {
namespace sodium 
{
	extern craft::lisp::BuiltinModuleDescription BuiltinSodium;

	CULTLANG_SODIUM_EXPORTED craft::instance<craft::lisp::Module> make_sodium_bindings(craft::instance<craft::lisp::Namespace> ns, craft::instance<> loader);
}}
