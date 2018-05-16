#pragma once
#include "lisp/common.h"

#define SODIUM_STATIC
#include "sodium/sodium.h"

namespace cultlang {
namespace sodium {
	class Hash
		: public virtual craft::types::Object
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_OBJECT_DECLARE(cultlang::sodium::Hash);
		
	public:
		uint8_t hash[crypto_generichash_BYTES];
	};

}}