#pragma once
#define SODIUM_STATIC
#include "lisp/common.h"
#include "sodium/sodium.h"

namespace cultlang {
namespace sodium {
	class Nonce
		: public virtual craft::types::Object
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_OBJECT_DECLARE(cultlang::sodium::Nonce);

	public:
		unsigned char nonce[crypto_secretbox_NONCEBYTES];

		CULTLANG_SODIUM_EXPORTED Nonce();
	};
}}