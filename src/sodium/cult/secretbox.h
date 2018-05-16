#pragma once
#include "sodium/common.h"

#include "all.h"


namespace cultlang {
namespace sodium
{
	class SecretBoxKey
		: public virtual craft::types::Object
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_OBJECT_DECLARE(cultlang::sodium::SecretBoxKey);
		
	public:
		unsigned char key[crypto_secretbox_KEYBYTES];
		CULTLANG_SODIUM_EXPORTED SecretBoxKey();
	};

	class SecretBoxCipher
		: public virtual craft::types::Object
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_OBJECT_DECLARE(cultlang::sodium::SecretBoxCipher);

	public:
		std::vector<uint8_t> cipher;

		SecretBoxCipher() = default;
		SecretBoxCipher(craft::instance<SecretBoxKey> key, craft::instance<Nonce> nonce, craft::instance<std::string> message);
	};

}}