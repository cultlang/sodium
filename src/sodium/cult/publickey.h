#pragma once
#include "sodium/common.h"

#include "all.h"

namespace cultlang {
namespace sodium
{
	class PrivateKey
		: public virtual craft::types::Object
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_OBJECT_DECLARE(cultlang::sodium::PrivateKey);
		
	public:
		unsigned char key[crypto_box_SECRETKEYBYTES];
	};

	class PublicKey
		: public virtual craft::types::Object
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_OBJECT_DECLARE(cultlang::sodium::PublicKey);

	public:
		unsigned char key[crypto_box_PUBLICKEYBYTES];
	};
	
	class Keypair
		: public virtual craft::types::Object
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_OBJECT_DECLARE(cultlang::sodium::Keypair);

	public:
		Keypair();

		craft::instance<PrivateKey> private_;
		craft::instance<PublicKey> public_;
	};

	class KeypairCipher
		: public virtual craft::types::Object
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_OBJECT_DECLARE(cultlang::sodium::KeypairCipher);

	public:
		std::vector<uint8_t> cipher;

		KeypairCipher() = default;
		KeypairCipher(craft::instance<PublicKey> pub, craft::instance<PrivateKey> priv, craft::instance<Nonce> nonce, craft::instance<std::string> message);
	};
}}