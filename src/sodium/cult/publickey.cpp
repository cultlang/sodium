#include "sodium/common.h"
#include "publickey.h"

using namespace craft;
using namespace craft::types;
using namespace craft::lisp;
using namespace cultlang::sodium;

CRAFT_DEFINE(PrivateKey)
{
	_.use<PParse>().singleton<FunctionalParse>([](std::string s) {
		size_t bin_len;

		std::string buf;
		buf.resize(s.size());

		auto res = instance<PrivateKey>::make();
		sodium_base642bin((uint8_t*)buf.c_str(), crypto_box_SECRETKEYBYTES,
			s.c_str(), s.size(), 0, &bin_len, 0, sodium_base64_VARIANT_URLSAFE);

		if (bin_len != crypto_generichash_BYTES)
			throw stdext::exception("Invalid String Length for Hash");

		memcpy(res->key, buf.data(), bin_len);
		return res;
	});

	_.use<PStringer>().singleton<FunctionalStringer>([](instance<PrivateKey> l) -> std::string {
		auto mlen = sodium_base64_ENCODED_LEN(crypto_box_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE);
		std::string res; res.resize(mlen);
		sodium_bin2base64(const_cast<char*>(res.c_str()), mlen, l->key, crypto_box_SECRETKEYBYTES,
			sodium_base64_VARIANT_URLSAFE);
		return res;
	});

	_.use<PRepr>().singleton<FunctionalRepr>(
		[](instance<PrivateKey> l) -> std::string
	{
		return l.getFeature<PRepr>()->toRepr(l);
	});
	_.defaults();
}

CRAFT_DEFINE(PublicKey)
{
	_.use<PParse>().singleton<FunctionalParse>([](std::string s) {
		size_t bin_len;

		std::string buf;
		buf.resize(s.size());

		auto res = instance<PublicKey>::make();
		sodium_base642bin((uint8_t*)buf.c_str(), crypto_box_PUBLICKEYBYTES,
			s.c_str(), s.size(), 0, &bin_len, 0, sodium_base64_VARIANT_URLSAFE);

		if (bin_len != crypto_generichash_BYTES)
			throw stdext::exception("Invalid String Length for Hash");

		memcpy(res->key, buf.data(), bin_len);
		return res;
	});

	_.use<PStringer>().singleton<FunctionalStringer>([](instance<PublicKey> l) -> std::string {
		auto mlen = sodium_base64_ENCODED_LEN(crypto_box_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE);
		std::string res; res.resize(mlen);
		sodium_bin2base64(const_cast<char*>(res.c_str()), mlen, l->key, crypto_box_PUBLICKEYBYTES,
			sodium_base64_VARIANT_URLSAFE);
		return res;
	});

	_.use<PRepr>().singleton<FunctionalRepr>(
		[](instance<PublicKey> l) -> std::string
	{
		return l.getFeature<PRepr>()->toRepr(l);
	});
	_.defaults();
}

CRAFT_DEFINE(Keypair)
{
	_.use<PStringer>().singleton<FunctionalStringer>([](instance<Keypair> l) -> std::string {
		std::ostringstream  res;

		res << "{" << "public: " << l->public_ << ", private: " << l->private_ << "}";

		return res.str();
	});
	_.use<PRepr>().singleton<FunctionalRepr>(
		[](instance<Keypair> l) -> std::string
	{
		return l.getFeature<PRepr>()->toRepr(l);
	});
	_.defaults();
}


Keypair::Keypair()
{
	private_ = instance<PrivateKey>::make();
	public_ = instance<PublicKey>::make();

	crypto_box_keypair(public_->key, private_->key);
}

CRAFT_DEFINE(KeypairCipher)
{
	_.use<PParse>().singleton<FunctionalParse>([](std::string s) {
		auto res = instance<KeypairCipher>::make();
		res->cipher.resize(s.size());

		size_t bin_len;
		sodium_base642bin(res->cipher.data(), s.size(),
			s.c_str(), s.size(), 0, &bin_len, 0, sodium_base64_VARIANT_URLSAFE);
		res->cipher.resize(bin_len);
		return res;
	});

	_.use<PStringer>().singleton<FunctionalStringer>([](instance<KeypairCipher> l) -> std::string {
		auto mlen = sodium_base64_ENCODED_LEN(l->cipher.size(), sodium_base64_VARIANT_URLSAFE);
		std::string res; res.resize(mlen);
		sodium_bin2base64(const_cast<char*>(res.c_str()), mlen, l->cipher.data(), l->cipher.size(),
			sodium_base64_VARIANT_URLSAFE);
		return res;
	});

	_.use<PRepr>().singleton<FunctionalRepr>(
		[](instance<KeypairCipher> l) -> std::string
	{
		return l.getFeature<PRepr>()->toRepr(l);
	});
	_.defaults();
}


KeypairCipher::KeypairCipher(instance<PublicKey> pub, instance<PrivateKey> priv, instance<Nonce> nonce, instance<std::string> message)
{
	cipher.resize(crypto_secretbox_MACBYTES + message->size());
	if (crypto_box_easy(cipher.data(), (uint8_t*)message->c_str(), message->size(), nonce->nonce,
		pub->key, priv->key) != 0) {
		throw stdext::exception("Those Keys must be wrong sorry");
	}
}
