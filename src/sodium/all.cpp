#include "sodium/common.h"

#include "all.h"

#include "lisp/library/system/prelude.h"
#include "lisp/semantics/cult/calling.h"

#include "cult/all.h"

using namespace craft;
using namespace craft::lisp;
using namespace craft::types;
using namespace cultlang::sodium;



#define lMM semantics->builtin_implementMultiMethod
#define SoD "sodium"


#define hsh(type)  (crypto_generichash(res->hash, crypto_generichash_BYTES, (uint8_t*)a.get(), sizeof(type), NULL, 0))

#include "typedefs.h"


instance<Module> cultlang::sodium::make_sodium_bindings(instance<lisp::Namespace> ns, instance<> loader)
{
	auto ret = instance<Module>::make(ns, loader);
	auto semantics = instance<CultSemantics>::make(ret);
	ret->builtin_setSemantics(semantics);

	lMM(SoD"/hash", [](instance<int32_t> a) { auto res = t_hsh::make(); hsh(int32_t); return res; });
	lMM(SoD"/hash", [](instance<uint8_t> a) { auto res = t_hsh::make(); hsh(uint8_t); return res; });
	lMM(SoD"/hash", [](instance<int8_t> a) { auto res = t_hsh::make(); hsh(int8_t); return res; });
	lMM(SoD"/hash", [](instance<uint64_t> a) { auto res = t_hsh::make(); hsh(uint64_t); return res; });
	lMM(SoD"/hash", [](instance<uint16_t> a) { auto res = t_hsh::make(); hsh(uint16_t); return res; });
	lMM(SoD"/hash", [](instance<float> a) { auto res = t_hsh::make(); hsh(float); return res; });
	lMM(SoD"/hash", [](instance<uint32_t> a) { auto res = t_hsh::make(); hsh(uint32_t); return res; });
	lMM(SoD"/hash", [](instance<bool> a) { auto res = t_hsh::make(); hsh(bool); return res; });
	lMM(SoD"/hash", [](instance<double> a) { auto res = t_hsh::make(); hsh(double); return res; });
	lMM(SoD"/hash", [](instance<int64_t> a) { auto res = t_hsh::make(); hsh(int64_t); return res; });
	lMM(SoD"/hash", [](instance<int16_t> a) { auto res = t_hsh::make(); hsh(int16_t); return res; });
	
	lMM(SoD"/nonce", [](){ return  t_non::make();});

	lMM(SoD"/curve", []() {return t_kp::make(); });
	lMM(SoD"/curve/private", [](t_kp a) {return a->private_; });
	lMM(SoD"/curve/public", [](t_kp a) {return a->public_; });
	lMM(SoD"/curve/encrypt", [](t_str msg, t_puk pub, t_prk priv,  t_non nonce) { return t_kpc::make(pub, priv, nonce, msg);});
	lMM(SoD"/curve/decrypt", [](t_kpc msg, t_puk pub, t_prk priv,  t_non nonce){
		size_t outsize = msg->cipher.size() - crypto_secretbox_MACBYTES;
		std::string res;
		res.resize(outsize);
		if (crypto_box_open_easy((uint8_t*)res.c_str(), msg->cipher.data(), msg->cipher.size(), nonce->nonce, pub->key, priv->key) != 0) {
			throw stdext::exception("Message Forgary");
		}
		return instance<std::string>::make(res);
	});

	lMM(SoD"/salsa", []() { return t_sbk::make();});
	lMM(SoD"/salsa/encrypt", [](instance<std::string> msg, t_sbk secret,  t_non nonce){ return t_sbc::make(secret, nonce, msg);});
	lMM(SoD"/salsa/decrypt", [](t_sbc msg, t_sbk key,  t_non nonce) {
		size_t outsize = msg->cipher.size() - crypto_secretbox_MACBYTES;
		std::string res;
		res.resize(outsize);
		if (crypto_secretbox_open_easy((uint8_t*)res.c_str(), msg->cipher.data(), msg->cipher.size(), nonce->nonce, key->key) != 0) {
			throw stdext::exception("Message Forgary");
		}
		return instance<std::string>::make(res);
	});
	return ret;
}

CRAFT_INIT_PRIORITY BuiltinModuleDescription cultlang::sodium::BuiltinSodium("cult/sodium", cultlang::sodium::make_sodium_bindings);


#include "types/dll_entry.inc"
