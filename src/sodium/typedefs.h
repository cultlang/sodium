#pragma  once
#include "cult/all.h"

typedef instance<std::string> t_str;

typedef instance<int8_t> t_i8;
typedef instance<uint16_t> t_i16;
typedef instance<uint32_t> t_i32;
typedef instance<uint64_t> t_i64;

typedef instance<uint8_t> t_u8;
typedef instance<uint16_t> t_u16;
typedef instance<uint32_t> t_u32;
typedef instance<uint64_t> t_u64;


typedef instance<float> t_f32;
typedef instance<double> t_f64;

typedef instance<Hash> t_hsh;
typedef instance<PHashable> t_phbl;
typedef instance<Nonce> t_non;
typedef instance<SecretBoxKey> t_sbk;
typedef instance<SecretBoxCipher> t_sbc;
typedef instance<PrivateKey> t_prk;
typedef instance<PublicKey> t_puk;
typedef instance<Keypair> t_kp;
typedef instance<KeypairCipher> t_kpc;
