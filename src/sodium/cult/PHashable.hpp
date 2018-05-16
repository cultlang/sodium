#pragma once
#include "hash.h"

namespace cultlang {
namespace sodium 
{
	class PHashable abstract
		: public craft::types::Provider
	{
		CULTLANG_SODIUM_EXPORTED CRAFT_LEGACY_FEATURE_DECLARE(cultlang::sodium::PHashable, "cultlang.sodium.hash", craft::types::SingletonProviderManager);

	public:
		virtual Hash asHash(craft::instance<> inst) const = 0;
	};

	/******************************************************************************
	** FunctionalStringer
	******************************************************************************/

	namespace _details
	{
		static std::function<Hash(craft::instance<>)> FunctionalHasher_defaultReport;
	}

	template <typename T>
	class FunctionalHasher
		: public craft::types::Implements<PHashable>::For<T>
	{
		std::function<Hash(craft::instance<>)> _hasher;

	public:
		inline FunctionalHasher(std::function<Hash(craft::instance<T>)> const& hasher)
			: _hasher([hasher](craft::instance<> inst) { return hasher(inst.asType<T>()); })
		{ }

		inline virtual Hash asHash(craft::instance<> inst) const override { return _hasher(inst); }
	};
	
}}


