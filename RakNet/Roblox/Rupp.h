#pragma once
#include <vector>
#include <memory>
#include <string_view>


#include "BitStream.h"

namespace RBX::Network::Rupp
{
	enum class ErrorCode
	{
		SUCCESS = 0x0,
		FAILED_DESERIALIZATION = 0x1,
		INVALID_PROTOCOL = 0x2,
		INVALID_FLAGS = 0x3,
		INVALID_LENGTH = 0x4,
		INVALID_TLV_TYPE = 0x5,
		INVALID_TLV_LENGTH = 0x6,
		TLV_ALREADY_EXISTS = 0x7,
		TLV_NOT_FOUND = 0x8,
		INVALID_TOKEN = 0x9,
		INVALID_ENDPOINT = 0xA,
	};

	struct TypeLengthValue {
		enum class TlvType {};
		virtual TlvType getTlvType();
		virtual unsigned char getValueByteLength();
		virtual void serialize(RakNet::BitStream& b);
		virtual ErrorCode deserialize(RakNet::BitStream& b, unsigned lengthOfTlvValue);
	};

	struct TokenTlv : TypeLengthValue
	{
		struct Token {
			unsigned char type[1];
			unsigned __int8 value[16];
		} token;
	};


	struct Rupp
	{
		enum class ProtocolType : unsigned char
		{
			RakNet
		};

		struct RuppInfo
		{
			std::string_view tokenInBitstream;
			unsigned char tokenType[1];
			ProtocolType protocol;
			unsigned char flag;
		} ruppInfo;
		std::vector<std::unique_ptr<TypeLengthValue> > typeLengthValues;
		bool cachedSerializationIsValid;
		RakNet::BitStream cachedSerialization;
		unsigned int tokenValueCacheLocation;

		static ErrorCode deserialize(RuppInfo& ruppInfoObject, RakNet::BitStream& b, unsigned short& ruppHeaderLength);
	};
}
