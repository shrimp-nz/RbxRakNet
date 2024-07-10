#include "Rupp.h"

using namespace RBX::Network::Rupp;

ErrorCode Rupp::deserialize(RuppInfo& ruppInfoObject, RakNet::BitStream& b, unsigned short& ruppHeaderLength)
{
	if (!b.Read(ruppInfoObject.protocol))
	{
		return ErrorCode::FAILED_DESERIALIZATION;
	}
	if (ruppInfoObject.protocol != Rupp::ProtocolType::RakNet)
	{
		return ErrorCode::INVALID_PROTOCOL;
	}
	if (!b.Read(ruppInfoObject.flag))
	{
		return ErrorCode::FAILED_DESERIALIZATION;
	}
	if (!b.Read(ruppHeaderLength))
	{
		return ErrorCode::FAILED_DESERIALIZATION;
	}
	if (ruppHeaderLength <= 4)
	{
		return ErrorCode::INVALID_LENGTH;
	}

	return ErrorCode::SUCCESS;
}
