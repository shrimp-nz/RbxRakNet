#pragma once
#include "../BitStream.h"

#include <array>
#include <memory>
#include <string>
#include <span>
namespace RBX::Security
{
	struct EarlyAuthData
	{
		std::string preauthBlob;
		std::string authBlob;
		std::uint8_t authVersion;
	};

	inline constexpr auto rakNonce = 0x754E657571696E55;
	struct SessionCrypto
	{
		virtual	~SessionCrypto() = default;
		bool initCommon();
		void resetKeyExchangeKeys(bool error);
		bool earlyDecryptData(std::span<std::uint8_t> message, std::span<const std::uint8_t> box, std::size_t aadSize);

		std::atomic<std::uint64_t> appNonce = 0;
		std::atomic<std::uint64_t> txRakNonce = rakNonce;
		std::uint64_t rxRakNonce = rakNonce;
		struct KeyExchangeKeys
		{
			KeyExchangeKeys();

			std::array<std::uint8_t, 32> publicEphemeralKey;
			std::array<std::uint8_t, 32> secretEphemeralKey;
			std::array<std::uint8_t, 32> publicEarlyKey;
			std::array<std::uint8_t, 32> secretEarlyKey;
			std::array<std::uint8_t, 32> earlySessionKeyClientToServer;
			std::array<std::uint8_t, 32> earlySessionKeyServerToClient;
			std::array<std::uint8_t, 32> peerPublicEphemeralKey;
		};
		std::unique_ptr<KeyExchangeKeys> keyExchangeKeys;
		bool isServer = false;
		bool isEarlySessionReady;
		bool isSessionReady;
		bool isError;
		enum CryptoFormat : std::uint8_t 
		{
			NoCrypto,
			ChaCha20Poly1305Ietf,
			Aes256Gcm,
			TestMask = 0x80,
			TestChaCha20Poly1305Ietf,
			TestAes256Gcm,
		} rakFormat = CryptoFormat::NoCrypto;
		std::shared_ptr<EarlyAuthData> earlyAuthData;
		std::array<std::uint8_t, 32> sessionKeyClientToServer;
		std::array<std::uint8_t, 32> sessionKeyServerToClient;
	};

	struct RakPeerCrypto : SessionCrypto
	{
		// publicEarlyKey, secretEarlyKey
		// returns a pair of `HuffmanStream`s in Roblox
		static std::pair<std::array<std::uint8_t, 32>, std::array<std::uint8_t, 32>> getServerKeyInfo(unsigned version);
		bool initServer(const std::array<std::uint8_t, 32>& publicEarlyKey, const std::array<std::uint8_t, 32>& secretEarlyKey);
		bool serverInitEarlySessionKeys(const std::array<std::uint8_t, 32>& peerPublicKey);
		bool earlyDecryptData(RakNet::BitStream& bitStream, std::size_t aadSize);
	private:
		static std::array<std::uint8_t, 32> kPublicEarlyTestKey;
		static std::array<std::uint8_t, 32> kSecretEarlyTestKey;
		static std::array<std::uint8_t, 32> kPublicEphemeralEarlyTestKey;
		static std::array<std::uint8_t, 32> kSecretEphemeralEarlyTestKey;
	};
}