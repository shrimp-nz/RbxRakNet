#include "Security.h"

#include <stdexcept>
#include <sodium.h>

using namespace RBX::Security;

std::array<std::uint8_t, 32> RakPeerCrypto::kPublicEarlyTestKey {
  0xCB, 0xB1, 0x8F, 0x91, 0x1D, 0x92, 0xB5, 0x5C, 0xD1, 0x8B,
  0x8D, 0x70, 0x68, 0x9D, 0xE6, 0x26, 0x08, 0xA0, 0xFA, 0x40,
  0x17, 0xC8, 0x59, 0xB2, 0x47, 0xD4, 0x67, 0xE2, 0x13, 0x88,
  0x2E, 0x61
};

std::array<std::uint8_t, 32> RakPeerCrypto::kSecretEarlyTestKey {
  0xE3, 0x44, 0x6C, 0x52, 0x05, 0xA5, 0x1D, 0xB9, 0x03, 0x1F,
  0x36, 0xA2, 0x59, 0x8D, 0x90, 0x5A, 0x35, 0xB7, 0x30, 0xDD,
  0x5C, 0xFC, 0x48, 0x4C, 0x86, 0x13, 0x12, 0x81, 0xA8, 0x46,
  0x71, 0x43
};

std::array<std::uint8_t, 32> RakPeerCrypto::kPublicEphemeralEarlyTestKey{
  0xD3, 0x71, 0xCB, 0x6E, 0x10, 0x7C, 0xCF, 0xC3, 0xAA, 0xE7,
  0xEE, 0xE4, 0x7B, 0x4B, 0x6D, 0x8B, 0x66, 0x5C, 0x59, 0x43,
  0x6E, 0x2F, 0x83, 0x41, 0x7B, 0xFA, 0xBE, 0x29, 0xA1, 0xC6,
  0x46, 0x3D
};

std::array<std::uint8_t, 32> RakPeerCrypto::kSecretEphemeralEarlyTestKey{
  0x3C, 0xDB, 0xCC, 0x14, 0x31, 0xB6, 0x2D, 0xCE, 0x8C, 0xE6,
  0xF3, 0xDB, 0x77, 0xD7, 0x4F, 0xE5, 0xF7, 0x5E, 0x49, 0xBA,
  0x17, 0x6D, 0xE2, 0x17, 0xF7, 0x1E, 0x31, 0x31, 0x2A, 0x2C,
  0x45, 0x4E
};

SessionCrypto::KeyExchangeKeys::KeyExchangeKeys()
{
    sodium_memzero(publicEphemeralKey.data(), publicEphemeralKey.size());
    sodium_memzero(secretEphemeralKey.data(), secretEphemeralKey.size());
    sodium_memzero(publicEarlyKey.data(), publicEarlyKey.size());
    sodium_memzero(secretEarlyKey.data(), secretEarlyKey.size());
    sodium_memzero(earlySessionKeyClientToServer.data(), earlySessionKeyClientToServer.size());
    sodium_memzero(earlySessionKeyServerToClient.data(), earlySessionKeyServerToClient.size());
    sodium_memzero(peerPublicEphemeralKey.data(), peerPublicEphemeralKey.size());
}

bool SessionCrypto::initCommon()
{
    if (sodium_init() < 0)
    {
        printf("Unable to initialize libsodium.\n");
        return false;
    }
    isEarlySessionReady = 0;
    isError = 0;
    keyExchangeKeys = std::make_unique<SessionCrypto::KeyExchangeKeys>();
    return crypto_kx_keypair(keyExchangeKeys->publicEphemeralKey.data(), keyExchangeKeys->secretEphemeralKey.data()) == 0;
}

void RBX::Security::SessionCrypto::resetKeyExchangeKeys(bool error)
{
    keyExchangeKeys = std::make_unique<KeyExchangeKeys>();
    this->isEarlySessionReady = false;
    if (error)
    {
        throw std::runtime_error("not implemented");
    }
}

bool RBX::Security::SessionCrypto::earlyDecryptData(std::span<std::uint8_t> message, std::span<const std::uint8_t> box, std::size_t aadSize)
{
    if (isError || !isEarlySessionReady)
    {
        return false;
    }
    
    auto key = isServer ? &keyExchangeKeys->earlySessionKeyClientToServer : &keyExchangeKeys->earlySessionKeyServerToClient;
    // TODO: check length?
    memcpy(message.data(), box.data(), aadSize);
    return !crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            &message[aadSize], 
            nullptr, 
            &box[aadSize], 
            message.size() - aadSize, 
            &box[message.size() + 12], 
            box.data(), 
            aadSize, 
            &box[message.size()], 
            key->data()
        );
}

// TODO: version enum
std::pair<std::array<std::uint8_t, 32>, std::array<std::uint8_t, 32>> RakPeerCrypto::getServerKeyInfo(unsigned version)
{
    if (version)
    {
        throw std::runtime_error("not implemented");
    }
    else
    {
        // return { kPublicEarlyTestKey, kSecretEarlyTestKey };
        return { kPublicEphemeralEarlyTestKey, kSecretEphemeralEarlyTestKey };
    }
}

bool RakPeerCrypto::initServer(const std::array<std::uint8_t, 32>& publicEarlyKey, const std::array<std::uint8_t, 32>& secretEarlyKey)
{
    isServer = true;
    if (!initCommon())
    {
        resetKeyExchangeKeys(true);
        return false;
    }

    keyExchangeKeys->publicEarlyKey = publicEarlyKey;
    keyExchangeKeys->secretEarlyKey = secretEarlyKey;
    return true;
}

bool RakPeerCrypto::serverInitEarlySessionKeys(const std::array<std::uint8_t, 32>& peerPublicKey)
{
    if (isError || !isServer || !keyExchangeKeys)
    {
        return false;
    }
    
    if (!crypto_kx_server_session_keys(
            keyExchangeKeys->earlySessionKeyClientToServer.data(), 
            keyExchangeKeys->earlySessionKeyServerToClient.data(), 
            keyExchangeKeys->publicEarlyKey.data(), 
            keyExchangeKeys->secretEarlyKey.data(), 
            peerPublicKey.data()
        ))
    {
        resetKeyExchangeKeys(true);
        return false;
    }

    isEarlySessionReady = true;
    keyExchangeKeys->peerPublicEphemeralKey = peerPublicKey;
    return true;
}

bool RBX::Security::RakPeerCrypto::earlyDecryptData(RakNet::BitStream& bitStream, std::size_t aadSize)
{
    auto dataSize = bitStream.GetNumberOfBytesUsed();
    if (dataSize < aadSize + 28)
    {
        return false;
    }
    bitStream.AssertCopyData();
    if (!SessionCrypto::earlyDecryptData(std::span(bitStream.GetData(), dataSize - 28), std::span(bitStream.GetData(), dataSize), aadSize))
    {
        return false;
    }
    bitStream.SetWriteOffset(BYTES_TO_BITS(dataSize - 28));
    return true;
}
