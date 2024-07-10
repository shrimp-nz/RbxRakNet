// ProxyTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <print>
#include <chrono>
#include <thread>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <RakPeer.h>
#include <RakNetStatistics.h>
#include <RakNetTypes.h>
#include <BitStream.h>
#include <RakSleep.h>
#include <PacketLogger.h>

#pragma comment (lib, "Ws2_32.lib")

int main()
{
    auto max_clients = 128;
    auto server = std::make_shared<RakNet::RakPeer>();
    RakNet::SocketDescriptor sock_desc{ 6942, nullptr };
    auto res = server->Startup(max_clients, &sock_desc, 1);
    if (res != RakNet::RAKNET_STARTED) {
        std::println("failed to start server on port {}", sock_desc.port);
        return 1;
    }
    RakNet::SystemAddress address = server->GetMyBoundAddress();
    std::println("started server {}", address.ToString());
    server->SetMaximumIncomingConnections(max_clients);

    while (true)
    {
        while (true)
        {
            RakNet::Packet* packet = server->Receive();
            if (!packet)
                break;
            std::println("server received packet");
            server->DeallocatePacket(packet);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}