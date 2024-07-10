// \file
//
// This file is part of RakNet Copyright 2003 Jenkins Software LLC
//
// Usage of RakNet is subject to the appropriate license agreement.


#define CAT_NEUTER_EXPORT /* Neuter dllimport for libcat */

#include "RakNetDefines.h"
#include "RakPeer.h"
#include "RakNetTypes.h"

// #if defined(new)
// #pragma push_macro("new")
// #undef new
// #define RMO_NEW_UNDEF_ALLOCATING_QUEUE
// #endif

#include <time.h>
#include <ctype.h> // toupper
#include <string.h>
#include "GetTime.h"
#include "MessageIdentifiers.h"
#include "DS_HuffmanEncodingTree.h"
#include "Rand.h"
#include "StringCompressor.h"
#include "StringTable.h"
#include "RakNetTypes.h"
#include "RakSleep.h"
#include "RakAssert.h"
#include "RakNetVersion.h"
#include "gettimeofday.h"
#include "SignaledEvent.h"
#include "SuperFastHash.h"
#include "RakAlloca.h"
#include "WSAStartupSingleton.h"

#ifdef USE_THREADED_SEND
#include "SendToThread.h"
#endif

#ifdef CAT_AUDIT
#define CAT_AUDIT_PRINTF(...) printf(__VA_ARGS__)
#else
#define CAT_AUDIT_PRINTF(...)
#endif

namespace RakNet
{
RAK_THREAD_DECLARATION(UpdateNetworkLoop);
RAK_THREAD_DECLARATION(RecvFromLoop);
RAK_THREAD_DECLARATION(UDTConnect);
}
#define REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE 8

#if !defined ( __APPLE__ ) && !defined ( __APPLE_CC__ )
#include <stdlib.h> // malloc
#endif
#include <bitset>



#if   defined(_WIN32)
//
#else
/*
#include <alloca.h> // Console 2
#include <stdlib.h>
extern bool _extern_Console2LoadModules(void);
extern int _extern_Console2GetConnectionStatus(void);
extern int _extern_Console2GetLobbyStatus(void);
//extern bool Console2StartupFluff(unsigned int *);
extern void Console2ShutdownFluff(void);
//extern unsigned int Console2ActivateConnection(unsigned int, void *);
//extern bool Console2BlockOnEstablished(void);
extern void Console2GetIPAndPort(unsigned int, char *, unsigned short *, unsigned int );
//extern void Console2DeactivateConnection(unsigned int, unsigned int);
*/
#endif


static const int NUM_MTU_SIZES=3;



static const int mtuSizes[NUM_MTU_SIZES]={MAXIMUM_MTU_SIZE, 1200, 576};


// Note to self - if I change this it might affect RECIPIENT_OFFLINE_MESSAGE_INTERVAL in Natpunchthrough.cpp
//static const int MAX_OPEN_CONNECTION_REQUESTS=8;
//static const int TIME_BETWEEN_OPEN_CONNECTION_REQUESTS=500;

#ifdef _MSC_VER
#pragma warning( push )
#endif

using namespace RakNet;

static RakNetRandom rnr;

struct RakPeerAndIndex
{
	SOCKET s;
	unsigned short remotePortRakNetWasStartedOn_PS3;
	RakPeer *rakPeer;
	unsigned int extraSocketOptions;
};

static const unsigned int MAX_OFFLINE_DATA_LENGTH=400; // I set this because I limit ID_CONNECTION_REQUEST to 512 bytes, and the password is appended to that packet.

// Used to distinguish between offline messages with data, and messages from the reliability layer
// Should be different than any message that could result from messages from the reliability layer
#if   !defined(__GNUC__)
#pragma warning(disable:4309) // 'initializing' : truncation of constant value
#endif
// Make sure highest bit is 0, so isValid in DatagramHeaderFormat is false
static const char OFFLINE_MESSAGE_DATA_ID[16]={0x00,0xFF,0xFF,0x00,0xFE,0xFE,0xFE,0xFE,0xFD,0xFD,0xFD,0xFD,0x12,0x34,0x56,0x78};

struct PacketFollowedByData
{
	Packet p;
	unsigned char data[1];
};

Packet *RakPeer::AllocPacket(unsigned dataSize, const char *file, unsigned int line)
{
	// Crashes when dataSize is 4 bytes - not sure why
// 	unsigned char *data = (unsigned char *) rakMalloc_Ex(sizeof(PacketFollowedByData)+dataSize, file, line);
// 	Packet *p = &((PacketFollowedByData *)data)->p;
// 	p->data=((PacketFollowedByData *)data)->data;
// 	p->length=dataSize;
// 	p->bitSize=BYTES_TO_BITS(dataSize);
// 	p->deleteData=false;
// 	p->guid=UNASSIGNED_RAKNET_GUID;
// 	return p;

	RakNet::Packet *p;
	packetAllocationPoolMutex.Lock();
	p = packetAllocationPool.Allocate(file,line);
	packetAllocationPoolMutex.Unlock();
	p = new ((void*)p) Packet;
	p->data=(unsigned char*) rakMalloc_Ex(dataSize,file,line);
	p->length=dataSize;
	p->bitSize=BYTES_TO_BITS(dataSize);
	p->deleteData=true;
	p->guid=UNASSIGNED_RAKNET_GUID;
	p->wasGeneratedLocally=false;
	return p;
}

Packet *RakPeer::AllocPacket(unsigned dataSize, unsigned char *data, const char *file, unsigned int line)
{
	// Packet *p = (Packet *)rakMalloc_Ex(sizeof(Packet), file, line);
	RakNet::Packet *p;
	packetAllocationPoolMutex.Lock();
	p = packetAllocationPool.Allocate(file,line);
	packetAllocationPoolMutex.Unlock();
	p = new ((void*)p) Packet;
	RakAssert(p);
	p->data=data;
	p->length=dataSize;
	p->bitSize=BYTES_TO_BITS(dataSize);
	p->deleteData=true;
	p->guid=UNASSIGNED_RAKNET_GUID;
	p->wasGeneratedLocally=false;
	return p;
}

STATIC_FACTORY_DEFINITIONS(RakPeerInterface,RakPeer) 

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Constructor
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RakPeer()
{
	StringCompressor::AddReference();
	RakNet::StringTable::AddReference();
	WSAStartupSingleton::AddRef();

	defaultMTUSize = mtuSizes[NUM_MTU_SIZES-1];
	trackFrequencyTable = false;
	maximumIncomingConnections = 0;
	maximumNumberOfPeers = 0;
	//remoteSystemListSize=0;
	remoteSystemList = 0;
	activeSystemList = 0;
	activeSystemListSize=0;
	remoteSystemLookup=0;
	bytesSentPerSecond = bytesReceivedPerSecond = 0;
	endThreads = true;
	isMainLoopThreadActive = false;
	startingActiveSystemListIndex = 0;


	// isRecvfromThreadActive=false;
#if defined(GET_TIME_SPIKE_LIMIT) && GET_TIME_SPIKE_LIMIT>0
	occasionalPing = true;
#else
	occasionalPing = false;
#endif
	allowInternalRouting=false;
	for (unsigned int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
		ipList[i]=UNASSIGNED_SYSTEM_ADDRESS;
	allowConnectionResponseIPMigration = false;
	//incomingPasswordLength=outgoingPasswordLength=0;
	incomingPasswordLength=0;
	splitMessageProgressInterval=0;
	//unreliableTimeout=0;
	unreliableTimeout=1000;
	maxOutgoingBPS=0;
	firstExternalID=UNASSIGNED_SYSTEM_ADDRESS;
	myGuid=UNASSIGNED_RAKNET_GUID;
	userUpdateThreadPtr=0;
	userUpdateThreadData=0;

#ifdef _DEBUG
	// Wait longer to disconnect in debug so I don't get disconnected while tracing
	defaultTimeoutTime=30000;
#else
	defaultTimeoutTime=10000;
#endif

#ifdef _DEBUG
	_packetloss=0.0;
	_minExtraPing=0;
	_extraPingVariance=0;
#endif

	bufferedCommands.SetPageSize(sizeof(BufferedCommandStruct)*16);
	socketQueryOutput.SetPageSize(sizeof(SocketQueryOutput)*8);
	bufferedPackets.SetPageSize(sizeof(RecvFromStruct)*BUFFERED_PACKETS_PAGE_SIZE); // This is big, keep the size down

	packetAllocationPoolMutex.Lock();
	packetAllocationPool.SetPageSize(sizeof(DataStructures::MemoryPool<Packet>::MemoryWithPage)*32);
	packetAllocationPoolMutex.Unlock();

	remoteSystemIndexPool.SetPageSize(sizeof(DataStructures::MemoryPool<RemoteSystemIndex>::MemoryWithPage)*32);

	GenerateGUID();

	quitAndDataEvents.InitEvent();
	limitConnectionFrequencyFromTheSameIP=false;
	ResetSendReceipt();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Destructor
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::~RakPeer()
{
	Shutdown( 0, 0 );

	// Free the ban list.
	ClearBanList();

	StringCompressor::RemoveReference();
	RakNet::StringTable::RemoveReference();
	WSAStartupSingleton::Deref();

	quitAndDataEvents.CloseEvent();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// \brief Starts the network threads, opens the listen port.
// You must call this before calling Connect().
// Multiple calls while already active are ignored.  To call this function again with different settings, you must first call Shutdown().
// \note Call SetMaximumIncomingConnections if you want to accept incoming connections
// \param[in] maxConnections The maximum number of connections between this instance of RakPeer and another instance of RakPeer. Required so the network can preallocate and for thread safety. A pure client would set this to 1.  A pure server would set it to the number of allowed clients.- A hybrid would set it to the sum of both types of connections
// \param[in] localPort The port to listen for connections on.
// \param[in] _threadSleepTimer How many ms to Sleep each internal update cycle. With new congestion control, the best results will be obtained by passing 10.
// \param[in] socketDescriptors An array of SocketDescriptor structures to force RakNet to listen on a particular IP address or port (or both).  Each SocketDescriptor will represent one unique socket.  Do not pass redundant structures.  To listen on a specific port, you can pass &socketDescriptor, 1SocketDescriptor(myPort,0); such as for a server.  For a client, it is usually OK to just pass SocketDescriptor();
// \param[in] socketDescriptorCount The size of the \a socketDescriptors array.  Pass 1 if you are not sure what to pass.
// \return False on failure (can't create socket or thread), true on success.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
StartupResult RakPeer::Startup( unsigned short maxConnections, SocketDescriptor *socketDescriptors, unsigned socketDescriptorCount, int threadPriority )
{
	if (IsActive())
		return RAKNET_ALREADY_STARTED;

	if (threadPriority==-99999)
	{


#if   defined(_WIN32)
		threadPriority=0;


#else
		threadPriority=1000;
#endif
	}


	// Fill out ipList structure
	unsigned int i;

	SocketLayer::GetMyIP( ipList );
// 	for (i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
// 	{
// 		if (ipList[i]!=UNASSIGNED_SYSTEM_ADDRESS)
// 		{
// 			char str[128];
// 			ipList[i].ToString(false,str);
// 			printf("%s\n",str);
// 		}
// 	}


	if (myGuid==UNASSIGNED_RAKNET_GUID)
	{
		rnr.SeedMT( GenerateSeedFromGuid() );
	}

	RakPeerAndIndex rpai[32];
	RakAssert(socketDescriptorCount<32);

	RakAssert(socketDescriptors && socketDescriptorCount>=1);

	if (socketDescriptors==0 || socketDescriptorCount<1)
		return INVALID_SOCKET_DESCRIPTORS;

	RakAssert( maxConnections > 0 );

	if ( maxConnections <= 0 )
		return INVALID_MAX_CONNECTIONS;

	DerefAllSockets();

	// Go through all socket descriptors and precreate sockets on the specified addresses
	for (i=0; i<socketDescriptorCount; i++)
	{
		const char *addrToBind;
		if (socketDescriptors[i].hostAddress[0]==0)
			addrToBind=0;
		else
			addrToBind=socketDescriptors[i].hostAddress;

#if RAKNET_SUPPORT_IPV6==1
		if (SocketLayer::IsSocketFamilySupported(addrToBind, socketDescriptors[i].socketFamily)==false)
			return SOCKET_FAMILY_NOT_SUPPORTED;
#endif

		if (socketDescriptors[i].port!=0 && SocketLayer::IsPortInUse(socketDescriptors[i].port, addrToBind, socketDescriptors[i].socketFamily)==true)
		{
			DerefAllSockets();
			return SOCKET_PORT_ALREADY_IN_USE;
		}

		RakNetSmartPtr<RakNetSocket> rns(RakNet::OP_NEW<RakNetSocket>(_FILE_AND_LINE_));
		if (socketDescriptors[i].remotePortRakNetWasStartedOn_PS3_PSP2==0)
		{
			rns->s = (unsigned int) SocketLayer::CreateBoundSocket( socketDescriptors[i].port, true, addrToBind, 100, socketDescriptors[i].extraSocketOptions, socketDescriptors[i].socketFamily );
		}

		if ((SOCKET)rns->s==(SOCKET)-1)
		{
			DerefAllSockets();
			return SOCKET_FAILED_TO_BIND;
		}

		SocketLayer::GetSystemAddress( rns->s, &rns->boundAddress );

		rns->remotePortRakNetWasStartedOn_PS3_PSP2=socketDescriptors[i].remotePortRakNetWasStartedOn_PS3_PSP2;
		rns->extraSocketOptions=socketDescriptors[i].extraSocketOptions;
		rns->userConnectionSocketIndex=i;

#if RAKNET_SUPPORT_IPV6==0
		if (addrToBind==0)
			rns->boundAddress.SetToLoopback(4);
#endif

		int zero=0;
		if (SocketLayer::SendTo((SOCKET)rns->s, (const char*) &zero,4,rns->boundAddress, rns->remotePortRakNetWasStartedOn_PS3_PSP2, rns->extraSocketOptions, _FILE_AND_LINE_)!=0)
		{
			DerefAllSockets();
			return SOCKET_FAILED_TEST_SEND;
		}

		socketList.Push(rns, _FILE_AND_LINE_ );

	}


	if ( maximumNumberOfPeers == 0 )
	{
		// Don't allow more incoming connections than we have peers.
		if ( maximumIncomingConnections > maxConnections )
			maximumIncomingConnections = maxConnections;

		maximumNumberOfPeers = maxConnections;
		// 04/19/2006 - Don't overallocate because I'm no longer allowing connected pings.
		// The disconnects are not consistently processed and the process was sloppy and complicated.
		// Allocate 10% extra to handle new connections from players trying to connect when the server is full
		//remoteSystemListSize = maxConnections;// * 11 / 10 + 1;

		// remoteSystemList in Single thread
		//remoteSystemList = RakNet::OP_NEW<RemoteSystemStruct[ remoteSystemListSize ]>( _FILE_AND_LINE_ );
		remoteSystemList = RakNet::OP_NEW_ARRAY<RemoteSystemStruct>(maximumNumberOfPeers, _FILE_AND_LINE_ );

		remoteSystemLookup = RakNet::OP_NEW_ARRAY<RemoteSystemIndex*>((unsigned int) maximumNumberOfPeers * REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE, _FILE_AND_LINE_ );

		activeSystemList = RakNet::OP_NEW_ARRAY<RemoteSystemStruct*>(maximumNumberOfPeers, _FILE_AND_LINE_ );

		for ( i = 0; i < maximumNumberOfPeers; i++ )
		//for ( i = 0; i < remoteSystemListSize; i++ )
		{
			// remoteSystemList in Single thread
			remoteSystemList[ i ].isActive = false;
			remoteSystemList[ i ].systemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystemList[ i ].guid = UNASSIGNED_RAKNET_GUID;
			remoteSystemList[ i ].myExternalSystemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystemList[ i ].connectMode=RemoteSystemStruct::NO_ACTION;
			remoteSystemList[ i ].MTUSize = defaultMTUSize;
			remoteSystemList[ i ].remoteSystemIndex = (SystemIndex) i;
#ifdef _DEBUG
			remoteSystemList[ i ].reliabilityLayer.ApplyNetworkSimulator(_packetloss, _minExtraPing, _extraPingVariance);
#endif

			// All entries in activeSystemList have valid pointers all the time.
			activeSystemList[ i ] = &remoteSystemList[ i ];
		}

		for (unsigned int i=0; i < (unsigned int) maximumNumberOfPeers*REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE; i++)
		{
			remoteSystemLookup[i]=0;
		}
	}

	// For histogram statistics
	// nextReadBytesTime=0;
	// lastSentBytes=lastReceivedBytes=0;

	if ( endThreads )
	{
		updateCycleIsRunning = false;
		endThreads = false;

		ClearBufferedCommands();
		ClearBufferedPackets();
		ClearSocketQueryOutput();

		if ( isMainLoopThreadActive == false )
		{
			int errorCode = RakNet::RakThread::Create(UpdateNetworkLoop, this, threadPriority);
			if ( errorCode != 0 )
			{
				Shutdown( 0, 0 );
				return FAILED_TO_CREATE_NETWORK_THREAD;
			}

			RakAssert(isRecvFromLoopThreadActive.GetValue()==0);
			for (i=0; i<socketDescriptorCount; i++)
			{
				rpai[i].remotePortRakNetWasStartedOn_PS3=socketDescriptors[i].remotePortRakNetWasStartedOn_PS3_PSP2;
				rpai[i].extraSocketOptions=socketDescriptors[i].extraSocketOptions;
				rpai[i].s=socketList[i]->s;
				rpai[i].rakPeer=this;

				errorCode = RakNet::RakThread::Create(RecvFromLoop, &rpai[i], threadPriority);
				if ( errorCode != 0 )
				{
					Shutdown( 0, 0 );
					return FAILED_TO_CREATE_NETWORK_THREAD;
				}
			}

			while ( isRecvFromLoopThreadActive.GetValue() < (uint32_t) socketDescriptorCount )
				RakSleep(10);
		}

		// Wait for the threads to activate.  When they are active they will set these variables to true
		while (  isMainLoopThreadActive == false )
			RakSleep(10);

	}

#ifdef USE_THREADED_SEND
	RakNet::SendToThread::AddRef();
#endif

	return RAKNET_STARTED;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::AddToSecurityExceptionList(const char *ip)
{
	securityExceptionMutex.Lock();
	securityExceptionList.Insert(RakString(ip), _FILE_AND_LINE_);
	securityExceptionMutex.Unlock();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::RemoveFromSecurityExceptionList(const char *ip)
{
	if (securityExceptionList.Size()==0)
		return;

	if (ip==0)
	{
		securityExceptionMutex.Lock();
		securityExceptionList.Clear(false, _FILE_AND_LINE_);
		securityExceptionMutex.Unlock();
	}
	else
	{
		unsigned i=0;
		securityExceptionMutex.Lock();
		while (i < securityExceptionList.Size())
		{
			if (securityExceptionList[i].IPAddressMatch(ip))
			{
				securityExceptionList[i]=securityExceptionList[securityExceptionList.Size()-1];
				securityExceptionList.RemoveAtIndex(securityExceptionList.Size()-1);
			}
			else
				i++;
		}
		securityExceptionMutex.Unlock();
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::IsInSecurityExceptionList(const char *ip)
{
	if (securityExceptionList.Size()==0)
		return false;

	unsigned i=0;
	securityExceptionMutex.Lock();
	for (; i < securityExceptionList.Size(); i++)
	{
		if (securityExceptionList[i].IPAddressMatch(ip))
		{
			securityExceptionMutex.Unlock();
			return true;
		}
	}
	securityExceptionMutex.Unlock();
	return false;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sets how many incoming connections are allowed.  If this is less than the number of players currently connected, no
// more players will be allowed to connect.  If this is greater than the maximum number of peers allowed, it will be reduced
// to the maximum number of peers allowed.  Defaults to 0.
//
// Parameters:
// numberAllowed - Maximum number of incoming connections allowed.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetMaximumIncomingConnections( unsigned short numberAllowed )
{
	maximumIncomingConnections = numberAllowed;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the maximum number of incoming connections, which is always <= maxConnections
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned short RakPeer::GetMaximumIncomingConnections( void ) const
{
	return maximumIncomingConnections;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns how many open connections there are at this time
// \return the number of open connections
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned short RakPeer::NumberOfConnections(void) const
{
	DataStructures::List<SystemAddress> addresses;
	DataStructures::List<RakNetGUID> guids;
	GetSystemList(addresses, guids);
	return (unsigned short) addresses.Size();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sets the password incoming connections must match in the call to Connect (defaults to none)
// Pass 0 to passwordData to specify no password
//
// Parameters:
// passwordData: A data block that incoming connections must match.  This can be just a password, or can be a stream of data.
// - Specify 0 for no password data
// passwordDataLength: The length in bytes of passwordData
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetIncomingPassword( const char* passwordData, int passwordDataLength )
{
	//if (passwordDataLength > MAX_OFFLINE_DATA_LENGTH)
	//	passwordDataLength=MAX_OFFLINE_DATA_LENGTH;

	if (passwordDataLength > 255)
		passwordDataLength=255;

	if (passwordData==0)
		passwordDataLength=0;

	// Not threadsafe but it's not important enough to lock.  Who is going to change the password a lot during runtime?
	// It won't overflow at least because incomingPasswordLength is an unsigned char
	if (passwordDataLength>0)
		memcpy(incomingPassword, passwordData, passwordDataLength);
	incomingPasswordLength=(unsigned char)passwordDataLength;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::GetIncomingPassword( char* passwordData, int *passwordDataLength  )
{
	if (passwordData==0)
	{
		*passwordDataLength=incomingPasswordLength;
		return;
	}

	if (*passwordDataLength > incomingPasswordLength)
		*passwordDataLength=incomingPasswordLength;

	if (*passwordDataLength>0)
		memcpy(passwordData, incomingPassword, *passwordDataLength);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Call this to connect to the specified host (ip or domain name) and server port.
// Calling Connect and not calling SetMaximumIncomingConnections acts as a dedicated client.  Calling both acts as a true peer.
// This is a non-blocking connection.  You know the connection is successful when IsConnected() returns true
// or receive gets a packet with the type identifier ID_CONNECTION_REQUEST_ACCEPTED.  If the connection is not
// successful, such as rejected connection or no response then neither of these things will happen.
// Requires that you first call Initialize
//
// Parameters:
// host: Either a dotted IP address or a domain name
// remotePort: Which port to connect to on the remote machine.
// passwordData: A data block that must match the data block on the server.  This can be just a password, or can be a stream of data
// passwordDataLength: The length in bytes of passwordData
//
// Returns:
// True on successful initiation. False on incorrect parameters, internal error, or too many existing peers
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ConnectionAttemptResult RakPeer::Connect( const char* host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime )
{
	// If endThreads is true here you didn't call Startup() first.
	if ( host == 0 || endThreads || connectionSocketIndex>=socketList.Size() )
		return INVALID_PARAMETER;

	RakAssert(remotePort!=0);

	connectionSocketIndex=GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);

	if (passwordDataLength>255)
		passwordDataLength=255;

	if (passwordData==0)
		passwordDataLength=0;

	// Not threadsafe but it's not important enough to lock.  Who is going to change the password a lot during runtime?
	// It won't overflow at least because outgoingPasswordLength is an unsigned char
//	if (passwordDataLength>0)
//		memcpy(outgoingPassword, passwordData, passwordDataLength);
//	outgoingPasswordLength=(unsigned char) passwordDataLength;

	// 04/02/09 - Can't remember why I disabled connecting to self, but it seems to work
	// Connecting to ourselves in the same instance of the program?
//	if ( ( strcmp( host, "127.0.0.1" ) == 0 || strcmp( host, "0.0.0.0" ) == 0 ) && remotePort == mySystemAddress[0].port )
//		return false;

	return SendConnectionRequest( host, remotePort, passwordData, passwordDataLength, publicKey, connectionSocketIndex, 0, sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

ConnectionAttemptResult RakPeer::ConnectWithSocket(const char* host, unsigned short remotePort, const char *passwordData, int passwordDataLength, RakNetSmartPtr<RakNetSocket> socket, PublicKey *publicKey, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime)
{
	if ( host == 0 || endThreads || socket.IsNull() )
		return INVALID_PARAMETER;

	if (passwordDataLength>255)
		passwordDataLength=255;

	if (passwordData==0)
		passwordDataLength=0;

		return SendConnectionRequest( host, remotePort, passwordData, passwordDataLength, publicKey, 0, 0, sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime, socket );

}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Stops the network threads and close all connections.  Multiple calls are ok.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::Shutdown( unsigned int blockDuration, unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority )
{
	unsigned i,j;
	bool anyActive;
	RakNet::TimeMS startWaitingTime;
//	SystemAddress systemAddress;
	RakNet::TimeMS time;
	//unsigned short systemListSize = remoteSystemListSize; // This is done for threading reasons
	unsigned short systemListSize = maximumNumberOfPeers;

	if ( blockDuration > 0 )
	{
		for ( i = 0; i < systemListSize; i++ )
		{
			// remoteSystemList in user thread
			if (remoteSystemList[i].isActive)
				NotifyAndFlagForShutdown(remoteSystemList[i].systemAddress, false, orderingChannel, disconnectionNotificationPriority);
		}

		time = RakNet::GetTimeMS();
		startWaitingTime = time;
		while ( time - startWaitingTime < blockDuration )
		{
			anyActive=false;
			for (j=0; j < systemListSize; j++)
			{
				// remoteSystemList in user thread
				if (remoteSystemList[j].isActive)
				{
					anyActive=true;
					break;
				}
			}

			// If this system is out of packets to send, then stop waiting
			if ( anyActive==false )
				break;

			// This will probably cause the update thread to run which will probably
			// send the disconnection notification

			RakSleep(15);
			time = RakNet::GetTimeMS();
		}
	}

	activeSystemListSize=0;

	quitAndDataEvents.SetEvent();

	endThreads = true;

	// Get recvfrom to unblock
	for (i=0; i < socketList.Size(); i++)
	{
		SystemAddress sa2 = socketList[i]->boundAddress;
		if (SocketLayer::SendTo(socketList[i]->s, (const char*) &i,1,sa2, socketList[i]->remotePortRakNetWasStartedOn_PS3_PSP2, socketList[i]->extraSocketOptions, _FILE_AND_LINE_)!=0)
			break;
	}
	while ( isMainLoopThreadActive )
	{
		endThreads = true;
		RakSleep(15);
	}

	RakNet::TimeMS timeout = RakNet::GetTimeMS()+1000;
	while ( isRecvFromLoopThreadActive.GetValue()>0 && RakNet::GetTimeMS()<timeout )
	{
		// Get recvfrom to unblock
		for (i=0; i < socketList.Size(); i++)
		{
			SystemAddress sa2 = socketList[i]->boundAddress;
			SocketLayer::SendTo(socketList[i]->s, (const char*) &i,1,sa2, socketList[i]->remotePortRakNetWasStartedOn_PS3_PSP2, socketList[i]->extraSocketOptions, _FILE_AND_LINE_);
		}

		RakSleep(30);
	}

//	char c=0;
//	unsigned int socketIndex;
	// remoteSystemList in Single thread
	for ( i = 0; i < systemListSize; i++ )
	{
		// Reserve this reliability layer for ourselves
		remoteSystemList[ i ].isActive = false;

		// Remove any remaining packets
		remoteSystemList[ i ].reliabilityLayer.Reset(false, remoteSystemList[ i ].MTUSize, false);
		remoteSystemList[ i ].rakNetSocket.SetNull();

	}


	// Setting maximumNumberOfPeers to 0 allows remoteSystemList to be reallocated in Initialize.
	// Setting remoteSystemListSize prevents threads from accessing the reliability layer
	maximumNumberOfPeers = 0;
	//remoteSystemListSize = 0;

	// Free any packets the user didn't deallocate
	packetReturnMutex.Lock();
	for (i=0; i < packetReturnQueue.Size(); i++)
		DeallocatePacket(packetReturnQueue[i]);
	packetReturnQueue.Clear(_FILE_AND_LINE_);
	packetReturnMutex.Unlock();
	packetAllocationPoolMutex.Lock();
	packetAllocationPool.Clear(_FILE_AND_LINE_);
	packetAllocationPoolMutex.Unlock();

	if (isRecvFromLoopThreadActive.GetValue()>0)
	{
		timeout = RakNet::GetTimeMS()+1000;
		while ( isRecvFromLoopThreadActive.GetValue()>0 && RakNet::GetTimeMS()<timeout )
		{
			RakSleep(30);
		}
	}

	DerefAllSockets();

	ClearBufferedCommands();
	ClearBufferedPackets();
	ClearSocketQueryOutput();
	bytesSentPerSecond = bytesReceivedPerSecond = 0;

	ClearRequestedConnectionList();

	// Clear out the reliability layer list in case we want to reallocate it in a successive call to Init.
	RemoteSystemStruct * temp = remoteSystemList;
	remoteSystemList = 0;
	RakNet::OP_DELETE_ARRAY(temp, _FILE_AND_LINE_);
	RakNet::OP_DELETE_ARRAY(activeSystemList, _FILE_AND_LINE_);
	activeSystemList=0;

	ClearRemoteSystemLookup();

#ifdef USE_THREADED_SEND
	RakNet::SendToThread::Deref();
#endif

	ResetSendReceipt();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns true if the network threads are running
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
inline bool RakPeer::IsActive( void ) const
{
	return endThreads == false;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Fills the array remoteSystems with the systemAddress of all the systems we are connected to
//
// Parameters:
// remoteSystems (out): An array of SystemAddress structures to be filled with the SystemAddresss of the systems we are connected to
// - pass 0 to remoteSystems to only get the number of systems we are connected to
// numberOfSystems (int, out): As input, the size of remoteSystems array.  As output, the number of elements put into the array
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::GetConnectionList( SystemAddress *remoteSystems, unsigned short *numberOfSystems ) const
{
	if (numberOfSystems==0)
		return false;

	if ( remoteSystemList == 0 || endThreads == true )
	{
		if (numberOfSystems)
			*numberOfSystems=0;
		return false;
	}

	DataStructures::List<SystemAddress> addresses;
	DataStructures::List<RakNetGUID> guids;
	GetSystemList(addresses, guids);
	if (remoteSystems)
	{
		unsigned short i;
		for (i=0; i < *numberOfSystems && i < addresses.Size(); i++)
			remoteSystems[i]=addresses[i];
		*numberOfSystems=i;
	}
	else
	{
		*numberOfSystems=(unsigned short) addresses.Size();
	}
	return true;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
uint32_t RakPeer::GetNextSendReceipt(void)
{
	sendReceiptSerialMutex.Lock();
	uint32_t retVal = sendReceiptSerial;
	sendReceiptSerialMutex.Unlock();
	return retVal;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
uint32_t RakPeer::IncrementNextSendReceipt(void)
{
	sendReceiptSerialMutex.Lock();
	uint32_t returned = sendReceiptSerial;
	if (++sendReceiptSerial==0)
		sendReceiptSerial=1;
	sendReceiptSerialMutex.Unlock();
	return returned;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sends a block of data to the specified system that you are connected to.
// This function only works while the client is connected (Use the Connect function).
// The first byte should be a message identifier starting at ID_USER_PACKET_ENUM
//
// Parameters:
// data: The block of data to send
// length: The size in bytes of the data to send
// bitStream: The bitstream to send
// priority: What priority level to send on.
// reliability: How reliability to send this data
// orderingChannel: When using ordered or sequenced packets, what channel to order these on.
// - Packets are only ordered relative to other packets on the same stream
// systemAddress: Who to send this packet to, or in the case of broadcasting who not to send it to. Use UNASSIGNED_SYSTEM_ADDRESS to specify none
// broadcast: True to send this packet to all connected systems.  If true, then systemAddress specifies who not to send the packet to.
// Returns:
// \return 0 on bad input. Otherwise a number that identifies this message. If \a reliability is a type that returns a receipt, on a later call to Receive() you will get ID_SND_RECEIPT_ACKED or ID_SND_RECEIPT_LOSS with bytes 1-4 inclusive containing this number
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
uint32_t RakPeer::Send( const char *data, const int length, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, uint32_t forceReceiptNumber )
{
#ifdef _DEBUG
	RakAssert( data && length > 0 );
#endif
	RakAssert( !( reliability >= NUMBER_OF_RELIABILITIES || reliability < 0 ) );
	RakAssert( !( priority > NUMBER_OF_PRIORITIES || priority < 0 ) );
	RakAssert( !( orderingChannel >= NUMBER_OF_ORDERED_STREAMS ) );

	if ( data == 0 || length < 0 )
		return 0;

	if ( remoteSystemList == 0 || endThreads == true )
		return 0;

	if ( broadcast == false && systemIdentifier.IsUndefined())
		return 0;

	uint32_t usedSendReceipt;
	if (forceReceiptNumber!=0)
		usedSendReceipt=forceReceiptNumber;
	else
		usedSendReceipt=IncrementNextSendReceipt();

	if (broadcast==false && IsLoopbackAddress(systemIdentifier,true))
	{
		SendLoopback(data,length);

		if (reliability>=UNRELIABLE_WITH_ACK_RECEIPT)
		{
			char buff[5];
			buff[0]=ID_SND_RECEIPT_ACKED;
			sendReceiptSerialMutex.Lock();
			memcpy(buff+1, &sendReceiptSerial, 4);
			sendReceiptSerialMutex.Unlock();
			SendLoopback( buff, 5 );
		}

		return usedSendReceipt;
	}

	SendBuffered(data, length*8, priority, reliability, orderingChannel, systemIdentifier, broadcast, RemoteSystemStruct::NO_ACTION, usedSendReceipt);

	return usedSendReceipt;
}

void RakPeer::SendLoopback( const char *data, const int length )
{
	if ( data == 0 || length < 0 )
		return;

	Packet *packet = AllocPacket(length, _FILE_AND_LINE_);
	memcpy(packet->data, data, length);
	packet->systemAddress = GetLoopbackAddress();
	packet->guid=myGuid;
	PushBackPacket(packet, false);
}

uint32_t RakPeer::Send( const RakNet::BitStream * bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, uint32_t forceReceiptNumber )
{
#ifdef _DEBUG
	RakAssert( bitStream->GetNumberOfBytesUsed() > 0 );
#endif

	RakAssert( !( reliability >= NUMBER_OF_RELIABILITIES || reliability < 0 ) );
	RakAssert( !( priority > NUMBER_OF_PRIORITIES || priority < 0 ) );
	RakAssert( !( orderingChannel >= NUMBER_OF_ORDERED_STREAMS ) );

	if ( bitStream->GetNumberOfBytesUsed() == 0 )
		return 0;

	if ( remoteSystemList == 0 || endThreads == true )
		return 0;

	if ( broadcast == false && systemIdentifier.IsUndefined() )
		return 0;

	uint32_t usedSendReceipt;
	if (forceReceiptNumber!=0)
		usedSendReceipt=forceReceiptNumber;
	else
		usedSendReceipt=IncrementNextSendReceipt();

	if (broadcast==false && IsLoopbackAddress(systemIdentifier,true))
	{
		SendLoopback((const char*) bitStream->GetData(),bitStream->GetNumberOfBytesUsed());
		if (reliability>=UNRELIABLE_WITH_ACK_RECEIPT)
		{
			char buff[5];
			buff[0]=ID_SND_RECEIPT_ACKED;
			sendReceiptSerialMutex.Lock();
			memcpy(buff+1, &sendReceiptSerial,4);
			sendReceiptSerialMutex.Unlock();
			SendLoopback( buff, 5 );
		}
		return usedSendReceipt;
	}

	// Sends need to be buffered and processed in the update thread because the systemAddress associated with the reliability layer can change,
	// from that thread, resulting in a send to the wrong player!  While I could mutex the systemAddress, that is much slower than doing this
	SendBuffered((const char*)bitStream->GetData(), bitStream->GetNumberOfBitsUsed(), priority, reliability, orderingChannel, systemIdentifier, broadcast, RemoteSystemStruct::NO_ACTION, usedSendReceipt);


	return usedSendReceipt;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Sends multiple blocks of data, concatenating them automatically.
//
// This is equivalent to:
// RakNet::BitStream bs;
// bs.WriteAlignedBytes(block1, blockLength1);
// bs.WriteAlignedBytes(block2, blockLength2);
// bs.WriteAlignedBytes(block3, blockLength3);
// Send(&bs, ...)
//
// This function only works while the connected
// \param[in] data An array of pointers to blocks of data
// \param[in] lengths An array of integers indicating the length of each block of data
// \param[in] numParameters Length of the arrays data and lengths
// \param[in] priority What priority level to send on.  See PacketPriority.h
// \param[in] reliability How reliability to send this data.  See PacketPriority.h
// \param[in] orderingChannel When using ordered or sequenced messages, what channel to order these on. Messages are only ordered relative to other messages on the same stream
// \param[in] systemIdentifier Who to send this packet to, or in the case of broadcasting who not to send it to. Pass either a SystemAddress structure or a RakNetGUID structure. Use UNASSIGNED_SYSTEM_ADDRESS or to specify none
// \param[in] broadcast True to send this packet to all connected systems. If true, then systemAddress specifies who not to send the packet to.
// \return False if we are not connected to the specified recipient.  True otherwise
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
uint32_t RakPeer::SendList( const char **data, const int *lengths, const int numParameters, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, uint32_t forceReceiptNumber )
{
#ifdef _DEBUG
	RakAssert( data );
#endif

	if ( data == 0 || lengths == 0 )
		return 0;

	if ( remoteSystemList == 0 || endThreads == true )
		return 0;

	if (numParameters==0)
		return 0;

	if (lengths==0)
		return 0;

	if ( broadcast == false && systemIdentifier.IsUndefined() )
		return 0;

	uint32_t usedSendReceipt;
	if (forceReceiptNumber!=0)
		usedSendReceipt=forceReceiptNumber;
	else
		usedSendReceipt=IncrementNextSendReceipt();

	SendBufferedList(data, lengths, numParameters, priority, reliability, orderingChannel, systemIdentifier, broadcast, RemoteSystemStruct::NO_ACTION, usedSendReceipt);

	return usedSendReceipt;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Gets a packet from the incoming packet queue. Use DeallocatePacket to deallocate the packet after you are done with it.
// Check the Packet struct at the top of CoreNetworkStructures.h for the format of the struct
//
// Returns:
// 0 if no packets are waiting to be handled, otherwise an allocated packet
// If the client is not active this will also return 0, as all waiting packets are flushed when the client is Disconnected
// This also updates all memory blocks associated with synchronized memory and distributed objects
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ifdef _MSC_VER
#pragma warning( disable : 4701 ) // warning C4701: local variable <variable name> may be used without having been initialized
#endif
Packet* RakPeer::Receive( void )
{
	if ( !( IsActive() ) )
		return 0;

	RakNet::Packet *packet;
	int offset;
	do
	{
		packetReturnMutex.Lock();
		if (packetReturnQueue.IsEmpty())
			packet=0;
		else
			packet = packetReturnQueue.Pop();
		packetReturnMutex.Unlock();
		if (packet==0)
			return 0;

		if ( ( packet->length >= sizeof(unsigned char) + sizeof( RakNet::Time ) ) &&
			( (unsigned char) packet->data[ 0 ] == ID_TIMESTAMP ) )
		{
			offset = sizeof(unsigned char);
			ShiftIncomingTimestamp( packet->data + offset, packet->systemAddress );
		}

	} while(packet==0);

#ifdef _DEBUG
	RakAssert( packet->data );
#endif

	return packet;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Call this to deallocate a packet returned by Receive
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::DeallocatePacket( Packet *packet )
{
	if ( packet == 0 )
		return;

	if (packet->deleteData)
	{
		rakFree_Ex(packet->data, _FILE_AND_LINE_ );
		packet->~Packet();
		packetAllocationPoolMutex.Lock();
		packetAllocationPool.Release(packet,_FILE_AND_LINE_);
		packetAllocationPoolMutex.Unlock();
	}
	else
	{
		rakFree_Ex(packet, _FILE_AND_LINE_ );
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Return the total number of connections we are allowed
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned short RakPeer::GetMaximumNumberOfPeers( void ) const
{
	return maximumNumberOfPeers;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Close the connection to another host (if we initiated the connection it will disconnect, if they did it will kick them out).
//
// Parameters:
// target: Which connection to close
// sendDisconnectionNotification: True to send ID_DISCONNECTION_NOTIFICATION to the recipient. False to close it silently.
// channel: If blockDuration > 0, the disconnect packet will be sent on this channel
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::CloseConnection( const AddressOrGUID target, bool sendDisconnectionNotification, unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority )
{
	/*
	// This only be called from the user thread, for the user shutting down.
	// From the network thread, this should occur because of ID_DISCONNECTION_NOTIFICATION and ID_CONNECTION_LOST
	unsigned j;
	for (j=0; j < messageHandlerList.Size(); j++)
	{
		messageHandlerList[j]->OnClosedConnection(
			target.systemAddress==UNASSIGNED_SYSTEM_ADDRESS ? GetSystemAddressFromGuid(target.rakNetGuid) : target.systemAddress,
			target.rakNetGuid==UNASSIGNED_RAKNET_GUID ? GetGuidFromSystemAddress(target.systemAddress) : target.rakNetGuid,
			LCR_CLOSED_BY_USER);
	}
	*/

	CloseConnectionInternal(target, sendDisconnectionNotification, false, orderingChannel, disconnectionNotificationPriority);

	// 12/14/09 Return ID_CONNECTION_LOST when calling CloseConnection with sendDisconnectionNotification==false, elsewise it is never returned
	if (sendDisconnectionNotification==false && GetConnectionState(target)==IS_CONNECTED)
	{
		Packet *packet=AllocPacket(sizeof( char ), _FILE_AND_LINE_);
		packet->data[ 0 ] = ID_CONNECTION_LOST; // DeadConnection
		packet->guid = target.rakNetGuid==UNASSIGNED_RAKNET_GUID ? GetGuidFromSystemAddress(target.systemAddress) : target.rakNetGuid;
		packet->systemAddress = target.systemAddress==UNASSIGNED_SYSTEM_ADDRESS ? GetSystemAddressFromGuid(target.rakNetGuid) : target.systemAddress;
		packet->systemAddress.systemIndex = (SystemIndex) GetIndexFromSystemAddress(packet->systemAddress);
		packet->guid.systemIndex=packet->systemAddress.systemIndex;
		packet->wasGeneratedLocally=true; // else processed twice
		AddPacketToProducer(packet);
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Cancel a pending connection attempt
// If we are already connected, the connection stays open
// \param[in] target Which system to cancel
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::CancelConnectionAttempt( const SystemAddress target )
{
	unsigned int i;

	// Cancel pending connection attempt, if there is one
	i=0;
	requestedConnectionQueueMutex.Lock();
	while (i < requestedConnectionQueue.Size())
	{
		if (requestedConnectionQueue[i]->systemAddress==target)
		{
			RakNet::OP_DELETE(requestedConnectionQueue[i], _FILE_AND_LINE_ );
			requestedConnectionQueue.RemoveAtIndex(i);
			break;
		}
		else
			i++;
	}
	requestedConnectionQueueMutex.Unlock();

}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

ConnectionState RakPeer::GetConnectionState(const AddressOrGUID systemIdentifier)
{
	if (systemIdentifier.systemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		unsigned int i=0;
		requestedConnectionQueueMutex.Lock();
		for (; i < requestedConnectionQueue.Size(); i++)
		{
			if (requestedConnectionQueue[i]->systemAddress==systemIdentifier.systemAddress)
			{
				requestedConnectionQueueMutex.Unlock();
				return IS_PENDING;
			}
		}
		requestedConnectionQueueMutex.Unlock();
	}

	int index;
	if (systemIdentifier.systemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		index = GetIndexFromSystemAddress(systemIdentifier.systemAddress, false);
	}
	else
	{
		index = GetIndexFromGuid(systemIdentifier.rakNetGuid);
	}

	if (index==-1)
		return IS_NOT_CONNECTED;

	if (remoteSystemList[index].isActive==false)
		return IS_DISCONNECTED;

	switch (remoteSystemList[index].connectMode)
	{
	case RemoteSystemStruct::DISCONNECT_ASAP:
		return IS_DISCONNECTING;
	case RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY:
		return IS_SILENTLY_DISCONNECTING;
	case RemoteSystemStruct::DISCONNECT_ON_NO_ACK:
		return IS_DISCONNECTING;
	case RemoteSystemStruct::REQUESTED_CONNECTION:
		return IS_CONNECTING;
	case RemoteSystemStruct::HANDLING_CONNECTION_REQUEST:
		return IS_CONNECTING;
	case RemoteSystemStruct::UNVERIFIED_SENDER:
		return IS_CONNECTING;
	case RemoteSystemStruct::CONNECTED:
		return IS_CONNECTED;
    default:
		return IS_NOT_CONNECTED;
	}

	return IS_NOT_CONNECTED;
}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Given a systemAddress, returns an index from 0 to the maximum number of players allowed - 1.
//
// Parameters
// systemAddress - The systemAddress to search for
//
// Returns
// An integer from 0 to the maximum number of peers -1, or -1 if that player is not found
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetIndexFromSystemAddress( const SystemAddress systemAddress ) const
{
	return GetIndexFromSystemAddress(systemAddress, false);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// This function is only useful for looping through all players.
//
// Parameters
// index - an integer between 0 and the maximum number of players allowed - 1.
//
// Returns
// A valid systemAddress or UNASSIGNED_SYSTEM_ADDRESS if no such player at that index
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SystemAddress RakPeer::GetSystemAddressFromIndex( int index )
{
	// remoteSystemList in user thread
	//if ( index >= 0 && index < remoteSystemListSize )
	if ( index >= 0 && index < maximumNumberOfPeers )
		if (remoteSystemList[index].isActive && remoteSystemList[ index ].connectMode==RakPeer::RemoteSystemStruct::CONNECTED) // Don't give the user players that aren't fully connected, since sends will fail
			return remoteSystemList[ index ].systemAddress;

	return UNASSIGNED_SYSTEM_ADDRESS;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Same as GetSystemAddressFromIndex but returns RakNetGUID
// \param[in] index Index should range between 0 and the maximum number of players allowed - 1.
// \return The RakNetGUID
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakNetGUID RakPeer::GetGUIDFromIndex( int index )
{
	// remoteSystemList in user thread
	//if ( index >= 0 && index < remoteSystemListSize )
	if ( index >= 0 && index < maximumNumberOfPeers )
		if (remoteSystemList[index].isActive && remoteSystemList[ index ].connectMode==RakPeer::RemoteSystemStruct::CONNECTED) // Don't give the user players that aren't fully connected, since sends will fail
			return remoteSystemList[ index ].guid;

	return UNASSIGNED_RAKNET_GUID;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Same as calling GetSystemAddressFromIndex and GetGUIDFromIndex for all systems, but more efficient
// Indices match each other, so \a addresses[0] and \a guids[0] refer to the same system
// \param[out] addresses All system addresses. Size of the list is the number of connections. Size of the list will match the size of the \a guids list.
// \param[out] guids All guids. Size of the list is the number of connections. Size of the list will match the size of the \a addresses list.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::GetSystemList(DataStructures::List<SystemAddress> &addresses, DataStructures::List<RakNetGUID> &guids) const
{
	addresses.Clear(false, _FILE_AND_LINE_);
	guids.Clear(false, _FILE_AND_LINE_);

	if ( remoteSystemList == 0 || endThreads == true )
		return;

	unsigned int i;
	for (i=0; i < activeSystemListSize; i++)
	{
		if ((activeSystemList[i])->isActive &&
			(activeSystemList[i])->connectMode==RakPeer::RemoteSystemStruct::CONNECTED)
		{
			addresses.Push((activeSystemList[i])->systemAddress, _FILE_AND_LINE_ );
			guids.Push((activeSystemList[i])->guid, _FILE_AND_LINE_ );
		}
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Bans an IP from connecting. Banned IPs persist between connections.
//
// Parameters
// IP - Dotted IP address.  Can use * as a wildcard, such as 128.0.0.* will ban
// All IP addresses starting with 128.0.0
// milliseconds - how many ms for a temporary ban.  Use 0 for a permanent ban
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::AddToBanList( const char *IP, RakNet::TimeMS milliseconds )
{
	unsigned index;
	RakNet::TimeMS time = RakNet::GetTimeMS();

	if ( IP == 0 || IP[ 0 ] == 0 || strlen( IP ) > 15 )
		return ;

	// If this guy is already in the ban list, do nothing
	index = 0;

	banListMutex.Lock();

	for ( ; index < banList.Size(); index++ )
	{
		if ( strcmp( IP, banList[ index ]->IP ) == 0 )
		{
			// Already in the ban list.  Just update the time
			if (milliseconds==0)
				banList[ index ]->timeout=0; // Infinite
			else
				banList[ index ]->timeout=time+milliseconds;
			banListMutex.Unlock();
			return;
		}
	}

	banListMutex.Unlock();

	BanStruct *banStruct = RakNet::OP_NEW<BanStruct>( _FILE_AND_LINE_ );
	banStruct->IP = (char*) rakMalloc_Ex( 16, _FILE_AND_LINE_ );
	if (milliseconds==0)
		banStruct->timeout=0; // Infinite
	else
		banStruct->timeout=time+milliseconds;
	strcpy( banStruct->IP, IP );
	banListMutex.Lock();
	banList.Insert( banStruct, _FILE_AND_LINE_ );
	banListMutex.Unlock();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Allows a previously banned IP to connect.
//
// Parameters
// IP - Dotted IP address.  Can use * as a wildcard, such as 128.0.0.* will ban
// All IP addresses starting with 128.0.0
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::RemoveFromBanList( const char *IP )
{
	unsigned index;
	BanStruct *temp;

	if ( IP == 0 || IP[ 0 ] == 0 || strlen( IP ) > 15 )
		return ;

	index = 0;
	temp=0;

	banListMutex.Lock();

	for ( ; index < banList.Size(); index++ )
	{
		if ( strcmp( IP, banList[ index ]->IP ) == 0 )
		{
			temp = banList[ index ];
			banList[ index ] = banList[ banList.Size() - 1 ];
			banList.RemoveAtIndex( banList.Size() - 1 );
			break;
		}
	}

	banListMutex.Unlock();

	if (temp)
	{
		rakFree_Ex(temp->IP, _FILE_AND_LINE_ );
		RakNet::OP_DELETE(temp, _FILE_AND_LINE_);
	}

}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Allows all previously banned IPs to connect.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearBanList( void )
{
	unsigned index;
	index = 0;
	banListMutex.Lock();

	for ( ; index < banList.Size(); index++ )
	{
		rakFree_Ex(banList[ index ]->IP, _FILE_AND_LINE_ );
		RakNet::OP_DELETE(banList[ index ], _FILE_AND_LINE_);
	}

	banList.Clear(false, _FILE_AND_LINE_);

	banListMutex.Unlock();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetLimitIPConnectionFrequency(bool b)
{
	limitConnectionFrequencyFromTheSameIP=b;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Determines if a particular IP is banned.
//
// Parameters
// IP - Complete dotted IP address
//
// Returns
// True if IP matches any IPs in the ban list, accounting for any wildcards.
// False otherwise.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::IsBanned( const char *IP )
{
	unsigned banListIndex, characterIndex;
	RakNet::TimeMS time;
	BanStruct *temp;

	if ( IP == 0 || IP[ 0 ] == 0 || strlen( IP ) > 15 )
		return false;

	banListIndex = 0;

	if ( banList.Size() == 0 )
		return false; // Skip the mutex if possible

	time = RakNet::GetTimeMS();

	banListMutex.Lock();

	while ( banListIndex < banList.Size() )
	{
		if (banList[ banListIndex ]->timeout>0 && banList[ banListIndex ]->timeout<time)
		{
			// Delete expired ban
			temp = banList[ banListIndex ];
			banList[ banListIndex ] = banList[ banList.Size() - 1 ];
			banList.RemoveAtIndex( banList.Size() - 1 );
			rakFree_Ex(temp->IP, _FILE_AND_LINE_ );
			RakNet::OP_DELETE(temp, _FILE_AND_LINE_);
		}
		else
		{
			characterIndex = 0;

#ifdef _MSC_VER
#pragma warning( disable : 4127 ) // warning C4127: conditional expression is constant
#endif
			while ( true )
			{
				if ( banList[ banListIndex ]->IP[ characterIndex ] == IP[ characterIndex ] )
				{
					// Equal characters

					if ( IP[ characterIndex ] == 0 )
					{
						banListMutex.Unlock();
						// End of the string and the strings match

						return true;
					}

					characterIndex++;
				}

				else
				{
					if ( banList[ banListIndex ]->IP[ characterIndex ] == 0 || IP[ characterIndex ] == 0 )
					{
						// End of one of the strings
						break;
					}

					// Characters do not match
					if ( banList[ banListIndex ]->IP[ characterIndex ] == '*' )
					{
						banListMutex.Unlock();

						// Domain is banned.
						return true;
					}

					// Characters do not match and it is not a *
					break;
				}
			}

			banListIndex++;
		}
	}

	banListMutex.Unlock();

	// No match found.
	return false;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Send a ping to the specified connected system.
//
// Parameters:
// target - who to ping
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::Ping( const SystemAddress target )
{
	PingInternal(target, false, UNRELIABLE);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Send a ping to the specified unconnected system.
// The remote system, if it is Initialized, will respond with ID_UNCONNECTED_PONG.
// The final ping time will be encoded in the following sizeof(RakNet::TimeMS) bytes.  (Default is 4 bytes - See __GET_TIME_64BIT in RakNetTypes.h
//
// Parameters:
// host: Either a dotted IP address or a domain name.  Can be 255.255.255.255 for LAN broadcast.
// remotePort: Which port to connect to on the remote machine.
// onlyReplyOnAcceptingConnections: Only request a reply if the remote system has open connections
// connectionSocketIndex Index into the array of socket descriptors passed to socketDescriptors in RakPeer::Startup() to send on.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::Ping( const char* host, unsigned short remotePort, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex )
{
	if ( host == 0 )
		return false;

	// If this assert hits then Startup wasn't called or the call failed.
	RakAssert(connectionSocketIndex < socketList.Size());

//	if ( IsActive() == false )
//		return;

	RakNet::BitStream bitStream( sizeof(unsigned char) + sizeof(RakNet::Time) );
	if ( onlyReplyOnAcceptingConnections )
		bitStream.Write((MessageID)ID_UNCONNECTED_PING_OPEN_CONNECTIONS);
	else
		bitStream.Write((MessageID)ID_UNCONNECTED_PING);

	bitStream.Write(RakNet::GetTime());

	bitStream.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));

	// No timestamp for 255.255.255.255
	unsigned int realIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);

	SystemAddress systemAddress;
	systemAddress.FromStringExplicitPort(host,remotePort, socketList[realIndex]->boundAddress.GetIPVersion());
	systemAddress.FixForIPVersion(socketList[realIndex]->boundAddress);

	SocketLayer::SendTo( socketList[realIndex]->s, (const char*)bitStream.GetData(), (int) bitStream.GetNumberOfBytesUsed(), systemAddress, socketList[realIndex]->remotePortRakNetWasStartedOn_PS3_PSP2, socketList[realIndex]->extraSocketOptions, _FILE_AND_LINE_ );

	return true;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the average of all ping times read for a specified target
//
// Parameters:
// target - whose time to read
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetAveragePing( const AddressOrGUID systemIdentifier )
{
	int sum, quantity;
	RemoteSystemStruct *remoteSystem = GetRemoteSystem( systemIdentifier, false, false );

	if ( remoteSystem == 0 )
		return -1;

	for ( sum = 0, quantity = 0; quantity < PING_TIMES_ARRAY_SIZE; quantity++ )
	{
		if ( remoteSystem->pingAndClockDifferential[ quantity ].pingTime == 65535 )
			break;
		else
			sum += remoteSystem->pingAndClockDifferential[ quantity ].pingTime;
	}

	if ( quantity > 0 )
		return sum / quantity;
	else
		return -1;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the last ping time read for the specific player or -1 if none read yet
//
// Parameters:
// target - whose time to read
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetLastPing( const AddressOrGUID systemIdentifier ) const
{
	RemoteSystemStruct * remoteSystem = GetRemoteSystem( systemIdentifier, false, false );

	if ( remoteSystem == 0 )
		return -1;

//	return (int)(remoteSystem->reliabilityLayer.GetAckPing()/(RakNet::TimeUS)1000);

	if ( remoteSystem->pingAndClockDifferentialWriteIndex == 0 )
		return remoteSystem->pingAndClockDifferential[ PING_TIMES_ARRAY_SIZE - 1 ].pingTime;
	else
		return remoteSystem->pingAndClockDifferential[ remoteSystem->pingAndClockDifferentialWriteIndex - 1 ].pingTime;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the lowest ping time read or -1 if none read yet
//
// Parameters:
// target - whose time to read
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetLowestPing( const AddressOrGUID systemIdentifier ) const
{
	RemoteSystemStruct * remoteSystem = GetRemoteSystem( systemIdentifier, false, false );

	if ( remoteSystem == 0 )
		return -1;

	return remoteSystem->lowestPing;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Ping the remote systems every so often.  This is off by default
// This will work anytime
//
// Parameters:
// doPing - True to start occasional pings.  False to stop them.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetOccasionalPing( bool doPing )
{
	occasionalPing = doPing;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Length should be under 400 bytes, as a security measure against flood attacks
// Sets the data to send with an  (LAN server discovery) /(offline ping) response
// See the Ping sample project for how this is used.
// data: a block of data to store, or 0 for none
// length: The length of data in bytes, or 0 for none
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetOfflinePingResponse( const char *data, const unsigned int length )
{
	RakAssert(length < 400);

	rakPeerMutexes[ offlinePingResponse_Mutex ].Lock();
	offlinePingResponse.Reset();

	if ( data && length > 0 )
		offlinePingResponse.Write( data, length );

	rakPeerMutexes[ offlinePingResponse_Mutex ].Unlock();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns pointers to a copy of the data passed to SetOfflinePingResponse
// \param[out] data A pointer to a copy of the data passed to \a SetOfflinePingResponse()
// \param[out] length A pointer filled in with the length parameter passed to SetOfflinePingResponse()
// \sa SetOfflinePingResponse
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::GetOfflinePingResponse( char **data, unsigned int *length )
{
	rakPeerMutexes[ offlinePingResponse_Mutex ].Lock();
	*data = (char*) offlinePingResponse.GetData();
	*length = (int) offlinePingResponse.GetNumberOfBytesUsed();
	rakPeerMutexes[ offlinePingResponse_Mutex ].Unlock();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Return the unique SystemAddress that represents you on the the network
// Note that unlike in previous versions, this is a struct and is not sequential
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SystemAddress RakPeer::GetInternalID( const SystemAddress systemAddress, const int index ) const
{
	if (systemAddress==UNASSIGNED_SYSTEM_ADDRESS)
	{
		return ipList[index];
	}
	else
	{

//		SystemAddress returnValue;
		RemoteSystemStruct * remoteSystem = GetRemoteSystemFromSystemAddress( systemAddress, false, true );
		if (remoteSystem==0)
			return UNASSIGNED_SYSTEM_ADDRESS;

		return remoteSystem->theirInternalSystemAddress[index];
		/*
		sockaddr_in sa;
		socklen_t len = sizeof(sa);
		if (getsockname__(connectionSockets[remoteSystem->connectionSocketIndex], (sockaddr*)&sa, &len)!=0)
			return UNASSIGNED_SYSTEM_ADDRESS;
		returnValue.port=ntohs(sa.sin_port);
		returnValue.binaryAddress=sa.sin_addr.s_addr;
		return returnValue;
*/



	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Return the unique address identifier that represents you on the the network and is based on your external
// IP / port (the IP / port the specified player uses to communicate with you)
// Note that unlike in previous versions, this is a struct and is not sequential
//
// Parameters:
// target: Which remote system you are referring to for your external ID
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SystemAddress RakPeer::GetExternalID( const SystemAddress target ) const
{
	unsigned i;
	SystemAddress inactiveExternalId;

	inactiveExternalId=UNASSIGNED_SYSTEM_ADDRESS;

	if (target==UNASSIGNED_SYSTEM_ADDRESS)
		return firstExternalID;

	// First check for active connection with this systemAddress
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].systemAddress == target )
		{
			if ( remoteSystemList[ i ].isActive )
				return remoteSystemList[ i ].myExternalSystemAddress;
			else if (remoteSystemList[ i ].myExternalSystemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
				inactiveExternalId=remoteSystemList[ i ].myExternalSystemAddress;
		}
	}

	return inactiveExternalId;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const RakNetGUID RakPeer::GetMyGUID(void) const
{
	return myGuid;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SystemAddress RakPeer::GetMyBoundAddress(const int socketIndex)
{
	DataStructures::List<RakNetSmartPtr<RakNetSocket> > sockets;
	GetSockets( sockets );
	if (sockets.Size()>0)
		return sockets[socketIndex]->boundAddress;
	else
		return UNASSIGNED_SYSTEM_ADDRESS;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const RakNetGUID& RakPeer::GetGuidFromSystemAddress( const SystemAddress input ) const
{
	if (input==UNASSIGNED_SYSTEM_ADDRESS)
		return myGuid;

	if (input.systemIndex!=(SystemIndex)-1 && input.systemIndex<maximumNumberOfPeers && remoteSystemList[ input.systemIndex ].systemAddress == input)
		return remoteSystemList[ input.systemIndex ].guid;

	unsigned int i;
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].systemAddress == input )
		{
			return remoteSystemList[ i ].guid;
		}
	}

	return UNASSIGNED_RAKNET_GUID;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

unsigned int RakPeer::GetSystemIndexFromGuid( const RakNetGUID input ) const
{
	if (input==UNASSIGNED_RAKNET_GUID)
		return (unsigned int) -1;

	if (input==myGuid)
		return (unsigned int) -1;

	if (input.systemIndex!=(SystemIndex)-1 && input.systemIndex<maximumNumberOfPeers && remoteSystemList[ input.systemIndex ].guid == input)
		return input.systemIndex;

	unsigned int i;
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].guid == input )
		{
			return i;
		}
	}

	return (unsigned int) -1;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

SystemAddress RakPeer::GetSystemAddressFromGuid( const RakNetGUID input ) const
{
	if (input==UNASSIGNED_RAKNET_GUID)
		return UNASSIGNED_SYSTEM_ADDRESS;

	if (input==myGuid)
		return GetInternalID(UNASSIGNED_SYSTEM_ADDRESS);

	if (input.systemIndex!=(SystemIndex)-1 && input.systemIndex<maximumNumberOfPeers && remoteSystemList[ input.systemIndex ].guid == input)
		return remoteSystemList[ input.systemIndex ].systemAddress;

	unsigned int i;
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].guid == input )
		{
			return remoteSystemList[ i ].systemAddress;
		}
	}

	return UNASSIGNED_SYSTEM_ADDRESS;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Set the time, in MS, to use before considering ourselves disconnected after not being able to deliver a reliable packet
// \param[in] time Time, in MS
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetTimeoutTime( RakNet::TimeMS timeMS, const SystemAddress target )
{
	if (target==UNASSIGNED_SYSTEM_ADDRESS)
	{
		defaultTimeoutTime=timeMS;

		unsigned i;
		for ( i = 0; i < maximumNumberOfPeers; i++ )
		{
			if (remoteSystemList[ i ].isActive)
			{
				if ( remoteSystemList[ i ].isActive )
					remoteSystemList[ i ].reliabilityLayer.SetTimeoutTime(timeMS);
			}
		}
	}
	else
	{
		RemoteSystemStruct * remoteSystem = GetRemoteSystemFromSystemAddress( target, false, true );

		if ( remoteSystem != 0 )
			remoteSystem->reliabilityLayer.SetTimeoutTime(timeMS);
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

RakNet::TimeMS RakPeer::GetTimeoutTime( const SystemAddress target )
{
	if (target==UNASSIGNED_SYSTEM_ADDRESS)
	{
		return defaultTimeoutTime;
	}
	else
	{
		RemoteSystemStruct * remoteSystem = GetRemoteSystemFromSystemAddress( target, false, true );

		if ( remoteSystem != 0 )
			remoteSystem->reliabilityLayer.GetTimeoutTime();
	}
	return defaultTimeoutTime;
}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the current MTU size
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetMTUSize( const SystemAddress target ) const
{
	if (target!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		RemoteSystemStruct *rss=GetRemoteSystemFromSystemAddress(target, false, true);
		if (rss)
			return rss->MTUSize;
	}
	return defaultMTUSize;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the number of IP addresses we have
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetNumberOfAddresses( void )
{

	int i = 0;

	while ( ipList[ i ]!=UNASSIGNED_SYSTEM_ADDRESS )
		i++;

	return i;




}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns an IP address at index 0 to GetNumberOfAddresses-1
// \param[in] index index into the list of IP addresses
// \return The local IP address at this index
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
const char* RakPeer::GetLocalIP( unsigned int index )
{
	if (IsActive()==false)
	{
	// Fill out ipList structure

	SocketLayer::GetMyIP( ipList );

	}


	static char str[128];
	ipList[index].ToString(false,str);
	return str;




}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Is this a local IP?
// \param[in] An IP address to check
// \return True if this is one of the IP addresses returned by GetLocalIP
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::IsLocalIP( const char *ip )
{
	if (ip==0 || ip[0]==0)
		return false;


	if (strcmp(ip, "127.0.0.1")==0 || strcmp(ip, "localhost")==0)
		return true;

	int num = GetNumberOfAddresses();
	int i;
	for (i=0; i < num; i++)
	{
		if (strcmp(ip, GetLocalIP(i))==0)
			return true;
	}




	return false;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Allow or disallow connection responses from any IP. Normally this should be false, but may be necessary
// when connection to servers with multiple IP addresses
//
// Parameters:
// allow - True to allow this behavior, false to not allow.  Defaults to false.  Value persists between connections
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::AllowConnectionResponseIPMigration( bool allow )
{
	allowConnectionResponseIPMigration = allow;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Controls how often to return ID_DOWNLOAD_PROGRESS for large message downloads.
// ID_DOWNLOAD_PROGRESS is returned to indicate a new partial message chunk, roughly the MTU size, has arrived
// As it can be slow or cumbersome to get this notification for every chunk, you can set the interval at which it is returned.
// Defaults to 0 (never return this notification)
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetSplitMessageProgressInterval(int interval)
{
	RakAssert(interval>=0);
	splitMessageProgressInterval=interval;
	for ( unsigned short i = 0; i < maximumNumberOfPeers; i++ )
		remoteSystemList[ i ].reliabilityLayer.SetSplitMessageProgressInterval(splitMessageProgressInterval);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns what was passed to SetSplitMessageProgressInterval()
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetSplitMessageProgressInterval(void) const
{
	return splitMessageProgressInterval;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Set how long to wait before giving up on sending an unreliable message
// Useful if the network is clogged up.
// Set to 0 or less to never timeout.  Defaults to 0.
// timeoutMS How many ms to wait before simply not sending an unreliable message.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetUnreliableTimeout(RakNet::TimeMS timeoutMS)
{
	unreliableTimeout=timeoutMS;
	for ( unsigned short i = 0; i < maximumNumberOfPeers; i++ )
		remoteSystemList[ i ].reliabilityLayer.SetUnreliableTimeout(unreliableTimeout);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Send a message to host, with the IP socket option TTL set to 3
// This message will not reach the host, but will open the router.
// Used for NAT-Punchthrough
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SendTTL( const char* host, unsigned short remotePort, int ttl, unsigned connectionSocketIndex )
{
	char fakeData[2];
	fakeData[0]=0;
	fakeData[1]=1;
	unsigned int realIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);
	SystemAddress systemAddress = socketList[realIndex]->boundAddress;
	systemAddress.FromStringExplicitPort(host,remotePort);
	SocketLayer::SendToTTL( socketList[realIndex]->s, (char*)fakeData, 2, systemAddress, ttl );
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Put a packet back at the end of the receive queue in case you don't want to deal with it immediately
//
// packet The packet you want to push back.
// pushAtHead True to push the packet so that the next receive call returns it.  False to push it at the end of the queue (obviously pushing it at the end makes the packets out of order)
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::PushBackPacket( Packet *packet, bool pushAtHead)
{
	if (packet==0)
		return;

	packetReturnMutex.Lock();
	if (pushAtHead)
		packetReturnQueue.PushAtHead(packet,0,_FILE_AND_LINE_);
	else
		packetReturnQueue.Push(packet,_FILE_AND_LINE_);
	packetReturnMutex.Unlock();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ChangeSystemAddress(RakNetGUID guid, const SystemAddress &systemAddress)
{
	BufferedCommandStruct *bcs;

	bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
	bcs->data = 0;
	bcs->systemIdentifier.systemAddress=systemAddress;
	bcs->systemIdentifier.rakNetGuid=guid;
	bcs->command=BufferedCommandStruct::BCS_CHANGE_SYSTEM_ADDRESS;
	bufferedCommands.Push(bcs);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Packet* RakPeer::AllocatePacket(unsigned dataSize)
{
	return AllocPacket(dataSize, _FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakNetSmartPtr<RakNetSocket> RakPeer::GetSocket( const SystemAddress target )
{
	// Send a query to the thread to get the socket, and return when we got it
	BufferedCommandStruct *bcs;
	bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
	bcs->command=BufferedCommandStruct::BCS_GET_SOCKET;
	bcs->systemIdentifier=target;
	bcs->data=0;
	bufferedCommands.Push(bcs);

	// Block up to one second to get the socket, although it should actually take virtually no time
	SocketQueryOutput *sqo;
	RakNet::TimeMS stopWaiting = RakNet::GetTimeMS()+1000;
	DataStructures::List<RakNetSmartPtr<RakNetSocket> > output;
	while (RakNet::GetTimeMS() < stopWaiting)
	{
		if (isMainLoopThreadActive==false)
			return RakNetSmartPtr<RakNetSocket>();

		RakSleep(0);

		sqo = socketQueryOutput.Pop();
		if (sqo)
		{
			output=sqo->sockets;
			sqo->sockets.Clear(false, _FILE_AND_LINE_);
			socketQueryOutput.Deallocate(sqo, _FILE_AND_LINE_);
			if (output.Size())
				return output[0];
			break;
		}
	}
	return RakNetSmartPtr<RakNetSocket>();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::GetSockets( DataStructures::List<RakNetSmartPtr<RakNetSocket> > &sockets )
{
	sockets.Clear(false, _FILE_AND_LINE_);

	// Send a query to the thread to get the socket, and return when we got it
	BufferedCommandStruct *bcs;

	bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
	bcs->command=BufferedCommandStruct::BCS_GET_SOCKET;
	bcs->systemIdentifier=UNASSIGNED_SYSTEM_ADDRESS;
	bcs->data=0;
	bufferedCommands.Push(bcs);

	// Block up to one second to get the socket, although it should actually take virtually no time
	SocketQueryOutput *sqo;
	RakNetSmartPtr<RakNetSocket> output;
	while (1)
	{
		if (isMainLoopThreadActive==false)
			return;

		RakSleep(0);

		sqo = socketQueryOutput.Pop();
		if (sqo)
		{
			sockets=sqo->sockets;
			sqo->sockets.Clear(false, _FILE_AND_LINE_);
			socketQueryOutput.Deallocate(sqo, _FILE_AND_LINE_);
			return;
		}
	}
	return;
}
void RakPeer::ReleaseSockets( DataStructures::List<RakNetSmartPtr<RakNetSocket> > &sockets )
{
	sockets.Clear(false,_FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Adds simulated ping and packet loss to the outgoing data flow.
// To simulate bi-directional ping and packet loss, you should call this on both the sender and the recipient, with half the total ping and maxSendBPS value on each.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ApplyNetworkSimulator( float packetloss, unsigned short minExtraPing, unsigned short extraPingVariance)
{
#ifdef _DEBUG
	if (remoteSystemList)
	{
		unsigned short i;
		for (i=0; i < maximumNumberOfPeers; i++)
			//for (i=0; i < remoteSystemListSize; i++)
			remoteSystemList[i].reliabilityLayer.ApplyNetworkSimulator(packetloss, minExtraPing, extraPingVariance);
	}

	_packetloss=packetloss;
	_minExtraPing=minExtraPing;
	_extraPingVariance=extraPingVariance;
#endif
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

void RakPeer::SetPerConnectionOutgoingBandwidthLimit( unsigned maxBitsPerSecond )
{
	maxOutgoingBPS=maxBitsPerSecond;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns if you previously called ApplyNetworkSimulator
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::IsNetworkSimulatorActive( void )
{
#ifdef _DEBUG
	return _packetloss>0 || _minExtraPing>0 || _extraPingVariance>0;
#else
	return false;
#endif
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetUserUpdateThread(void (*_userUpdateThreadPtr)(RakPeerInterface *, void *), void *_userUpdateThreadData)
{
	userUpdateThreadPtr=_userUpdateThreadPtr;
	userUpdateThreadData=_userUpdateThreadData;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakNetStatistics * RakPeer::GetStatistics( const SystemAddress systemAddress, RakNetStatistics *rns )
{
	static RakNetStatistics staticStatistics;
	RakNetStatistics *systemStats;
	if (rns==0)
		systemStats=&staticStatistics;
	else
		systemStats=rns;

	if (systemAddress==UNASSIGNED_SYSTEM_ADDRESS)
	{
		bool firstWrite=false;
		// Return a crude sum
		for ( unsigned short i = 0; i < maximumNumberOfPeers; i++ )
		{
			if (remoteSystemList[ i ].isActive)
			{
				RakNetStatistics rnsTemp;
				remoteSystemList[ i ].reliabilityLayer.GetStatistics(&rnsTemp);

				if (firstWrite==false)
				{
					memcpy(systemStats, &rnsTemp, sizeof(RakNetStatistics));
					firstWrite=true;
				}
				else
					(*systemStats)+=rnsTemp;
			}
		}
		return systemStats;
	}
	else
	{
		RemoteSystemStruct * rss;
		rss = GetRemoteSystemFromSystemAddress( systemAddress, false, false );
		if ( rss && endThreads==false )
		{
			rss->reliabilityLayer.GetStatistics(systemStats);
			return systemStats;
		}
	}

	return 0;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::GetStatistics( const int index, RakNetStatistics *rns )
{
	if (index < maximumNumberOfPeers && remoteSystemList[ index ].isActive)
	{
		remoteSystemList[ index ].reliabilityLayer.GetStatistics(rns);
		return true;
	}
	return false;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetReceiveBufferSize(void)
{
	unsigned int size;
	packetReturnMutex.Lock();
	size=packetReturnQueue.Size();
	packetReturnMutex.Unlock();
	return size;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetIndexFromSystemAddress( const SystemAddress systemAddress, bool calledFromNetworkThread ) const
{
	unsigned i;

	if ( systemAddress == UNASSIGNED_SYSTEM_ADDRESS )
		return -1;

	if (systemAddress.systemIndex!=(SystemIndex)-1 && systemAddress.systemIndex < maximumNumberOfPeers && remoteSystemList[systemAddress.systemIndex].systemAddress==systemAddress && remoteSystemList[ systemAddress.systemIndex ].isActive)
		return systemAddress.systemIndex;

	if (calledFromNetworkThread)
	{
		return GetRemoteSystemIndex(systemAddress);
	}
	else
	{
		// remoteSystemList in user and network thread
		for ( i = 0; i < maximumNumberOfPeers; i++ )
			if ( remoteSystemList[ i ].isActive && remoteSystemList[ i ].systemAddress == systemAddress )
				return i;

		// If no active results found, try previously active results.
		for ( i = 0; i < maximumNumberOfPeers; i++ )
			if ( remoteSystemList[ i ].systemAddress == systemAddress )
				return i;
	}

	return -1;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetIndexFromGuid( const RakNetGUID guid )
{
	unsigned i;

	if ( guid == UNASSIGNED_RAKNET_GUID )
		return -1;

	if (guid.systemIndex!=(SystemIndex)-1 && guid.systemIndex < maximumNumberOfPeers && remoteSystemList[guid.systemIndex].guid==guid && remoteSystemList[ guid.systemIndex ].isActive)
		return guid.systemIndex;

	// remoteSystemList in user and network thread
	for ( i = 0; i < maximumNumberOfPeers; i++ )
		if ( remoteSystemList[ i ].isActive && remoteSystemList[ i ].guid == guid )
			return i;

	// If no active results found, try previously active results.
	for ( i = 0; i < maximumNumberOfPeers; i++ )
		if ( remoteSystemList[ i ].guid == guid )
			return i;

	return -1;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ConnectionAttemptResult RakPeer::SendConnectionRequest( const char* host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned int extraData, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime )
{
	RakAssert(passwordDataLength <= 256);
	RakAssert(remotePort!=0);
	SystemAddress systemAddress;
	if (!systemAddress.FromStringExplicitPort(host,remotePort,socketList[connectionSocketIndex]->boundAddress.GetIPVersion()))
		return CANNOT_RESOLVE_DOMAIN_NAME;

	// Already connected?
	if (GetRemoteSystemFromSystemAddress(systemAddress, false, true))
		return ALREADY_CONNECTED_TO_ENDPOINT;

	//RequestedConnectionStruct *rcs = (RequestedConnectionStruct *) rakMalloc_Ex(sizeof(RequestedConnectionStruct), _FILE_AND_LINE_);
	RequestedConnectionStruct *rcs = RakNet::OP_NEW<RequestedConnectionStruct>(_FILE_AND_LINE_);

	rcs->systemAddress=systemAddress;
	rcs->nextRequestTime=RakNet::GetTimeMS();
	rcs->requestsMade=0;
	rcs->data=0;
	rcs->extraData=extraData;
	rcs->socketIndex=connectionSocketIndex;
	rcs->actionToTake=RequestedConnectionStruct::CONNECT;
	rcs->sendConnectionAttemptCount=sendConnectionAttemptCount;
	rcs->timeBetweenSendConnectionAttemptsMS=timeBetweenSendConnectionAttemptsMS;
	memcpy(rcs->outgoingPassword, passwordData, passwordDataLength);
	rcs->outgoingPasswordLength=(unsigned char) passwordDataLength;
	rcs->timeoutTime=timeoutTime;

	// Return false if already pending, else push on queue
	unsigned int i=0;
	requestedConnectionQueueMutex.Lock();
	for (; i < requestedConnectionQueue.Size(); i++)
	{
		if (requestedConnectionQueue[i]->systemAddress==systemAddress)
		{
			requestedConnectionQueueMutex.Unlock();
			// Not necessary
			//RakNet::OP_DELETE(rcs->client_handshake,_FILE_AND_LINE_);
			RakNet::OP_DELETE(rcs,_FILE_AND_LINE_);
			return CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
		}
	}
	requestedConnectionQueue.Push(rcs, _FILE_AND_LINE_ );
	requestedConnectionQueueMutex.Unlock();

	return CONNECTION_ATTEMPT_STARTED;
}
ConnectionAttemptResult RakPeer::SendConnectionRequest( const char* host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned int extraData, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime, RakNetSmartPtr<RakNetSocket> socket )
{
	RakAssert(passwordDataLength <= 256);
	SystemAddress systemAddress;
	systemAddress.FromStringExplicitPort(host,remotePort);

	// Already connected?
	if (GetRemoteSystemFromSystemAddress(systemAddress, false, true))
		return ALREADY_CONNECTED_TO_ENDPOINT;

	//RequestedConnectionStruct *rcs = (RequestedConnectionStruct *) rakMalloc_Ex(sizeof(RequestedConnectionStruct), _FILE_AND_LINE_);
	RequestedConnectionStruct *rcs = RakNet::OP_NEW<RequestedConnectionStruct>(_FILE_AND_LINE_);

	rcs->systemAddress=systemAddress;
	rcs->nextRequestTime=RakNet::GetTimeMS();
	rcs->requestsMade=0;
	rcs->data=0;
	rcs->extraData=extraData;
	rcs->socketIndex=connectionSocketIndex;
	rcs->actionToTake=RequestedConnectionStruct::CONNECT;
	rcs->sendConnectionAttemptCount=sendConnectionAttemptCount;
	rcs->timeBetweenSendConnectionAttemptsMS=timeBetweenSendConnectionAttemptsMS;
	memcpy(rcs->outgoingPassword, passwordData, passwordDataLength);
	rcs->outgoingPasswordLength=(unsigned char) passwordDataLength;
	rcs->timeoutTime=timeoutTime;
	rcs->socket=socket;

	// Return false if already pending, else push on queue
	unsigned int i=0;
	requestedConnectionQueueMutex.Lock();
	for (; i < requestedConnectionQueue.Size(); i++)
	{
		if (requestedConnectionQueue[i]->systemAddress==systemAddress)
		{
			requestedConnectionQueueMutex.Unlock();
			// Not necessary
			//RakNet::OP_DELETE(rcs->client_handshake,_FILE_AND_LINE_);
			RakNet::OP_DELETE(rcs,_FILE_AND_LINE_);
			return CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
		}
	}
	requestedConnectionQueue.Push(rcs, _FILE_AND_LINE_ );
	requestedConnectionQueueMutex.Unlock();

	return CONNECTION_ATTEMPT_STARTED;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ValidateRemoteSystemLookup(void) const
{
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystem( const AddressOrGUID systemIdentifier, bool calledFromNetworkThread, bool onlyActive ) const
{
	if (systemIdentifier.rakNetGuid!=UNASSIGNED_RAKNET_GUID)
		return GetRemoteSystemFromGUID(systemIdentifier.rakNetGuid, onlyActive);
	else
		return GetRemoteSystemFromSystemAddress(systemIdentifier.systemAddress, calledFromNetworkThread, onlyActive);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystemFromSystemAddress( const SystemAddress systemAddress, bool calledFromNetworkThread, bool onlyActive ) const
{
	unsigned i;

	if ( systemAddress == UNASSIGNED_SYSTEM_ADDRESS )
		return 0;

	if (calledFromNetworkThread)
	{
		unsigned int index = GetRemoteSystemIndex(systemAddress);
		if (index!=(unsigned int) -1)
		{
			if (onlyActive==false || remoteSystemList[ index ].isActive==true )
			{
				RakAssert(remoteSystemList[index].systemAddress==systemAddress);
				return remoteSystemList + index;
			}
		}
	}
	else
	{
		int deadConnectionIndex=-1;

		// Active connections take priority.  But if there are no active connections, return the first systemAddress match found
		for ( i = 0; i < maximumNumberOfPeers; i++ )
		{
			if (remoteSystemList[ i ].systemAddress == systemAddress)
			{
				if ( remoteSystemList[ i ].isActive )
					return remoteSystemList + i;
				else if (deadConnectionIndex==-1)
					deadConnectionIndex=i;
			}
		}

		if (deadConnectionIndex!=-1 && onlyActive==false)
			return remoteSystemList + deadConnectionIndex;
	}

	return 0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystemFromGUID( const RakNetGUID guid, bool onlyActive ) const
{
	if (guid==UNASSIGNED_RAKNET_GUID)
		return 0;

	unsigned i;
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].guid == guid && (onlyActive==false || remoteSystemList[ i ].isActive))
		{
			return remoteSystemList + i;
		}
	}
	return 0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ParseConnectionRequestPacket( RakPeer::RemoteSystemStruct *remoteSystem, const SystemAddress &systemAddress, const char *data, int byteSize )
{
	RakNet::BitStream bs((unsigned char*) data,byteSize,false);
	bs.IgnoreBytes(sizeof(MessageID));
	RakNetGUID guid;
	bs.Read(guid);
	RakNet::Time incomingTimestamp;
	bs.Read(incomingTimestamp);
	unsigned char doSecurity;
	bs.Read(doSecurity);

	unsigned char *password = bs.GetData()+BITS_TO_BYTES(bs.GetReadOffset());
	int passwordLength = byteSize - BITS_TO_BYTES(bs.GetReadOffset());
	if ( incomingPasswordLength != passwordLength ||
		memcmp( password, incomingPassword, incomingPasswordLength ) != 0 )
	{
		CAT_AUDIT_PRINTF("AUDIT: Invalid password\n");
		// This one we only send once since we don't care if it arrives.
		RakNet::BitStream bitStream;
		bitStream.Write((MessageID)ID_INVALID_PASSWORD);
		bitStream.Write(GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
		SendImmediate((char*) bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), IMMEDIATE_PRIORITY, RELIABLE, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);
		remoteSystem->connectMode=RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
		return;
	}

	// OK
	remoteSystem->connectMode=RemoteSystemStruct::HANDLING_CONNECTION_REQUEST;

	OnConnectionRequest( remoteSystem, incomingTimestamp );
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::OnConnectionRequest( RakPeer::RemoteSystemStruct *remoteSystem, RakNet::Time incomingTimestamp )
{
	RakNet::BitStream bitStream;
	bitStream.Write((MessageID)ID_CONNECTION_REQUEST_ACCEPTED);
	bitStream.Write(remoteSystem->systemAddress);
	SystemIndex systemIndex = (SystemIndex) GetIndexFromSystemAddress( remoteSystem->systemAddress, true );
	RakAssert(systemIndex!=65535);
	bitStream.Write(systemIndex);
	for (unsigned int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
		bitStream.Write(ipList[i]);
	bitStream.Write(incomingTimestamp);
	bitStream.Write(RakNet::GetTime());

	SendImmediate((char*)bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, RELIABLE_ORDERED, 0, remoteSystem->systemAddress, false, false, RakNet::GetTimeUS(), 0);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::NotifyAndFlagForShutdown( const SystemAddress systemAddress, bool performImmediate, unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority )
{
	RakNet::BitStream temp( sizeof(unsigned char) );
	temp.Write( (MessageID)ID_DISCONNECTION_NOTIFICATION );
	if (performImmediate)
	{
		SendImmediate((char*)temp.GetData(), temp.GetNumberOfBitsUsed(), disconnectionNotificationPriority, RELIABLE_ORDERED, orderingChannel, systemAddress, false, false, RakNet::GetTimeUS(), 0);
		RemoteSystemStruct *rss=GetRemoteSystemFromSystemAddress(systemAddress, true, true);
		rss->connectMode=RemoteSystemStruct::DISCONNECT_ASAP;
	}
	else
	{
		SendBuffered((const char*)temp.GetData(), temp.GetNumberOfBitsUsed(), disconnectionNotificationPriority, RELIABLE_ORDERED, orderingChannel, systemAddress, false, RemoteSystemStruct::DISCONNECT_ASAP, 0);
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned short RakPeer::GetNumberOfRemoteInitiatedConnections( void ) const
{
	if ( remoteSystemList == 0 || endThreads == true )
		return 0;

	unsigned short numberOfIncomingConnections;
	numberOfIncomingConnections = 0;
	unsigned int i;
	for (i=0; i < activeSystemListSize; i++)
	{
		if ((activeSystemList[i])->isActive &&
			(activeSystemList[i])->connectMode==RakPeer::RemoteSystemStruct::CONNECTED &&
			(activeSystemList[i])->weInitiatedTheConnection==false
			)
		{
			numberOfIncomingConnections++;
		}
	}
	return numberOfIncomingConnections;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct * RakPeer::AssignSystemAddressToRemoteSystemList( const SystemAddress systemAddress, RemoteSystemStruct::ConnectMode connectionMode, RakNetSmartPtr<RakNetSocket> incomingRakNetSocket, bool *thisIPConnectedRecently, SystemAddress bindingAddress, int incomingMTU, RakNetGUID guid, bool useSecurity )
{
	RemoteSystemStruct * remoteSystem;
	unsigned i,j,assignedIndex;
	RakNet::TimeMS time = RakNet::GetTimeMS();
#ifdef _DEBUG
	RakAssert(systemAddress!=UNASSIGNED_SYSTEM_ADDRESS);
#endif

	if (limitConnectionFrequencyFromTheSameIP)
	{
		if (IsLoopbackAddress(systemAddress,false)==false)
		{
			for ( i = 0; i < maximumNumberOfPeers; i++ )
			{
				if ( remoteSystemList[ i ].isActive==true &&
					remoteSystemList[ i ].systemAddress.EqualsExcludingPort(systemAddress) &&
					time >= remoteSystemList[ i ].connectionTime &&
					time - remoteSystemList[ i ].connectionTime < 100
					)
				{
					// 4/13/09 Attackers can flood ID_OPEN_CONNECTION_REQUEST and use up all available connection slots
					// Ignore connection attempts if this IP address connected within the last 100 milliseconds
					*thisIPConnectedRecently=true;
					ValidateRemoteSystemLookup();
					return 0;
				}
			}
		}
	}

	// Don't use a different port than what we received on
	bindingAddress.CopyPort(incomingRakNetSocket->boundAddress);

	*thisIPConnectedRecently=false;
	for ( assignedIndex = 0; assignedIndex < maximumNumberOfPeers; assignedIndex++ )
	{
		if ( remoteSystemList[ assignedIndex ].isActive==false )
		{
			remoteSystem=remoteSystemList+assignedIndex;
			ReferenceRemoteSystem(systemAddress, assignedIndex);
			remoteSystem->MTUSize=defaultMTUSize;
			remoteSystem->guid=guid;
			remoteSystem->isActive = true; // This one line causes future incoming packets to go through the reliability layer
			// Reserve this reliability layer for ourselves.
			if (incomingMTU > remoteSystem->MTUSize)
				remoteSystem->MTUSize=incomingMTU;
			remoteSystem->reliabilityLayer.Reset(true, remoteSystem->MTUSize, useSecurity);
			remoteSystem->reliabilityLayer.SetSplitMessageProgressInterval(splitMessageProgressInterval);
			remoteSystem->reliabilityLayer.SetUnreliableTimeout(unreliableTimeout);
			remoteSystem->reliabilityLayer.SetTimeoutTime(defaultTimeoutTime);
			AddToActiveSystemList(assignedIndex);
			if (incomingRakNetSocket->boundAddress==bindingAddress)
			{
				remoteSystem->rakNetSocket=incomingRakNetSocket;
			}
			else
			{
				char str[256];
				bindingAddress.ToString(true,str);
				// See if this is an internal IP address.
				// If so, force binding on it so we reply on the same IP address as they sent to.
				unsigned int ipListIndex, foundIndex=(unsigned int)-1;

				for (ipListIndex=0; ipListIndex < MAXIMUM_NUMBER_OF_INTERNAL_IDS; ipListIndex++)
				{
					if (ipList[ipListIndex]==UNASSIGNED_SYSTEM_ADDRESS)
						break;

					if (bindingAddress.EqualsExcludingPort(ipList[ipListIndex]))
					{
						foundIndex=ipListIndex;
						break;
					}
				}

				// 06/26/09 Unconfirmed report that Vista firewall blocks the reply if we force a binding
				// For now use the incoming socket only
				// Originally this code was to force a machine with multiple IP addresses to reply back on the IP
				// that the datagram came in on
				if (1 || foundIndex==(unsigned int)-1)
				{
					// Must not be an internal LAN address. Just use whatever socket it came in on
					remoteSystem->rakNetSocket=incomingRakNetSocket;
				}
				else
				{
					// Force binding
					unsigned int socketListIndex;
					for (socketListIndex=0; socketListIndex < socketList.Size(); socketListIndex++)
					{
						if (socketList[socketListIndex]->boundAddress==bindingAddress)
						{
							// Force binding with existing socket
							remoteSystem->rakNetSocket=socketList[socketListIndex];
							break;
						}
					}

					if (socketListIndex==socketList.Size())
					{
						char ipListFoundIndexStr[128];
						ipList[foundIndex].ToString(false,str);

						// Force binding with new socket
						RakNetSmartPtr<RakNetSocket> rns(RakNet::OP_NEW<RakNetSocket>(_FILE_AND_LINE_));
						if (incomingRakNetSocket->remotePortRakNetWasStartedOn_PS3_PSP2==0)
							rns->s = (unsigned int) SocketLayer::CreateBoundSocket( bindingAddress.GetPort(), true, ipListFoundIndexStr, 0, incomingRakNetSocket->extraSocketOptions, incomingRakNetSocket->socketFamily );
						else
							rns->s = (unsigned int) SocketLayer::CreateBoundSocket_PS3Lobby( bindingAddress.GetPort(), true, ipListFoundIndexStr, incomingRakNetSocket->socketFamily );
						if ((SOCKET)rns->s==(SOCKET)-1)
						{
							// Can't bind. Just use whatever socket it came in on
							remoteSystem->rakNetSocket=incomingRakNetSocket;
						}
						else
						{
							rns->boundAddress=bindingAddress;
							rns->remotePortRakNetWasStartedOn_PS3_PSP2=incomingRakNetSocket->remotePortRakNetWasStartedOn_PS3_PSP2;
							rns->extraSocketOptions=incomingRakNetSocket->extraSocketOptions;
							rns->userConnectionSocketIndex=(unsigned int)-1;
							socketList.Push(rns, _FILE_AND_LINE_ );
							remoteSystem->rakNetSocket=rns;

							RakPeerAndIndex rpai;
							rpai.remotePortRakNetWasStartedOn_PS3=rns->remotePortRakNetWasStartedOn_PS3_PSP2;
							rpai.extraSocketOptions=rns->extraSocketOptions;
							rpai.s=rns->s;
							rpai.rakPeer=this;
#ifdef _WIN32
							int highPriority=THREAD_PRIORITY_ABOVE_NORMAL;
#else
							int highPriority=-10;
#endif

//#if !defined(_XBOX) && !defined(X360)
							highPriority=0;
//#endif







							RakNet::RakThread::Create(RecvFromLoop, &rpai, highPriority);

							RakSleep(10);


							/*
#if defined (_WIN32) && defined(USE_WAIT_FOR_MULTIPLE_EVENTS)
							if (threadSleepTimer>0)
							{
								rns->recvEvent=CreateEvent(0,FALSE,FALSE,0);
								WSAEventSelect(rns->s,rns->recvEvent,FD_READ);
							}
#endif
							*/
						}
					}
				}
			}

			for ( j = 0; j < (unsigned) PING_TIMES_ARRAY_SIZE; j++ )
			{
				remoteSystem->pingAndClockDifferential[ j ].pingTime = 65535;
				remoteSystem->pingAndClockDifferential[ j ].clockDifferential = 0;
			}

			remoteSystem->connectMode=connectionMode;
			remoteSystem->pingAndClockDifferentialWriteIndex = 0;
			remoteSystem->lowestPing = 65535;
			remoteSystem->nextPingTime = 0; // Ping immediately
			remoteSystem->weInitiatedTheConnection = false;
			remoteSystem->connectionTime = time;
			remoteSystem->myExternalSystemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystem->lastReliableSend=time;

#ifdef _DEBUG
			int indexLoopupCheck=GetIndexFromSystemAddress( systemAddress, true );
			if ((int) indexLoopupCheck!=(int) assignedIndex)
			{
				RakAssert((int) indexLoopupCheck==(int) assignedIndex);
			}
#endif

			return remoteSystem;
		}
	}

	return 0;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Adjust the first four bytes (treated as unsigned int) of the pointer
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ShiftIncomingTimestamp( unsigned char *data, const SystemAddress &systemAddress ) const
{
#ifdef _DEBUG
	RakAssert( IsActive() );
	RakAssert( data );
#endif

	RakNet::BitStream timeBS( data, sizeof(RakNet::Time), false);
	RakNet::Time encodedTimestamp;
	timeBS.Read(encodedTimestamp);

	encodedTimestamp = encodedTimestamp - GetBestClockDifferential( systemAddress );
	timeBS.SetWriteOffset(0);
	timeBS.Write(encodedTimestamp);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Thanks to Chris Taylor (cat02e@fsu.edu) for the improved timestamping algorithm
RakNet::Time RakPeer::GetBestClockDifferential( const SystemAddress systemAddress ) const
{
	int counter, lowestPingSoFar;
	RakNet::Time clockDifferential;
	RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress( systemAddress, true, true );

	if ( remoteSystem == 0 )
		return 0;

	lowestPingSoFar = 65535;

	clockDifferential = 0;

	for ( counter = 0; counter < PING_TIMES_ARRAY_SIZE; counter++ )
	{
		if ( remoteSystem->pingAndClockDifferential[ counter ].pingTime == 65535 )
			break;

		if ( remoteSystem->pingAndClockDifferential[ counter ].pingTime < lowestPingSoFar )
		{
			clockDifferential = remoteSystem->pingAndClockDifferential[ counter ].clockDifferential;
			lowestPingSoFar = remoteSystem->pingAndClockDifferential[ counter ].pingTime;
		}
	}

	return clockDifferential;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::RemoteSystemLookupHashIndex(const SystemAddress &sa) const
{
	return SystemAddress::ToInteger(sa) % ((unsigned int) maximumNumberOfPeers * REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ReferenceRemoteSystem(const SystemAddress &sa, unsigned int remoteSystemListIndex)
{
// #ifdef _DEBUG
// 	for ( int remoteSystemIndex = 0; remoteSystemIndex < maximumNumberOfPeers; ++remoteSystemIndex )
// 	{
// 		if (remoteSystemList[remoteSystemIndex].isActive )
// 		{
// 			unsigned int hashIndex = GetRemoteSystemIndex(remoteSystemList[remoteSystemIndex].systemAddress);
// 			RakAssert(hashIndex==remoteSystemIndex);
// 		}
// 	}
// #endif


	SystemAddress oldAddress = remoteSystemList[remoteSystemListIndex].systemAddress;
	if (oldAddress!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		// The system might be active if rerouting
//		RakAssert(remoteSystemList[remoteSystemListIndex].isActive==false);

		// Remove the reference if the reference is pointing to this inactive system
		if (GetRemoteSystem(oldAddress)==&remoteSystemList[remoteSystemListIndex])
			DereferenceRemoteSystem(oldAddress);
	}
	DereferenceRemoteSystem(sa);

// #ifdef _DEBUG
// 	for ( int remoteSystemIndex = 0; remoteSystemIndex < maximumNumberOfPeers; ++remoteSystemIndex )
// 	{
// 		if (remoteSystemList[remoteSystemIndex].isActive )
// 		{
// 			unsigned int hashIndex = GetRemoteSystemIndex(remoteSystemList[remoteSystemIndex].systemAddress);
// 			if (hashIndex!=remoteSystemIndex)
// 			{
// 				RakAssert(hashIndex==remoteSystemIndex);
// 			}
// 		}
// 	}
// #endif


	remoteSystemList[remoteSystemListIndex].systemAddress=sa;

	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *rsi;
	rsi = remoteSystemIndexPool.Allocate(_FILE_AND_LINE_);
	if (remoteSystemLookup[hashIndex]==0)
	{
		rsi->next=0;
		rsi->index=remoteSystemListIndex;
		remoteSystemLookup[hashIndex]=rsi;
	}
	else
	{
		RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
		while (cur->next!=0)
		{
			cur=cur->next;
		}

		rsi = remoteSystemIndexPool.Allocate(_FILE_AND_LINE_);
		rsi->next=0;
		rsi->index=remoteSystemListIndex;
		cur->next=rsi;
	}

// #ifdef _DEBUG
// 	for ( int remoteSystemIndex = 0; remoteSystemIndex < maximumNumberOfPeers; ++remoteSystemIndex )
// 	{
// 		if (remoteSystemList[remoteSystemIndex].isActive )
// 		{
// 			unsigned int hashIndex = GetRemoteSystemIndex(remoteSystemList[remoteSystemIndex].systemAddress);
// 			RakAssert(hashIndex==remoteSystemIndex);
// 		}
// 	}
// #endif


	RakAssert(GetRemoteSystemIndex(sa)==remoteSystemListIndex);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::DereferenceRemoteSystem(const SystemAddress &sa)
{
	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
	RemoteSystemIndex *last = 0;
	while (cur!=0)
	{
		if (remoteSystemList[cur->index].systemAddress==sa)
		{
			if (last==0)
			{
				remoteSystemLookup[hashIndex]=cur->next;
			}
			else
			{
				last->next=cur->next;
			}
			remoteSystemIndexPool.Release(cur,_FILE_AND_LINE_);
			break;
		}
		last=cur;
		cur=cur->next;
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetRemoteSystemIndex(const SystemAddress &sa) const
{
	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
	while (cur!=0)
	{
		if (remoteSystemList[cur->index].systemAddress==sa)
			return cur->index;
		cur=cur->next;
	}
	return (unsigned int) -1;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct* RakPeer::GetRemoteSystem(const SystemAddress &sa) const
{
	unsigned int remoteSystemIndex = GetRemoteSystemIndex(sa);
	if (remoteSystemIndex==(unsigned int)-1)
		return 0;
	return remoteSystemList + remoteSystemIndex;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearRemoteSystemLookup(void)
{
	remoteSystemIndexPool.Clear(_FILE_AND_LINE_);
	RakNet::OP_DELETE_ARRAY(remoteSystemLookup,_FILE_AND_LINE_);
	remoteSystemLookup=0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::AddToActiveSystemList(unsigned int remoteSystemListIndex)
{
	activeSystemList[activeSystemListSize++]=remoteSystemList+remoteSystemListIndex;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::RemoveFromActiveSystemList(const SystemAddress &sa)
{
	unsigned int i;
	for (i=0; i < activeSystemListSize; i++)
	{
		RemoteSystemStruct *rss=activeSystemList[i];
		if (rss->systemAddress==sa)
		{
			activeSystemList[i]=activeSystemList[activeSystemListSize-1];
			activeSystemListSize--;
			return;
		}
	}
	RakAssert("activeSystemList invalid, entry not found in RemoveFromActiveSystemList. Ensure that AddToActiveSystemList and RemoveFromActiveSystemList are called by the same thread." && 0);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
/*
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::LookupIndexUsingHashIndex(const SystemAddress &sa) const
{
	unsigned int scanCount=0;
	unsigned int index = RemoteSystemLookupHashIndex(sa);
	if (remoteSystemLookup[index].index==(unsigned int)-1)
		return (unsigned int) -1;
	while (remoteSystemList[remoteSystemLookup[index].index].systemAddress!=sa)
	{
		if (++index==(unsigned int) maximumNumberOfPeers*REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE)
			index=0;
		if (++scanCount>(unsigned int) maximumNumberOfPeers*REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE)
			return (unsigned int) -1;
		if (remoteSystemLookup[index].index==-1)
			return (unsigned int) -1;
	}
	return index;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::RemoteSystemListIndexUsingHashIndex(const SystemAddress &sa) const
{
	unsigned int index = LookupIndexUsingHashIndex(sa);
	if (index!=(unsigned int) -1)
	{
		return remoteSystemLookup[index].index;
	}
	return (unsigned int) -1;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::FirstFreeRemoteSystemLookupIndex(const SystemAddress &sa) const
{
//	unsigned int collisionCount=0;
	unsigned int index = RemoteSystemLookupHashIndex(sa);
	while (remoteSystemLookup[index].index!=(unsigned int)-1)
	{
		if (++index==(unsigned int) maximumNumberOfPeers*REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE)
			index=0;
//		collisionCount++;
	}
//	printf("%i collisions. Using index %i\n", collisionCount, index);
	return index;
}
*/
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::IsLoopbackAddress(const AddressOrGUID &systemIdentifier, bool matchPort) const
{
	if (systemIdentifier.rakNetGuid!=UNASSIGNED_RAKNET_GUID)
		return systemIdentifier.rakNetGuid==myGuid;

	for (int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS && ipList[i]!=UNASSIGNED_SYSTEM_ADDRESS; i++)
	{
		if (matchPort)
		{
			if (ipList[i]==systemIdentifier.systemAddress)
				return true;
		}
		else
		{
			if (ipList[i].EqualsExcludingPort(systemIdentifier.systemAddress))
				return true;
		}
	}

	return (matchPort==true && systemIdentifier.systemAddress==firstExternalID) ||
		(matchPort==false && systemIdentifier.systemAddress.EqualsExcludingPort(firstExternalID));
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SystemAddress RakPeer::GetLoopbackAddress(void) const
{
	return ipList[0];
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::AllowIncomingConnections(void) const
{
	return GetNumberOfRemoteInitiatedConnections() < GetMaximumIncomingConnections();
}
using RBX::Network::Rupp::Rupp;
using RuppErrorCode = RBX::Network::Rupp::ErrorCode;

std::pair<unsigned, Rupp::RuppInfo> RakNet::RakPeer::ReadRuppHeader(const char* data, const int length, RakPeer* rakPeer, RakNet::TimeUS timeUS)
{
	Rupp::RuppInfo ruppInfo;
	BitStream b((unsigned char*)data, length, false);
	
	unsigned short headerLength = 0;
	Rupp::deserialize(ruppInfo, b, headerLength);
	return { headerLength, ruppInfo };
}
std::bitset<27> bitset_a("111100101100000100000000000");
std::bitset<6> bitset_b("101001");
void RakPeer::ProcessOfflineNetworkPacket(SystemAddress systemAddress, const char* data, const int length, RakPeer* rakPeer, RakNetSmartPtr<RakNetSocket> rakNetSocket, RakNet::TimeUS timeRead, RakNet::TimeUS timeUS, unsigned short ruppLength, std::string_view gameServiceToken)
{
	(void)timeRead;
	RakPeer::RemoteSystemStruct* remoteSystem;
	RakNet::Packet* packet;

	auto packetId = (unsigned char)data[0];
	if (packetId != ID_OPEN_CONNECTION_REPLY_1 && packetId != ID_OPEN_CONNECTION_REPLY_2 && packetId < bitset_a.size() && bitset_a.test(packetId))
	{
		RakNet::BitStream inBitStream((unsigned char*)data, length, false);
		inBitStream.IgnoreBytes(1);
		inBitStream.IgnoreBytes(16);
		if (packetId == ID_INCOMPATIBLE_PROTOCOL_VERSION) 
		{
			inBitStream.IgnoreBytes(1);
		}
		RakNetGUID guid;
		inBitStream.Read(guid);

		unsigned requestedConnectionQueueIndex = 0;
		rakPeer->requestedConnectionQueueMutex.Lock();
		while (requestedConnectionQueueIndex < rakPeer->requestedConnectionQueue.Size())
		{
			RequestedConnectionStruct* rcs;
			rcs = rakPeer->requestedConnectionQueue[requestedConnectionQueueIndex];
			if (rcs->actionToTake == RequestedConnectionStruct::CONNECT && rcs->systemAddress == systemAddress)
			{
				rakPeer->requestedConnectionQueue.RemoveAtIndex(requestedConnectionQueueIndex);
				RakNet::OP_DELETE(rcs, _FILE_AND_LINE_);
				rakPeer->requestedConnectionQueueMutex.Unlock();

				Packet* packet = rakPeer->AllocPacket(sizeof(char), _FILE_AND_LINE_);
				packet->data[0] = packetId;
				packet->bitSize = (sizeof(char) * 8);
				packet->systemAddress = systemAddress;
				rakPeer->AddPacketToProducer(packet);

				return;
			}
		}
		rakPeer->requestedConnectionQueueMutex.Unlock();
	}
	else
	{
		switch (packetId)
		{
		case ID_RBX_OPEN_REQUEST_1:
			rakPeer->processRbxOpenRequest1(data, length, systemAddress, rakNetSocket, ruppLength, timeUS);
			break;
		case ID_RBX_OPEN_REPLY_1:
			rakPeer->processRbxOpenReply1(data, length, systemAddress, rakNetSocket);
			break;
		case ID_RBX_OPEN_REQUEST_2:
			rakPeer->processRbxOpenRequest2(data, length, systemAddress, rakNetSocket, ruppLength, gameServiceToken, timeUS);
			break;
		case ID_RBX_OPEN_REPLY_2:
			rakPeer->processRbxOpenReply2(data, length, systemAddress, rakNetSocket, timeRead);
			break;
		}
	}
}

void RakPeer::sendRbxOpenError(unsigned char packetId, SystemAddress systemAddress, RakNetSmartPtr<RakNetSocket> rakNetSocket, RakNet::TimeUS timeUS, bool ruppFromServer)
{
	printf("WARNING: sendRbxOpenError not implemented\n");
}

bool RakPeer::processRbxOpenRequest1(const char* data, const int length, SystemAddress systemAddress, RakNetSmartPtr<RakNetSocket> rakNetSocket, unsigned short ruppLength, RakNet::TimeUS timeUS)
{
	// mtu?
	auto totalLength = length + ruppLength;
	if (length < 18 || totalLength + 40 < 0x240)
	{
		printf("RbxOpenRequest1 has incorrect size %d.\n", length);
		return false;
	}
	// client opted in to receiving Rupp headers
	auto ruppFromServer = data[18] != 0;
	if (data[17] != RAKNET_PROTOCOL_VERSION)
	{
		printf("RbxOpenRequest1 Incompatible Protocol\n");
		sendRbxOpenError(ID_INCOMPATIBLE_PROTOCOL_VERSION, systemAddress, rakNetSocket, timeUS, ruppFromServer);
		return false;
	}
	sendRbxOpenReply1(totalLength, systemAddress, rakNetSocket, timeUS, ruppFromServer);
	return true;
}

void RakPeer::sendRbxOpenReply1(const int totalLength, SystemAddress systemAddress, RakNetSmartPtr<RakNetSocket> rakNetSocket, RakNet::TimeUS timeUS, bool ruppFromServer)
{
	BitStream bitStream(28);
	if (ruppFromServer)
	{
		printf("WARNING: sending rupp headers not implemented\n");
	}
	bitStream.Write((unsigned char)ID_RBX_OPEN_REPLY_1);
	bitStream.WriteAlignedBytes((const unsigned char*)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
	bitStream.Write(GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
	bitStream.Write((unsigned char)0);
	bitStream.Write((unsigned short)(totalLength + 40));
	SocketLayer::SendTo(rakNetSocket->s, (char*)bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), systemAddress, rakNetSocket->remotePortRakNetWasStartedOn_PS3_PSP2, rakNetSocket->extraSocketOptions, _FILE_AND_LINE_);
}

bool RakPeer::processRbxOpenReply1(const char* data, const int length, SystemAddress systemAddress, RakNetSmartPtr<RakNetSocket> rakNetSocket)
{
	printf("WARNING: processRbxOpenReply1 not implemented\n");
	return false;
}

bool RakPeer::processRbxOpenRequest2(const char* data, const int length, SystemAddress systemAddress, RakNetSmartPtr<RakNetSocket> rakNetSocket, unsigned short ruppLength, std::string_view gameServiceToken, RakNet::TimeUS timeUS)
{
	auto totalLength = length + ruppLength;
	if (length < 107 || totalLength + 40 < 0x240)
	{
		printf("RbxOpenRequest2 has incorrect size %d.\n", length);
		return false;
	}
	BitStream bitStream((unsigned char*)data, length, false);
	bitStream.IgnoreBytes(17);
	// TODO: seems to be unused? breakpoint and check
	// maybe not used in studio?
	std::uint8_t unk0;
	bitStream.Read(unk0);
	// additional data, see crypto_aead_chacha20poly1305_ietf_decrypt
	std::uint8_t aadSize;
	bitStream.Read(aadSize);
	struct
	{
		std::uint8_t unkSize;
		std::uint8_t unk;
	} unk1;
	bitStream.Read(unk1);

	std::uint16_t version;
	bitStream.Read(version);

	std::array<std::uint8_t, 32> peerPublicKey;
	bitStream.ReadAlignedBytes(peerPublicKey.data(), peerPublicKey.size());

	std::uint8_t authVersion;
	bitStream.Read(authVersion);
	std::uint8_t preauthBlobSize;
	bitStream.Read(preauthBlobSize);
	std::string preauthBlob;
	if (preauthBlobSize)
	{
		bitStream.ReadAlignedBytes((unsigned char*)preauthBlob.data(), preauthBlobSize);
	}
	auto preauthResult = verifyPreauthMac(preauthBlob, authVersion);
	switch (preauthResult)
	{
	case PreauthResult::FailToVerify:
		return false;
	case PreauthResult::VerifiedFirst:
		printf("Preauth-Pass\n");
		break;
	case PreauthResult::VerifiedSecond:
		printf("Preauth-Failover\n");
		break;
	}

	if (aadSize != BITS_TO_BYTES(bitStream.GetReadOffset()) || aadSize < 0x35)
	{
		printf("RbxOpenRequest2 unexpected aad size %d.\n", length);
		return false;
	}

	unsigned remoteSystemIndex;
	RemoteSystemStruct* remoteSystem = nullptr;
	if (systemAddress != UNASSIGNED_SYSTEM_ADDRESS 
		&& (remoteSystemIndex = GetRemoteSystemIndex(systemAddress), remoteSystemIndex != -1) 
		&& remoteSystemList[remoteSystemIndex].isActive)
	{
		remoteSystem = &remoteSystemList[remoteSystemIndex];
		if (preauthResult == PreauthResult::Duplicate)
		{
			printf("Preauth-Drop\n");
		}
	}
	else
	{
		if (preauthResult == PreauthResult::Duplicate)
		{
			printf("Preauth-Dupe\n");
		}
		if (preauthKey.length())
		{
			printf("RbxOpenRequest2 mac was previously used but did not create active rss\n");
			return false;
		}
	}

	std::shared_ptr<RBX::Security::RakPeerCrypto> rbxSessionCrypto;
	if (remoteSystem)
	{
		rbxSessionCrypto = remoteSystem->reliabilityLayer.rbxSessionCrypto;
	}
	else
	{
		rbxSessionCrypto = std::make_shared<RBX::Security::RakPeerCrypto>();
		if (isRbxConnection != (version != 0))
		{
			printf("RbxOpenRequest2 key exchange version incorrect for connecting to %s server\n", isRbxConnection ? "Roblox" : "local");
		}
		auto [publicEarlyKey, secretEarlyKey] = RBX::Security::RakPeerCrypto::getServerKeyInfo(version);
		rbxSessionCrypto->initServer(publicEarlyKey, secretEarlyKey);
		rbxSessionCrypto->serverInitEarlySessionKeys(peerPublicKey);
	}

	if (!rbxSessionCrypto)
	{
		printf("RbxOpenRequest2 no session crypto\n");
		return false;
	}

	BitStream decryptedStream((unsigned char*)data, aadSize + unk1.unkSize + 28, false);
	if (!rbxSessionCrypto->earlyDecryptData(decryptedStream, aadSize))
	{
		printf("RbxOpenRequest2 decrypt failed for %s\n", systemAddress.ToString());
		return false;
	}

	printf("RbxOpenRequest2 not implemented\n");
	return false;
}

bool RakPeer::processRbxOpenReply2(const char* data, const int length, SystemAddress systemAddress, RakNetSmartPtr<RakNetSocket> rakNetSocket, RakNet::TimeUS timeRead)
{
	printf("WARNING: processRbxOpenReply2 not implemented\n");
	return false;
}

RakPeer::PreauthResult RakPeer::verifyPreauthMac(std::string_view preauthBlob, std::uint8_t authVersion)
{
	return PreauthResult::VerifiedFirst;
}

bool RakPeer::ProcessBannedPacket(SystemAddress systemAddress, RakPeer* rakPeer, RakNetSmartPtr<RakNet::RakNetSocket> rakNetSocket, BitStream& updateBitStream, RakNet::TimeUS timeUS)
{
	RakAssert(systemAddress.GetPort());
	char str1[64];
	systemAddress.ToString(false, str1);
	if (rakPeer->IsBanned(str1))
	{
		throw "todo";
		RakNet::BitStream bs;
		bs.Write((MessageID)ID_CONNECTION_BANNED);
		bs.WriteAlignedBytes((const unsigned char*)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
		bs.Write(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));

		unsigned i;
		SocketLayer::SendTo(rakNetSocket->s, (char*)bs.GetData(), bs.GetNumberOfBytesUsed(), systemAddress, rakNetSocket->remotePortRakNetWasStartedOn_PS3_PSP2, rakNetSocket->extraSocketOptions, _FILE_AND_LINE_);

		return true;
	}
	return false;
}

void RakPeer::ProcessBufferedCommands(BitStream& updateBitStream, RakNet::TimeUS timeUS, RakNet::TimeMS timeMS)
{
	BufferedCommandStruct* bcs;
	while ((bcs = bufferedCommands.PopInaccurate()) != 0)
	{
		if (bcs->command == BufferedCommandStruct::BCS_SEND)
		{
			// GetTime is a very slow call so do it once and as late as possible
			if (timeUS == 0)
			{
				timeUS = RakNet::GetTimeUS();
				timeMS = (RakNet::TimeMS)(timeUS / (RakNet::TimeUS)1000);
			}

			bool callerDataAllocationUsed = SendImmediate((char*)bcs->data, bcs->numberOfBitsToSend, bcs->priority, bcs->reliability, bcs->orderingChannel, bcs->systemIdentifier, bcs->broadcast, true, timeUS, bcs->receipt);
			if (callerDataAllocationUsed == false)
				rakFree_Ex(bcs->data, _FILE_AND_LINE_);

			// Set the new connection state AFTER we call sendImmediate in case we are setting it to a disconnection state, which does not allow further sends
			if (bcs->connectionMode != RemoteSystemStruct::NO_ACTION)
			{
				RakPeer::RemoteSystemStruct* remoteSystem = GetRemoteSystem(bcs->systemIdentifier, true, true);
				if (remoteSystem)
					remoteSystem->connectMode = bcs->connectionMode;
			}
		}
		else if (bcs->command == BufferedCommandStruct::BCS_CLOSE_CONNECTION)
		{
			CloseConnectionInternal(bcs->systemIdentifier, false, true, bcs->orderingChannel, bcs->priority);
		}
		else if (bcs->command == BufferedCommandStruct::BCS_CHANGE_SYSTEM_ADDRESS)
		{
			// Reroute
			RakPeer::RemoteSystemStruct* rssFromGuid = GetRemoteSystem(bcs->systemIdentifier.rakNetGuid, true, true);
			if (rssFromGuid != 0)
			{
				unsigned int existingSystemIndex = GetRemoteSystemIndex(rssFromGuid->systemAddress);
				ReferenceRemoteSystem(bcs->systemIdentifier.systemAddress, existingSystemIndex);
			}
		}
		else if (bcs->command == BufferedCommandStruct::BCS_GET_SOCKET)
		{
			SocketQueryOutput* sqo;
			if (bcs->systemIdentifier.IsUndefined())
			{
				sqo = socketQueryOutput.Allocate(_FILE_AND_LINE_);
				sqo->sockets = socketList;
				socketQueryOutput.Push(sqo);
			}
			else
			{
				RakPeer::RemoteSystemStruct* remoteSystem = GetRemoteSystem(bcs->systemIdentifier, true, true);
				sqo = socketQueryOutput.Allocate(_FILE_AND_LINE_);

				sqo->sockets.Clear(false, _FILE_AND_LINE_);
				if (remoteSystem)
				{
					sqo->sockets.Push(remoteSystem->rakNetSocket, _FILE_AND_LINE_);
				}
				else
				{
					// Leave empty smart pointer
				}
				socketQueryOutput.Push(sqo);
			}

		}

#ifdef _DEBUG
		bcs->data = 0;
#endif

		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
	}
}

void RakPeer::ProcessBufferedPackets(BitStream& updateBitStream, RakNet::TimeUS timeUS)
{
	unsigned int socketListIndex;
	RakPeer::RecvFromStruct* recvFromStruct;
	while ((recvFromStruct = bufferedPackets.PopInaccurate()) != 0)
	{
		for (socketListIndex = 0; socketListIndex < socketList.Size(); socketListIndex++)
		{
			if ((SOCKET)socketList[socketListIndex]->s == recvFromStruct->s)
				break;
		}
		if (socketListIndex != socketList.Size()) {
			auto systemAddress = recvFromStruct->systemAddress;
			auto data = recvFromStruct->data;
			auto length = recvFromStruct->bytesRead;
			auto rakNetSocket = socketList[socketListIndex];
			auto timeRead = recvFromStruct->timeRead;

			auto [ruppHeaderLength, ruppInfo] = ReadRuppHeader(data, length, this, timeUS);
			if (!ProcessBannedPacket(systemAddress, this, rakNetSocket, updateBitStream, timeRead)) {
				//data += ruppHeaderLength;
				//length -= ruppHeaderLength;
				// The reason for all this is that the reliability layer has no way to tell between offline messages that arrived late for a player that is now connected,
				// and a regular encoding. So I insert OFFLINE_MESSAGE_DATA_ID into the stream, the encoding of which is essentially impossible to hit by chance
				bool isOfflineMessage;
				auto packetId = (unsigned char)data[0];
				if (length <= 2)
				{
					isOfflineMessage = true;
				}
				else if (packetId < bitset_a.size() && bitset_a.test(packetId)
					|| (packetId - ID_RBX_OPEN_REQUEST_2) < bitset_b.size() && bitset_b.test(packetId - ID_RBX_OPEN_REQUEST_2))
				{
					isOfflineMessage = true;
				}
				else if ((packetId == ID_INCOMPATIBLE_PROTOCOL_VERSION &&
					(size_t)length == sizeof(MessageID) * 2 + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID)))
				{
					isOfflineMessage = memcmp(data + sizeof(MessageID) * 2, OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID)) == 0;
				}
				else
				{
					isOfflineMessage = false;
				}

				if (isOfflineMessage)
				{
					ProcessOfflineNetworkPacket(systemAddress, data, length, this, rakNetSocket, timeRead, timeUS, ruppHeaderLength, "");
				}
				else
				{
					RakPeer::RemoteSystemStruct* remoteSystem;

					// See if this datagram came from a connected system
					remoteSystem = GetRemoteSystemFromSystemAddress(systemAddress, true, true);
					if (remoteSystem)
					{
						// Handle regular incoming data
						// HandleSocketReceiveFromConnectedPlayer is only safe to be called from the same thread as Update, which is this thread
						if (isOfflineMessage == false)
						{
							remoteSystem->reliabilityLayer.HandleSocketReceiveFromConnectedPlayer(
								data, length, systemAddress, remoteSystem->MTUSize,
								rakNetSocket->s, &rnr, rakNetSocket->remotePortRakNetWasStartedOn_PS3_PSP2, rakNetSocket->extraSocketOptions, timeRead, updateBitStream);
						}
					}
				}
			}
		}
		bufferedPackets.Deallocate(recvFromStruct, _FILE_AND_LINE_);
	}
}
void RakPeer::HandleRequestedConnectionQueue(RakNet::TimeUS timeUS, RakNet::TimeMS timeMS)
{
	bool condition1, condition2;
	unsigned requestedConnectionQueueIndex = 0;
	requestedConnectionQueueMutex.Lock();
	while (requestedConnectionQueueIndex < requestedConnectionQueue.Size())
	{
		RequestedConnectionStruct* rcs;
		rcs = requestedConnectionQueue[requestedConnectionQueueIndex];
		requestedConnectionQueueMutex.Unlock();
		if (rcs->nextRequestTime < timeMS)
		{
			condition1 = rcs->requestsMade == rcs->sendConnectionAttemptCount + 1;
			condition2 = (bool)((rcs->systemAddress == UNASSIGNED_SYSTEM_ADDRESS) == 1);
			// If too many requests made or a hole then remove this if possible, otherwise invalidate it
			if (condition1 || condition2)
			{
				if (rcs->data)
				{
					rakFree_Ex(rcs->data, _FILE_AND_LINE_);
					rcs->data = 0;
				}

				if (condition1 && !condition2 && rcs->actionToTake == RequestedConnectionStruct::CONNECT)
				{
					// Tell user of connection attempt failed
					Packet* packet = AllocPacket(sizeof(char), _FILE_AND_LINE_);
					packet->data[0] = ID_CONNECTION_ATTEMPT_FAILED; // Attempted a connection and couldn't
					packet->bitSize = (sizeof(char) * 8);
					packet->systemAddress = rcs->systemAddress;
					AddPacketToProducer(packet);
				}

				RakNet::OP_DELETE(rcs, _FILE_AND_LINE_);

				requestedConnectionQueueMutex.Lock();
				for (unsigned int k = 0; k < requestedConnectionQueue.Size(); k++)
				{
					if (requestedConnectionQueue[k] == rcs)
					{
						requestedConnectionQueue.RemoveAtIndex(k);
						break;
					}
				}
				requestedConnectionQueueMutex.Unlock();
			}
			else
			{

				int MTUSizeIndex = rcs->requestsMade / (rcs->sendConnectionAttemptCount / NUM_MTU_SIZES);
				if (MTUSizeIndex >= NUM_MTU_SIZES)
					MTUSizeIndex = NUM_MTU_SIZES - 1;
				rcs->requestsMade++;
				rcs->nextRequestTime = timeMS + rcs->timeBetweenSendConnectionAttemptsMS;

				RakNet::BitStream bitStream;
				bitStream.Write((MessageID)ID_OPEN_CONNECTION_REQUEST_1);
				bitStream.WriteAlignedBytes((const unsigned char*)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
				bitStream.Write((MessageID)RAKNET_PROTOCOL_VERSION);
				bitStream.PadWithZeroToByteLength(mtuSizes[MTUSizeIndex] - UDP_HEADER_SIZE);

				char str[256];
				rcs->systemAddress.ToString(true, str);

				if (rcs->socket.IsNull())
				{
					rcs->systemAddress.FixForIPVersion(socketList[rcs->socketIndex]->boundAddress);
					SocketLayer::SetDoNotFragment(socketList[rcs->socketIndex]->s, 1, socketList[rcs->socketIndex]->boundAddress.GetIPPROTO());
					RakNet::Time sendToStart = RakNet::GetTime();
					if (SocketLayer::SendTo(socketList[rcs->socketIndex]->s, (const char*)bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), rcs->systemAddress, socketList[rcs->socketIndex]->remotePortRakNetWasStartedOn_PS3_PSP2, socketList[rcs->socketIndex]->extraSocketOptions, _FILE_AND_LINE_) == -10040)
					{
						// Don't use this MTU size again
						rcs->requestsMade = (unsigned char)((MTUSizeIndex + 1) * (rcs->sendConnectionAttemptCount / NUM_MTU_SIZES));
						rcs->nextRequestTime = timeMS;
					}
					else
					{
						RakNet::Time sendToEnd = RakNet::GetTime();
						if (sendToEnd - sendToStart > 100)
						{
							// Drop to lowest MTU
							int lowestMtuIndex = rcs->sendConnectionAttemptCount / NUM_MTU_SIZES * (NUM_MTU_SIZES - 1);
							if (lowestMtuIndex > rcs->requestsMade)
							{
								rcs->requestsMade = (unsigned char)lowestMtuIndex;
								rcs->nextRequestTime = timeMS;
							}
							else
								rcs->requestsMade = (unsigned char)(rcs->sendConnectionAttemptCount + 1);
						}
					}
					SocketLayer::SetDoNotFragment(socketList[rcs->socketIndex]->s, 0, socketList[rcs->socketIndex]->boundAddress.GetIPPROTO());
				}
				else
				{
					rcs->systemAddress.FixForIPVersion(rcs->socket->boundAddress);
					SocketLayer::SetDoNotFragment(rcs->socket->s, 1, rcs->socket->boundAddress.GetIPPROTO());
					RakNet::Time sendToStart = RakNet::GetTime();
					if (SocketLayer::SendTo(rcs->socket->s, (const char*)bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), rcs->systemAddress, socketList[rcs->socketIndex]->remotePortRakNetWasStartedOn_PS3_PSP2, socketList[rcs->socketIndex]->extraSocketOptions, _FILE_AND_LINE_) == -10040)
					{
						// Don't use this MTU size again
						rcs->requestsMade = (unsigned char)((MTUSizeIndex + 1) * (rcs->sendConnectionAttemptCount / NUM_MTU_SIZES));
						rcs->nextRequestTime = timeMS;
					}
					else
					{
						RakNet::Time sendToEnd = RakNet::GetTime();
						if (sendToEnd - sendToStart > 100)
						{
							// Drop to lowest MTU
							int lowestMtuIndex = rcs->sendConnectionAttemptCount / NUM_MTU_SIZES * (NUM_MTU_SIZES - 1);
							if (lowestMtuIndex > rcs->requestsMade)
							{
								rcs->requestsMade = (unsigned char)lowestMtuIndex;
								rcs->nextRequestTime = timeMS;
							}
							else
								rcs->requestsMade = (unsigned char)rcs->sendConnectionAttemptCount + 1;
						}
					}
					SocketLayer::SetDoNotFragment(rcs->socket->s, 0, rcs->socket->boundAddress.GetIPPROTO());
				}

				requestedConnectionQueueIndex++;
			}
		}
		else
			requestedConnectionQueueIndex++;

		requestedConnectionQueueMutex.Lock();
	}
	requestedConnectionQueueMutex.Unlock();
}
void RakPeer::HandleActiveSystemList(BitStream& updateBitStream, RakNet::TimeUS timeUS, RakNet::TimeMS timeMS)
{
	// remoteSystemList in network thread

////// ROBLOX:
	unsigned int count = 0;
	bool newStartingIndexAssigned = false;
	unsigned int activeSystemListIndex = startingActiveSystemListIndex;

	// ROBLOX:
	while (count < activeSystemListSize)
	{
		// ROBLOX:
		if ((activeSystemListIndex + 1) >= activeSystemListSize)
			activeSystemListIndex = -1;

		count++;
		activeSystemListIndex++;
		// END ROBLOX

			// Found an active remote system
		RakPeer::RemoteSystemStruct* remoteSystem = activeSystemList[activeSystemListIndex];
		SystemAddress systemAddress = remoteSystem->systemAddress;
		RakAssert(systemAddress != UNASSIGNED_SYSTEM_ADDRESS);
		// Update is only safe to call from the same thread that calls HandleSocketReceiveFromConnectedPlayer,
		// which is this thread

		if (timeUS == 0)
		{
			timeUS = RakNet::GetTimeUS();
			timeMS = (RakNet::TimeMS)(timeUS / (RakNet::TimeUS)1000);
			//RAKNET_DEBUG_PRINTF("timeUS = %I64i timeMS=%i\n", timeUS, timeMS);
		}


		if (timeMS > remoteSystem->lastReliableSend && timeMS - remoteSystem->lastReliableSend > remoteSystem->reliabilityLayer.GetTimeoutTime() / 2 && remoteSystem->connectMode == RemoteSystemStruct::CONNECTED)
		{
			// If no reliable packets are waiting for an ack, do a one byte reliable send so that disconnections are noticed
			RakNetStatistics rakNetStatistics;
			RakNetStatistics* rnss = remoteSystem->reliabilityLayer.GetStatistics(&rakNetStatistics);
			if (rnss->messagesInResendBuffer == 0)
			{
				PingInternal(systemAddress, true, RELIABLE);

				//remoteSystem->lastReliableSend=timeMS+remoteSystem->reliabilityLayer.GetTimeoutTime();
				remoteSystem->lastReliableSend = timeMS;
			}
		}

		// Roblox: bool bufferEmpty = 
		bool bufferEmpty = remoteSystem->reliabilityLayer.Update(remoteSystem->rakNetSocket->s, systemAddress, remoteSystem->MTUSize, timeUS, maxOutgoingBPS, &rnr, remoteSystem->rakNetSocket->remotePortRakNetWasStartedOn_PS3_PSP2, remoteSystem->rakNetSocket->extraSocketOptions, updateBitStream); // systemAddress only used for the internet simulator test

		// Check for failure conditions
		if (remoteSystem->reliabilityLayer.IsDeadConnection() ||
			((remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ASAP || remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY) && remoteSystem->reliabilityLayer.IsOutgoingDataWaiting() == false) ||
			(remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ON_NO_ACK && (remoteSystem->reliabilityLayer.AreAcksWaiting() == false || remoteSystem->reliabilityLayer.AckTimeout(timeMS) == true)) ||
			((
				(remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION ||
					remoteSystem->connectMode == RemoteSystemStruct::HANDLING_CONNECTION_REQUEST ||
					remoteSystem->connectMode == RemoteSystemStruct::UNVERIFIED_SENDER)
				&& timeMS > remoteSystem->connectionTime && timeMS - remoteSystem->connectionTime > 10000))
			)
		{
			//	RAKNET_DEBUG_PRINTF("timeMS=%i remoteSystem->connectionTime=%i\n", timeMS, remoteSystem->connectionTime );

				// Failed.  Inform the user?
				// TODO - RakNet 4.0 - Return a different message identifier for DISCONNECT_ASAP_SILENTLY and DISCONNECT_ASAP than for DISCONNECT_ON_NO_ACK
				// The first two mean we called CloseConnection(), the last means the other system sent us ID_DISCONNECTION_NOTIFICATION
			if (remoteSystem->connectMode == RemoteSystemStruct::CONNECTED || remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION
				|| remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ASAP || remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ON_NO_ACK)
			{
				//					RakNet::BitStream undeliveredMessages;
				//					remoteSystem->reliabilityLayer.GetUndeliveredMessages(&undeliveredMessages,remoteSystem->MTUSize);

				//					packet=AllocPacket(sizeof( char ) + undeliveredMessages.GetNumberOfBytesUsed());
				Packet* packet = AllocPacket(sizeof(char), _FILE_AND_LINE_);
				if (remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION)
					packet->data[0] = ID_CONNECTION_ATTEMPT_FAILED; // Attempted a connection and couldn't
				else if (remoteSystem->connectMode == RemoteSystemStruct::CONNECTED)
					packet->data[0] = ID_CONNECTION_LOST; // DeadConnection
				else
					packet->data[0] = ID_DISCONNECTION_NOTIFICATION; // DeadConnection

				//					memcpy(packet->data+1, undeliveredMessages.GetData(), undeliveredMessages.GetNumberOfBytesUsed());

				packet->guid = remoteSystem->guid;
				packet->systemAddress = systemAddress;
				packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
				packet->guid.systemIndex = packet->systemAddress.systemIndex;

				AddPacketToProducer(packet);
			}
			// else connection shutting down, don't bother telling the user

#ifdef _DO_PRINTF
			RAKNET_DEBUG_PRINTF("Connection dropped for player %i:%i\n", systemAddress);
#endif
			CloseConnectionInternal(systemAddress, false, true, 0, LOW_PRIORITY);
			continue;
		}

		///// Roblox:
		if (!bufferEmpty && !newStartingIndexAssigned)
		{
			if (startingActiveSystemListIndex != activeSystemListIndex)
			{
				startingActiveSystemListIndex = activeSystemListIndex;
				newStartingIndexAssigned = true;
			}
		}
		//// End Roblox

		// Ping this guy if it is time to do so
		if (remoteSystem->connectMode == RemoteSystemStruct::CONNECTED && timeMS > remoteSystem->nextPingTime && (occasionalPing || remoteSystem->lowestPing == (unsigned short)-1))
		{
			remoteSystem->nextPingTime = timeMS + 5000;
			PingInternal(systemAddress, true, UNRELIABLE);

			// Update again immediately after this tick so the ping goes out right away
			quitAndDataEvents.SetEvent();
		}

		// Find whoever has the lowest player ID
		//if (systemAddress < authoritativeClientSystemAddress)
		// authoritativeClientSystemAddress=systemAddress;

		// Does the reliability layer have any packets waiting for us?
		// To be thread safe, this has to be called in the same thread as HandleSocketReceiveFromConnectedPlayer
		unsigned char* data;
		BitSize_t bitSize = remoteSystem->reliabilityLayer.Receive(&data);

		while (bitSize > 0)
		{
			// These types are for internal use and should never arrive from a network packet
			if (data[0] == ID_CONNECTION_ATTEMPT_FAILED)
			{
				RakAssert(0);
				bitSize = 0;
				continue;
			}

			// Fast and easy - just use the data that was returned
			unsigned int byteSize = (unsigned int)BITS_TO_BYTES(bitSize);

			// For unknown senders we only accept a few specific packets
			if (remoteSystem->connectMode == RemoteSystemStruct::UNVERIFIED_SENDER)
			{
				if ((unsigned char)(data)[0] == ID_CONNECTION_REQUEST)
				{
					ParseConnectionRequestPacket(remoteSystem, systemAddress, (const char*)data, byteSize);
					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else
				{
					CloseConnectionInternal(systemAddress, false, true, 0, LOW_PRIORITY);
#ifdef _DO_PRINTF
					RAKNET_DEBUG_PRINTF("Temporarily banning %i:%i for sending nonsense data\n", systemAddress);
#endif

					char str1[64];
					systemAddress.ToString(false, str1);
					AddToBanList(str1, remoteSystem->reliabilityLayer.GetTimeoutTime());


					rakFree_Ex(data, _FILE_AND_LINE_);
				}
			}
			else
			{
				// However, if we are connected we still take a connection request in case both systems are trying to connect to each other
				// at the same time
				if ((unsigned char)(data)[0] == ID_CONNECTION_REQUEST)
				{
					// 04/27/06 This is wrong.  With cross connections, we can both have initiated the connection are in state REQUESTED_CONNECTION
					// 04/28/06 Downgrading connections from connected will close the connection due to security at ((remoteSystem->connectMode!=RemoteSystemStruct::CONNECTED && time > remoteSystem->connectionTime && time - remoteSystem->connectionTime > 10000))
					if (remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION)
					{
						ParseConnectionRequestPacket(remoteSystem, systemAddress, (const char*)data, byteSize);
					}
					else
					{

						RakNet::BitStream bs((unsigned char*)data, byteSize, false);
						bs.IgnoreBytes(sizeof(MessageID));
						bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
						bs.IgnoreBytes(RakNetGUID::size());
						RakNet::Time incomingTimestamp;
						bs.Read(incomingTimestamp);

						// Got a connection request message from someone we are already connected to. Just reply normally.
						// This can happen due to race conditions with the fully connected mesh
						OnConnectionRequest(remoteSystem, incomingTimestamp);
					}
					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((unsigned char)data[0] == ID_NEW_INCOMING_CONNECTION && byteSize > sizeof(unsigned char) + sizeof(unsigned int) + sizeof(unsigned short) + sizeof(RakNet::Time) * 2)
				{
					if (remoteSystem->connectMode == RemoteSystemStruct::HANDLING_CONNECTION_REQUEST)
					{
						remoteSystem->connectMode = RemoteSystemStruct::CONNECTED;
						PingInternal(systemAddress, true, UNRELIABLE);

						// Update again immediately after this tick so the ping goes out right away
						quitAndDataEvents.SetEvent();

						RakNet::BitStream inBitStream((unsigned char*)data, byteSize, false);
						SystemAddress bsSystemAddress;

						inBitStream.IgnoreBits(8);
						inBitStream.Read(bsSystemAddress);
						for (unsigned int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
							inBitStream.Read(remoteSystem->theirInternalSystemAddress[i]);

						RakNet::Time sendPingTime, sendPongTime;
						inBitStream.Read(sendPingTime);
						inBitStream.Read(sendPongTime);
						OnConnectedPong(sendPingTime, sendPongTime, remoteSystem);

						// Overwrite the data in the packet
						//					NewIncomingConnectionStruct newIncomingConnectionStruct;
						//					RakNet::BitStream nICS_BS( data, NewIncomingConnectionStruct_Size, false );
						//					newIncomingConnectionStruct.Deserialize( nICS_BS );

						remoteSystem->myExternalSystemAddress = bsSystemAddress;
						firstExternalID = bsSystemAddress;
						firstExternalID.debugPort = ntohs(firstExternalID.address.addr4.sin_port);

						// Send this info down to the game
						Packet* packet = AllocPacket(byteSize, data, _FILE_AND_LINE_);
						packet->bitSize = bitSize;
						packet->systemAddress = systemAddress;
						packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
						packet->guid = remoteSystem->guid;
						packet->guid.systemIndex = packet->systemAddress.systemIndex;
						AddPacketToProducer(packet);
					}
					else
					{
						// Send to game even if already connected. This could happen when connecting to 127.0.0.1
						// Ignore, already connected
					//	rakFree_Ex(data, _FILE_AND_LINE_ );
					}
				}
				else if ((unsigned char)data[0] == ID_CONNECTED_PONG && byteSize == sizeof(unsigned char) + sizeof(RakNet::Time) * 2)
				{
					RakNet::Time sendPingTime, sendPongTime;

					// Copy into the ping times array the current time - the value returned
					// First extract the sent ping
					RakNet::BitStream inBitStream((unsigned char*)data, byteSize, false);
					//PingStruct ps;
					//ps.Deserialize(psBS);
					inBitStream.IgnoreBits(8);
					inBitStream.Read(sendPingTime);
					inBitStream.Read(sendPongTime);

					OnConnectedPong(sendPingTime, sendPongTime, remoteSystem);

					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((unsigned char)data[0] == ID_CONNECTED_PING && byteSize == sizeof(unsigned char) + sizeof(RakNet::Time))
				{
					RakNet::BitStream inBitStream((unsigned char*)data, byteSize, false);
					inBitStream.IgnoreBits(8);
					RakNet::Time sendPingTime;
					inBitStream.Read(sendPingTime);

					RakNet::BitStream outBitStream;
					outBitStream.Write((MessageID)ID_CONNECTED_PONG);
					outBitStream.Write(sendPingTime);
					outBitStream.Write(RakNet::GetTime());
					SendImmediate((char*)outBitStream.GetData(), outBitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, UNRELIABLE, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);

					// Update again immediately after this tick so the ping goes out right away
					quitAndDataEvents.SetEvent();

					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((unsigned char)data[0] == ID_DISCONNECTION_NOTIFICATION)
				{
					// We shouldn't close the connection immediately because we need to ack the ID_DISCONNECTION_NOTIFICATION
					remoteSystem->connectMode = RemoteSystemStruct::DISCONNECT_ON_NO_ACK;
					rakFree_Ex(data, _FILE_AND_LINE_);

					//	AddPacketToProducer(packet);
				}
				else if ((unsigned char)(data)[0] == ID_DETECT_LOST_CONNECTIONS && byteSize == sizeof(unsigned char))
				{
					// Do nothing
					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((unsigned char)(data)[0] == ID_INVALID_PASSWORD)
				{
					if (remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION)
					{
						Packet* packet = AllocPacket(byteSize, data, _FILE_AND_LINE_);
						packet->bitSize = bitSize;
						packet->systemAddress = systemAddress;
						packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
						packet->guid = remoteSystem->guid;
						packet->guid.systemIndex = packet->systemAddress.systemIndex;
						AddPacketToProducer(packet);

						remoteSystem->connectMode = RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
					}
					else
					{
						rakFree_Ex(data, _FILE_AND_LINE_);
					}
				}
				else if ((unsigned char)(data)[0] == ID_CONNECTION_REQUEST_ACCEPTED)
				{
					if (byteSize > sizeof(MessageID) + sizeof(unsigned int) + sizeof(unsigned short) + sizeof(SystemIndex) + sizeof(RakNet::Time) * 2)
					{
						// Make sure this connection accept is from someone we wanted to connect to
						bool allowConnection, alreadyConnected;

						if (remoteSystem->connectMode == RemoteSystemStruct::HANDLING_CONNECTION_REQUEST ||
							remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION ||
							allowConnectionResponseIPMigration)
							allowConnection = true;
						else
							allowConnection = false;

						if (remoteSystem->connectMode == RemoteSystemStruct::HANDLING_CONNECTION_REQUEST)
							alreadyConnected = true;
						else
							alreadyConnected = false;

						if (allowConnection)
						{
							SystemAddress externalID;
							SystemIndex systemIndex;
							//								SystemAddress internalID;

							RakNet::BitStream inBitStream((unsigned char*)data, byteSize, false);
							inBitStream.IgnoreBits(8);
							//	inBitStream.Read(remotePort);
							inBitStream.Read(externalID);
							inBitStream.Read(systemIndex);
							for (unsigned int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
								inBitStream.Read(remoteSystem->theirInternalSystemAddress[i]);

							RakNet::Time sendPingTime, sendPongTime;
							inBitStream.Read(sendPingTime);
							inBitStream.Read(sendPongTime);
							OnConnectedPong(sendPingTime, sendPongTime, remoteSystem);

							// Find a free remote system struct to use
							//						RakNet::BitStream casBitS(data, byteSize, false);
							//						ConnectionAcceptStruct cas;
							//						cas.Deserialize(casBitS);
							//	systemAddress.GetPort() = remotePort;

							// The remote system told us our external IP, so save it
							remoteSystem->myExternalSystemAddress = externalID;
							remoteSystem->connectMode = RemoteSystemStruct::CONNECTED;

							firstExternalID = externalID;
							firstExternalID.debugPort = ntohs(firstExternalID.address.addr4.sin_port);

							// Send the connection request complete to the game
							Packet* packet = AllocPacket(byteSize, data, _FILE_AND_LINE_);
							packet->bitSize = byteSize * 8;
							packet->systemAddress = systemAddress;
							packet->systemAddress.systemIndex = (SystemIndex)GetIndexFromSystemAddress(systemAddress, true);
							packet->guid = remoteSystem->guid;
							packet->guid.systemIndex = packet->systemAddress.systemIndex;
							AddPacketToProducer(packet);

							RakNet::BitStream outBitStream;
							outBitStream.Write((MessageID)ID_NEW_INCOMING_CONNECTION);
							outBitStream.Write(systemAddress);
							for (unsigned int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
								outBitStream.Write(ipList[i]);
							outBitStream.Write(sendPongTime);
							outBitStream.Write(RakNet::GetTime());


							// We turned on encryption with SetEncryptionKey.  This pads packets to up to a multiple of 16 bytes.
							// As soon as a multiple of 16 byte packet arrives on the remote system, we will turn on AES.  This works because all encrypted packets are multiples of 16 and the
							// packets I happen to be sending before this are not a multiple of 16 bytes.  Otherwise there is no way to know if a packet that arrived is
							// encrypted or not so the other side won't know to turn on encryption or not.
							RakAssert((outBitStream.GetNumberOfBytesUsed() & 15) != 0);
							SendImmediate((char*)outBitStream.GetData(), outBitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, RELIABLE_ORDERED, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);

							if (alreadyConnected == false)
							{
								PingInternal(systemAddress, true, UNRELIABLE);
							}
						}
						else
						{
							// Ignore, already connected
							rakFree_Ex(data, _FILE_AND_LINE_);
						}
					}
					else
					{
						// Version mismatch error?
						RakAssert(0);
						rakFree_Ex(data, _FILE_AND_LINE_);
					}
				}
				else
				{
					// What do I do if I get a message from a system, before I am fully connected?
					// I can either ignore it or give it to the user
					// It seems like giving it to the user is a better option
					if ((data[0] >= (MessageID)ID_TIMESTAMP || data[0] == ID_SND_RECEIPT_ACKED || data[0] == ID_SND_RECEIPT_LOSS) &&
						remoteSystem->isActive
						)
					{
						Packet* packet = AllocPacket(byteSize, data, _FILE_AND_LINE_);
						packet->bitSize = bitSize;
						packet->systemAddress = systemAddress;
						packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
						packet->guid = remoteSystem->guid;
						packet->guid.systemIndex = packet->systemAddress.systemIndex;
						AddPacketToProducer(packet);
					}
					else
					{
						rakFree_Ex(data, _FILE_AND_LINE_);
					}
				}
			}

			// Does the reliability layer have any more packets waiting for us?
			// To be thread safe, this has to be called in the same thread as HandleSocketReceiveFromConnectedPlayer
			bitSize = remoteSystem->reliabilityLayer.Receive(&data);
		}

	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::PingInternal( const SystemAddress target, bool performImmediate, PacketReliability reliability )
{
	if ( IsActive() == false )
		return ;

	RakNet::BitStream bitStream(sizeof(unsigned char)+sizeof(RakNet::Time));
	bitStream.Write((MessageID)ID_CONNECTED_PING);
	bitStream.Write(RakNet::GetTime());
	if (performImmediate)
		SendImmediate( (char*)bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, reliability, 0, target, false, false, RakNet::GetTimeUS(), 0 );
	else
		Send( &bitStream, IMMEDIATE_PRIORITY, reliability, 0, target, false );
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::CloseConnectionInternal( const AddressOrGUID& systemIdentifier, bool sendDisconnectionNotification, bool performImmediate, unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority )
{
#ifdef _DEBUG
	RakAssert(orderingChannel < 32);
#endif

	if (systemIdentifier.IsUndefined())
		return;

	if ( remoteSystemList == 0 || endThreads == true )
		return;

	SystemAddress target;
	if (systemIdentifier.systemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		target=systemIdentifier.systemAddress;
	}
	else
	{
		target=GetSystemAddressFromGuid(systemIdentifier.rakNetGuid);
	}

	if (target!=UNASSIGNED_SYSTEM_ADDRESS && performImmediate)
		target.FixForIPVersion(socketList[0]->boundAddress);

	if (sendDisconnectionNotification)
	{
		NotifyAndFlagForShutdown(target, performImmediate, orderingChannel, disconnectionNotificationPriority);
	}
	else
	{
		if (performImmediate)
		{
			unsigned int index = GetRemoteSystemIndex(target);
			if (index!=(unsigned int) -1)
			{
				if ( remoteSystemList[index].isActive )
				{
					RemoveFromActiveSystemList(target);

					// Found the index to stop
					remoteSystemList[index].isActive = false;

					remoteSystemList[index].guid=UNASSIGNED_RAKNET_GUID;

					// Reserve this reliability layer for ourselves
					//remoteSystemList[ remoteSystemLookup[index].index ].systemAddress = UNASSIGNED_SYSTEM_ADDRESS;

					// Clear any remaining messages
					remoteSystemList[index].reliabilityLayer.Reset(false, remoteSystemList[index].MTUSize, false);

					// Not using this socket
					remoteSystemList[index].rakNetSocket.SetNull();
				}
			}
		}
		else
		{
			BufferedCommandStruct *bcs;
			bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
			bcs->command=BufferedCommandStruct::BCS_CLOSE_CONNECTION;
			bcs->systemIdentifier=target;
			bcs->data=0;
			bcs->orderingChannel=orderingChannel;
			bcs->priority=disconnectionNotificationPriority;
			bufferedCommands.Push(bcs);
		}
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SendBuffered( const char *data, BitSize_t numberOfBitsToSend, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, RemoteSystemStruct::ConnectMode connectionMode, uint32_t receipt )
{
	BufferedCommandStruct *bcs;

	bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
	bcs->data = (char*) rakMalloc_Ex( (size_t) BITS_TO_BYTES(numberOfBitsToSend), _FILE_AND_LINE_ ); // Making a copy doesn't lose efficiency because I tell the reliability layer to use this allocation for its own copy
	if (bcs->data==0)
	{
		notifyOutOfMemory(_FILE_AND_LINE_);
		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
		return;
	}
	memcpy(bcs->data, data, (size_t) BITS_TO_BYTES(numberOfBitsToSend));
	bcs->numberOfBitsToSend=numberOfBitsToSend;
	bcs->priority=priority;
	bcs->reliability=reliability;
	bcs->orderingChannel=orderingChannel;
	bcs->systemIdentifier=systemIdentifier;
	bcs->broadcast=broadcast;
	bcs->connectionMode=connectionMode;
	bcs->receipt=receipt;
	bcs->command=BufferedCommandStruct::BCS_SEND;
	bufferedCommands.Push(bcs);

	if (priority==IMMEDIATE_PRIORITY)
	{
		// Forces pending sends to go out now, rather than waiting to the next update interval
		quitAndDataEvents.SetEvent();
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SendBufferedList( const char **data, const int *lengths, const int numParameters, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, RemoteSystemStruct::ConnectMode connectionMode, uint32_t receipt )
{
	BufferedCommandStruct *bcs;
	unsigned int totalLength=0;
	unsigned int lengthOffset;
	int i;
	for (i=0; i < numParameters; i++)
	{
		if (lengths[i]>0)
			totalLength+=lengths[i];
	}
	if (totalLength==0)
		return;

	char *dataAggregate;
	dataAggregate = (char*) rakMalloc_Ex( (size_t) totalLength, _FILE_AND_LINE_ ); // Making a copy doesn't lose efficiency because I tell the reliability layer to use this allocation for its own copy
	if (dataAggregate==0)
	{
		notifyOutOfMemory(_FILE_AND_LINE_);
		return;
	}
	for (i=0, lengthOffset=0; i < numParameters; i++)
	{
		if (lengths[i]>0)
		{
			memcpy(dataAggregate+lengthOffset, data[i], lengths[i]);
			lengthOffset+=lengths[i];
		}
	}

	if (broadcast==false && IsLoopbackAddress(systemIdentifier,true))
	{
		SendLoopback(dataAggregate,totalLength);
		rakFree_Ex(dataAggregate,_FILE_AND_LINE_);
		return;
	}

	bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
	bcs->data = dataAggregate;
	bcs->numberOfBitsToSend=BYTES_TO_BITS(totalLength);
	bcs->priority=priority;
	bcs->reliability=reliability;
	bcs->orderingChannel=orderingChannel;
	bcs->systemIdentifier=systemIdentifier;
	bcs->broadcast=broadcast;
	bcs->connectionMode=connectionMode;
	bcs->receipt=receipt;
	bcs->command=BufferedCommandStruct::BCS_SEND;
	bufferedCommands.Push(bcs);

	if (priority==IMMEDIATE_PRIORITY)
	{
		// Forces pending sends to go out now, rather than waiting to the next update interval
		quitAndDataEvents.SetEvent();
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::SendImmediate( char *data, BitSize_t numberOfBitsToSend, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, bool useCallerDataAllocation, RakNet::TimeUS currentTime, uint32_t receipt )
{
	unsigned *sendList;
	unsigned sendListSize;
	bool callerDataAllocationUsed;
	unsigned int remoteSystemIndex, sendListIndex; // Iterates into the list of remote systems
//	unsigned numberOfBytesUsed = (unsigned) BITS_TO_BYTES(numberOfBitsToSend);
	callerDataAllocationUsed=false;

	sendListSize=0;

	if (systemIdentifier.systemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
		remoteSystemIndex=GetIndexFromSystemAddress( systemIdentifier.systemAddress, true );
	else if (systemIdentifier.rakNetGuid!=UNASSIGNED_RAKNET_GUID)
		remoteSystemIndex=GetSystemIndexFromGuid(systemIdentifier.rakNetGuid);
	else
		remoteSystemIndex=(unsigned int) -1;

	// 03/06/06 - If broadcast is false, use the optimized version of GetIndexFromSystemAddress
	if (broadcast==false)
	{
		if (remoteSystemIndex==(unsigned int) -1)
		{
#ifdef _DEBUG
//			int debugIndex = GetRemoteSystemIndex(systemIdentifier.systemAddress);
#endif
			return false;
		}


		sendList=(unsigned *)alloca(sizeof(unsigned));




		if (remoteSystemList[remoteSystemIndex].isActive &&
			remoteSystemList[remoteSystemIndex].connectMode!=RemoteSystemStruct::DISCONNECT_ASAP &&
			remoteSystemList[remoteSystemIndex].connectMode!=RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY &&
			remoteSystemList[remoteSystemIndex].connectMode!=RemoteSystemStruct::DISCONNECT_ON_NO_ACK)
		{
			sendList[0]=remoteSystemIndex;
			sendListSize=1;
		}
	}
	else
	{

	//sendList=(unsigned *)alloca(sizeof(unsigned)*remoteSystemListSize);
		sendList=(unsigned *)alloca(sizeof(unsigned)*maximumNumberOfPeers);





		// remoteSystemList in network thread
		unsigned int idx;
		for ( idx = 0; idx < maximumNumberOfPeers; idx++ )
		{
			if (remoteSystemIndex!=(unsigned int) -1 && idx==remoteSystemIndex)
				continue;

			if ( remoteSystemList[ idx ].isActive && remoteSystemList[ idx ].systemAddress != UNASSIGNED_SYSTEM_ADDRESS )
				sendList[sendListSize++]=idx;
		}
	}

	if (sendListSize==0)
	{



		return false;
	}

	for (sendListIndex=0; sendListIndex < sendListSize; sendListIndex++)
	{
		// Send may split the packet and thus deallocate data.  Don't assume data is valid if we use the callerAllocationData
		bool useData = useCallerDataAllocation && callerDataAllocationUsed==false && sendListIndex+1==sendListSize;
		remoteSystemList[sendList[sendListIndex]].reliabilityLayer.Send( data, numberOfBitsToSend, priority, reliability, orderingChannel, useData==false, remoteSystemList[sendList[sendListIndex]].MTUSize, currentTime, receipt );
		if (useData)
			callerDataAllocationUsed=true;

		if (reliability==RELIABLE ||
			reliability==RELIABLE_ORDERED ||
			reliability==RELIABLE_SEQUENCED ||
			reliability==RELIABLE_WITH_ACK_RECEIPT ||
			reliability==RELIABLE_ORDERED_WITH_ACK_RECEIPT
//			||
//			reliability==RELIABLE_SEQUENCED_WITH_ACK_RECEIPT
			)
			remoteSystemList[sendList[sendListIndex]].lastReliableSend=(RakNet::TimeMS)(currentTime/(RakNet::TimeUS)1000);
	}





	// Return value only meaningful if true was passed for useCallerDataAllocation.  Means the reliability layer used that data copy, so the caller should not deallocate it
	return callerDataAllocationUsed;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ResetSendReceipt(void)
{
	sendReceiptSerialMutex.Lock();
	sendReceiptSerial=1;
	sendReceiptSerialMutex.Unlock();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::OnConnectedPong(RakNet::Time sendPingTime, RakNet::Time sendPongTime, RemoteSystemStruct *remoteSystem)
{
	RakNet::Time ping;
//	RakNet::TimeMS lastPing;
	RakNet::Time time = RakNet::GetTime(); // Update the time value to be accurate
	if (time > sendPingTime)
		ping = time - sendPingTime;
	else
		ping=0;

//	lastPing = remoteSystem->pingAndClockDifferential[ remoteSystem->pingAndClockDifferentialWriteIndex ].pingTime;

	remoteSystem->pingAndClockDifferential[ remoteSystem->pingAndClockDifferentialWriteIndex ].pingTime = ( unsigned short ) ping;
	// Thanks to Chris Taylor (cat02e@fsu.edu) for the improved timestamping algorithm
	// Divide each integer by 2, rather than the sum by 2, to prevent overflow
	remoteSystem->pingAndClockDifferential[ remoteSystem->pingAndClockDifferentialWriteIndex ].clockDifferential = sendPongTime - ( time/2 + sendPingTime/2 );

	if ( remoteSystem->lowestPing == (unsigned short)-1 || remoteSystem->lowestPing > (int) ping )
		remoteSystem->lowestPing = (unsigned short) ping;

	if ( ++( remoteSystem->pingAndClockDifferentialWriteIndex ) == (RakNet::Time) PING_TIMES_ARRAY_SIZE )
		remoteSystem->pingAndClockDifferentialWriteIndex = 0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearBufferedCommands(void)
{
	BufferedCommandStruct *bcs;

	while ((bcs=bufferedCommands.Pop())!=0)
	{
		if (bcs->data)
			rakFree_Ex(bcs->data, _FILE_AND_LINE_ );

		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
	}
	bufferedCommands.Clear(_FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearBufferedPackets(void)
{
	RecvFromStruct *bcs;

	while ((bcs=bufferedPackets.Pop())!=0)
	{
		bufferedPackets.Deallocate(bcs, _FILE_AND_LINE_);
	}
	bufferedPackets.Clear(_FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearSocketQueryOutput(void)
{
	socketQueryOutput.Clear(_FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearRequestedConnectionList(void)
{
	DataStructures::Queue<RequestedConnectionStruct*> freeQueue;
	requestedConnectionQueueMutex.Lock();
	while (requestedConnectionQueue.Size())
		freeQueue.Push(requestedConnectionQueue.Pop(), _FILE_AND_LINE_ );
	requestedConnectionQueueMutex.Unlock();
	unsigned i;
	for (i=0; i < freeQueue.Size(); i++)
	{
#if LIBCAT_SECURITY==1
		CAT_AUDIT_PRINTF("AUDIT: In ClearRequestedConnectionList(), Deleting freeQueue index %i client_handshake %x\n", i, freeQueue[i]->client_handshake);
		RakNet::OP_DELETE(freeQueue[i]->client_handshake,_FILE_AND_LINE_);
#endif
		RakNet::OP_DELETE(freeQueue[i], _FILE_AND_LINE_ );
	}
}
inline void RakPeer::AddPacketToProducer(RakNet::Packet *p)
{
	packetReturnMutex.Lock();
	packetReturnQueue.Push(p,_FILE_AND_LINE_);
	packetReturnMutex.Unlock();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
union Buff6AndBuff8
{
	unsigned char buff6[6];
	uint64_t buff8;
};
uint64_t RakPeerInterface::Get64BitUniqueRandomNumber(void)
{
	// Mac address is a poor solution because you can't have multiple connections from the same system













#if   defined(_WIN32)
	uint64_t g=RakNet::GetTimeUS();

	RakNet::TimeUS lastTime, thisTime;
	int j;
	// Sleep a small random time, then use the last 4 bits as a source of randomness
	for (j=0; j < 8; j++)
	{
		lastTime = RakNet::GetTimeUS();
		RakSleep(1);
		RakSleep(0);
		thisTime = RakNet::GetTimeUS();
		RakNet::TimeUS diff = thisTime-lastTime;
		unsigned int diff4Bits = (unsigned int) (diff & 15);
		diff4Bits <<= 32-4;
		diff4Bits >>= j*4;
		((char*)&g)[j] ^= diff4Bits;
	}
	return g;

#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_usec + tv.tv_sec * 1000000;
#endif
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::GenerateGUID(void)
{
	myGuid.g=Get64BitUniqueRandomNumber();

}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GenerateSeedFromGuid(void)
{
	/*
	// Construct a random seed based on the initial guid value, and the last digits of the difference to each subsequent number
	// This assumes that only the last 3 bits of each guidId integer has a meaningful amount of randomness between it and the prior number
	unsigned int t = guid.g[0];
	unsigned int i;
	for (i=1; i < sizeof(guid.g) / sizeof(guid.g[0]); i++)
	{
		unsigned int diff = guid.g[i]-guid.g[i-1];
		unsigned int diff3Bits = diff & 0x0007;
		diff3Bits <<= 29;
		diff3Bits >>= (i-1)*3;
		t ^= diff3Bits;
	}

	return t;
	*/
	return (unsigned int) ((myGuid.g >> 32) ^ myGuid.g);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::DerefAllSockets(void)
{
	unsigned int i;
	for (i=0; i < socketList.Size(); i++)
	{
		socketList[i].SetNull();
	}
	socketList.Clear(false, _FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetRakNetSocketFromUserConnectionSocketIndex(unsigned int userIndex) const
{
	unsigned int i;
	for (i=0; i < socketList.Size(); i++)
	{
		if (socketList[i]->userConnectionSocketIndex==userIndex)
			return i;
	}
	RakAssert("GetRakNetSocketFromUserConnectionSocketIndex failed" && 0);
	return (unsigned int) -1;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::RunUpdateCycle( RakNet::TimeUS timeUS, RakNet::Time timeMS, BitStream &updateBitStream )
{
	ProcessBufferedPackets(updateBitStream, timeUS);

	ProcessBufferedCommands(updateBitStream, timeUS, timeMS);
	
	if (requestedConnectionQueue.IsEmpty()==false)
	{
		assert(timeUS != 0);
		HandleRequestedConnectionQueue(timeUS, timeMS);
	}

	HandleActiveSystemList(updateBitStream, timeUS, timeMS);

	return true;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

RAK_THREAD_DECLARATION(RakNet::RecvFromLoop)
{



	RakPeerAndIndex *rpai = ( RakPeerAndIndex * ) arguments;

	RakPeer * rakPeer = rpai->rakPeer;
	SOCKET s = rpai->s;
	unsigned short remotePortRakNetWasStartedOn_PS3 = rpai->remotePortRakNetWasStartedOn_PS3;
	unsigned int extraSocketOptions = rpai->extraSocketOptions;

	rakPeer->isRecvFromLoopThreadActive.Increment();

	RakPeer::RecvFromStruct *recvFromStruct;
	while ( rakPeer->endThreads == false )
	{
		recvFromStruct=rakPeer->bufferedPackets.Allocate( _FILE_AND_LINE_ );
		if (recvFromStruct != NULL)
		{
			recvFromStruct->s=s;
			recvFromStruct->remotePortRakNetWasStartedOn_PS3=remotePortRakNetWasStartedOn_PS3;
			recvFromStruct->extraSocketOptions=extraSocketOptions;
			SocketLayer::RecvFromBlocking(s, rakPeer, remotePortRakNetWasStartedOn_PS3, extraSocketOptions, recvFromStruct->data, &recvFromStruct->bytesRead, &recvFromStruct->systemAddress, &recvFromStruct->timeRead);

			if (recvFromStruct->bytesRead>0)
			{
				RakAssert(recvFromStruct->systemAddress.GetPort());
				rakPeer->bufferedPackets.Push(recvFromStruct);
				rakPeer->quitAndDataEvents.SetEvent();
			}
			else
			{
				rakPeer->bufferedPackets.Deallocate(recvFromStruct, _FILE_AND_LINE_);
			}
		}
		else
			RakSleep(30);
	}
	rakPeer->isRecvFromLoopThreadActive.Decrement();




	return 0;

}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RAK_THREAD_DECLARATION(RakNet::UpdateNetworkLoop)
{



	RakPeer * rakPeer = ( RakPeer * ) arguments;


/*
	// 11/15/05 - this is slower than Sleep()
#ifdef _WIN32
#if (_WIN32_WINNT >= 0x0400) || (_WIN32_WINDOWS > 0x0400)
	// Lets see if these timers give better performance than Sleep
	HANDLE timerHandle;
	LARGE_INTEGER dueTime;

	if ( rakPeer->threadSleepTimer <= 0 )
		rakPeer->threadSleepTimer = 1;

	// 2nd parameter of false means synchronization timer instead of manual-reset timer
	timerHandle = CreateWaitableTimer( NULL, FALSE, 0 );

	RakAssert( timerHandle );

	dueTime.QuadPart = -10000 * rakPeer->threadSleepTimer; // 10000 is 1 ms?

	BOOL success = SetWaitableTimer( timerHandle, &dueTime, rakPeer->threadSleepTimer, NULL, NULL, FALSE );
    (void) success;
	RakAssert( success );

#endif
#endif
*/

	BitStream updateBitStream( MAXIMUM_MTU_SIZE
#if LIBCAT_SECURITY==1
		+ cat::AuthenticatedEncryption::OVERHEAD_BYTES
#endif
		);

	RakNet::TimeUS timeUS;
	RakNet::TimeMS timeMS;

	rakPeer->isMainLoopThreadActive = true;

	while ( rakPeer->endThreads == false )
	{
		// Set inside RunUpdateCycle() itself, this is here for testing
		timeUS=0;
		timeMS=0;

// #ifdef _DEBUG
// 		// Sanity check, make sure RunUpdateCycle does not block or not otherwise get called for a long time
// 		RakNetTime thisCall=RakNet::GetTime();
// 		RakAssert(thisCall-lastCall<250);
// 		lastCall=thisCall;
// #endif
		if (rakPeer->userUpdateThreadPtr)
			rakPeer->userUpdateThreadPtr(rakPeer, rakPeer->userUpdateThreadData);

		rakPeer->RunUpdateCycle(timeUS, timeMS, updateBitStream);

		// Pending sends go out this often, unless quitAndDataEvents is set
		rakPeer->quitAndDataEvents.WaitOnEvent(10);

		/*

// #if ((_WIN32_WINNT >= 0x0400) || (_WIN32_WINDOWS > 0x0400)) &&
#if defined(USE_WAIT_FOR_MULTIPLE_EVENTS) && defined(_WIN32)

		if (rakPeer->threadSleepTimer>0)
		{
			WSAEVENT eventArray[256];
			unsigned int i, eventArrayIndex;
			for (i=0,eventArrayIndex=0; i < rakPeer->socketList.Size(); i++)
			{
				if (rakPeer->socketList[i]->recvEvent!=INVALID_HANDLE_VALUE)
				{
					eventArray[eventArrayIndex]=rakPeer->socketList[i]->recvEvent;
					eventArrayIndex++;
					if (eventArrayIndex==256)
						break;
				}
			}
			WSAWaitForMultipleEvents(eventArrayIndex,(const HANDLE*) &eventArray,FALSE,rakPeer->threadSleepTimer,FALSE);
		}
		else
		{
			RakSleep(0);
		}

#else // ((_WIN32_WINNT >= 0x0400) || (_WIN32_WINDOWS > 0x0400)) && defined(USE_WAIT_FOR_MULTIPLE_EVENTS)
		#pragma message("-- RakNet: Using Sleep(). Uncomment USE_WAIT_FOR_MULTIPLE_EVENTS in RakNetDefines.h if you want to use WaitForSingleObject instead. --")

		RakSleep( rakPeer->threadSleepTimer );
#endif
		*/
	}

	rakPeer->isMainLoopThreadActive = false;

	/*
#ifdef _WIN32
#if (_WIN32_WINNT >= 0x0400) || (_WIN32_WINDOWS > 0x0400)
	CloseHandle(timerHandle);
#endif
#endif
	*/




	return 0;

}

// #if defined(RMO_NEW_UNDEF_ALLOCATING_QUEUE)
// #pragma pop_macro("new")
// #undef RMO_NEW_UNDEF_ALLOCATING_QUEUE
// #endif


#ifdef _MSC_VER
#pragma warning( pop )
#endif
