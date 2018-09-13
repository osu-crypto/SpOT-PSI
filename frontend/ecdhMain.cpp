
#include "cryptoTools/Network/Endpoint.h" 

#include "libPSI/ECDH/EcdhPsiReceiver.h"
#include "libPSI/ECDH/EcdhPsiSender.h"


#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <fstream>
#include "ecdhMain.h"

using namespace osuCrypto;

//extern u8 dummy[];

void EcdhSend(int curveType, int setSize, std::string ipAdress, int mTrials)
{
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    {
        {
			// set up networking
			std::string name = "n";
			IOService ios;
			Endpoint ep1(ios, ipAdress, EpMode::Server, name);

			std::vector<Channel> sendChls(1);
			for (u64 i = 0; i < 1; ++i)
				sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));


            for (u64 jj = 0; jj < mTrials; jj++)
            {
                std::vector<block> set(setSize);
                prng.get(set.data(), set.size());


                EcdhPsiSender sendPSIs;

                sendPSIs.init(setSize, 40, prng.get<block>());
                //sendChls[0].asyncSend(dummy, 1);

                sendPSIs.sendInput(set, sendChls, curveType);
            }
        }
    }
}


void EcdhRecv(int curveType,  int setSize, std::string ipAdress,int mTrials)
{

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

   // for (auto setSize : params.mNumItems)
    {
     //   for (auto numThreads : params.mNumThreads)
        {
			// set up networking
			std::string name = "n";
			IOService ios;
			Endpoint ep0(ios, ipAdress, EpMode::Client, name);

			std::vector<Channel> recvChls(1);
			for (u64 i = 0; i < 1; ++i)
				recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));


            for (u64 jj = 0; jj < mTrials; jj++)
            {

                std::vector<block> set(setSize);
                prng.get(set.data(), set.size());

                EcdhPsiReceiver recvPSIs;

                gTimer.reset();

                Timer timer;
                auto start = timer.setTimePoint("start");
                recvPSIs.init(setSize, 40, ZeroBlock);

				//recvChls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("init");

                recvPSIs.sendInput(set, recvChls, curveType);
                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

				if(curveType==0)
					std::cout << "Ecdh_k283" << std::endl;
				else
					std::cout << "Ecdh_Curve25519" << std::endl;

				std::cout << timer << std::endl;




            }
        }
    }
}



