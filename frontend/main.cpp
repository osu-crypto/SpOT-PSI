#include <iostream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"

#include <cryptoTools/Common/Defines.h>
using namespace osuCrypto;

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
int miraclTestMain();

#include "libOTe/Tools/LinearCode.h"
#include "libOTe/Tools/bch511.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"
#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"

#include "CLP.h"
#include "main.h"
#include <cryptoTools/gsl/span>

#include <cryptoTools/Common/Matrix.h>



void kkrt_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 step = 1024;
    u64 numOTs = 1 << 24;
    u64 numThreads = 1;

    u64 otsPer = numOTs / numThreads;

    auto rr = i ? EpMode::Server : EpMode::Client;
    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, rr, name);
    std::vector<Channel> chls(numThreads);

    for (u64 k = 0; k < numThreads; ++k)
        chls[k] = ep0.addChannel(name + ToString(k), name + ToString(k));



    u64 baseCount = 4 * 128;

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    block choice = prng0.get<block>();// ((u8*)choice.data(), ncoinputBlkSize * sizeof(block));

    std::vector<std::thread> thds(numThreads);

    if (i == 0)
    {

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                KkrtNcoOtReceiver r;
				r.configure(false, 40, 128);
                r.setBaseOts(baseSend);
                auto& chl = chls[k];

                r.init(otsPer, prng0, chl);
                block encoding1;
                for (u64 i = 0; i < otsPer; i += step)
                {
                    for (u64 j = 0; j < step; ++j)
                    {
                        r.encode(i + j, &choice, &encoding1);
                    }

                    r.sendCorrection(chl, step);
                }
                r.check(chl, ZeroBlock);

                chl.close();
            });
        }
        for (u64 k = 0; k < numThreads; ++k)
            thds[k].join();
    }
    else
    {
        Timer time;
        time.setTimePoint("start");
        block encoding2;

        for (u64 k = 0; k < numThreads; ++k)
        {
            thds[k] = std::thread(
                [&, k]()
            {
                KkrtNcoOtSender s;
				s.configure(false, 40, 128);
                s.setBaseOts(baseRecv, baseChoice);
                auto& chl = chls[k];

                s.init(otsPer, prng0, chl);
                for (u64 i = 0; i < otsPer; i += step)
                {

                    s.recvCorrection(chl, step);

                    for (u64 j = 0; j < step; ++j)
                    {
                        s.encode(i + j, &choice, &encoding2);
                    }
                }
                s.check(chl, ZeroBlock);
                chl.close();
            });
        }


        for (u64 k = 0; k < numThreads; ++k)
            thds[k].join();

        time.setTimePoint("finish");
        std::cout << time << std::endl;
    }


    //for (u64 k = 0; k < numThreads; ++k)
        //chls[k]->close();

    ep0.stop();
    ios.stop();
}





void iknp_test(int i)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 numOTs = 1 << 24;

    auto rr = i ? EpMode::Server : EpMode::Client;

    // get up the networking
    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, rr, name);
    Channel chl = ep0.addChannel(name, name);


    // cheat and compute the base OT in the clear.
    u64 baseCount = 128;
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }




    if (i)
    {
        BitVector choice(numOTs);
        std::vector<block> msgs(numOTs);
        choice.randomize(prng0);
        IknpOtExtReceiver r;
        r.setBaseOts(baseSend);

        r.receive(choice, msgs, prng0, chl);
    }
    else
    {
        std::vector<std::array<block, 2>> msgs(numOTs);

        Timer time;
        time.setTimePoint("start");
        IknpOtExtSender s;
        s.setBaseOts(baseRecv, baseChoice);

        s.send(msgs, prng0, chl);

        time.setTimePoint("finish");
        std::cout << time << std::endl;

    }


    chl.close();

    ep0.stop();
    ios.stop();
}


double maxprob1(u64 balls, u64 bins, u64 k)
{
	return std::log(bins * std::pow(balls * exp(1) / (bins * k), k)) / std::log(2);
}
u64 findMaxBinSize(u64 n, u64 numBins, u64 numHash = 1)
{
	u64 balls = n;
	u64 maxBin = n;
	while (true)
	{
		// finds the min number of bins needed to get max occ. to be maxBin
		
		if (-maxprob1(balls, numBins, maxBin) < 40)
		{
			// maxBins is too small, skip it.
			continue;
			maxBin++;
		}
		else
			return maxBin;
	}
}



int main(int argc, char** argv)
{

	std::vector<u64> n = { 12,14,16,20,24 };

	for (u64 i = 0; i < n.size(); i++)
	{
		u64 p = 1 << n[i];
		for (u64 numBins = 128; numBins < 1024; numBins += 128)
		{
			u64 maxBin = findMaxBinSize(p, numBins);
			std::cout << n[i] << " | " << numBins << " | " << maxBin << std::endl;
		}
		std::cout << std::endl;
	}

    return 0;
}
