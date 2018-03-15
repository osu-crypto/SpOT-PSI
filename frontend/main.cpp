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


void seft_balance1()
{
	u64 numBalls = 1 << 12;
	u64 numBins = 1 << 8;

	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

	u64 bound = 1 + numBalls / numBins;
	std::cout << "bound " << bound << "\n";

	std::vector<block> mBalls(numBalls);
	for (u64 i = 0; i < numBalls; ++i)
		mBalls[i] = prng1.get<block>();


	std::vector<std::vector<std::vector<block>>> mBins(numBins);
	for (u64 i = 0; i < numBins; i++)
		mBins[i].resize(numBins);

	std::vector<u64>b(2);
	std::vector<u64> cnt(numBins);
	block mHashSeed = prng1.get<block>();
	AES hasher(mHashSeed);


	//init
	gTimer.reset();
	gTimer.setTimePoint("start");

	for (u64 i = 0; i < numBalls; ++i)
	{
		block temp = hasher.ecbEncBlock(mBalls[i]);

		std::cout << temp << "\n";
		block left = temp >> 64;
		std::cout << left << "\n";


		/*u64 b1 = *(u64*)&(temp.m128i_u64[0]) % numBins;


		u64 b2 = *(u64*)&(temp.m128i_u64[1]) % numBins;*/



		u64 b1 = rand() % numBins; u64 b2 = rand() % numBins;

		if (cnt[b1] > cnt[b2])//choosing the lightest of 2 bin
		{
			u64 t = b2;
			b2 = b1;
			b1 = t;
		}

		mBins[b1][b2].emplace_back(mBalls[i]);
		cnt[b1]++;

	}

	std::vector<u64> heavyBins;
	std::vector<u64> noHeavyBins;
	for (u64 i = 0; i < numBins; i++)
	{
		if (cnt[i] > bound)
			heavyBins.emplace_back(i);
		else
			noHeavyBins.emplace_back(i);
	}


	int iter = 0;
	bool isXinB2 = false, isNotDone = true;
	block x;

	int cntDone = 0;

	while (isNotDone)
	{
		u64 i1 = rand() % heavyBins.size();
		u64 i2 = rand() % noHeavyBins.size();
		u64 b1 = heavyBins[i1];
		u64 b2 = noHeavyBins[i2];

		bool isXinB2 = false;

		if (mBins[b1][b2].size() > 0)
		{
			u64 idxItem = rand() % mBins[b1][b2].size();
			x = mBins[b1][b2][idxItem];

			//if (cnt[b2] < cnt[b1])
			{
				mBins[b2][b1].emplace_back(x);
				mBins[b1][b2].erase(mBins[b1][b2].begin() + idxItem); //remove that item from b1
				cnt[b2]++;
				cnt[b1]--;

				if (cnt[b2] > bound)
				{
					heavyBins.emplace_back(b2);
					noHeavyBins.erase(noHeavyBins.begin() + i2); //remove that item from b1
				}

				if (cnt[b1] < bound)
				{
					noHeavyBins.emplace_back(b1);
					heavyBins.erase(heavyBins.begin() + i1); //remove that item from b1
				}

				isXinB2 = true;
			}
		}

		if (isXinB2 && (cnt[b2] == cnt[b1]))
		{
			u64 rB = rand() % 2;
			if (rB == 0) //place x back into b1
			{
				mBins[b1][b2].emplace_back(x);
				mBins[b2][b1].erase(mBins[b2][b1].end() - 1); //remove last item

				cnt[b1]++;
				cnt[b2]--;

			}
		}
		iter++;

		isNotDone = false;

		for (u64 i = 0; i < numBins; i++)
		{
			//std::cout << i << "\t" << cnt << "\n";

			if (cnt[i] > bound)
			{
				//std::cout << iter << "----------" << i << "\t" << bound << "\t" << cnt[i] << "\n";
				//throw UnitTestFail();
				isNotDone = true;
				break;
			}

		}
	}
	std::cout << "iter " << iter << "\n";
	gTimer.setTimePoint("finish");
	std::cout << gTimer << std::endl;

	for (u64 i = 0; i < numBins; i++)
	{
		if (cnt[i] > bound)
		{

			std::cout << "error----------" << i << "\t" << bound << "\t" << cnt[i] << "\n";
			break;
		}
	}

	//check


}

#if 1
struct item
{
	block value;
	u64 alterBin;
};

struct sBin
{
	u64 b2;
	std::vector<block> data;
};


struct Bin
{
	std::unordered_map<u64, std::vector<block>> values;
	std::vector<u64> lightBins;
};

void seft_balance()
{
	u64 numBalls = 1 << 8, numBins = 1 << 2;

	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

	u64 bound = 1 + numBalls / numBins;
	std::cout << "bound " << bound << "\n";

	std::vector<block> mBalls(numBalls);
	for (u64 i = 0; i < numBalls; ++i)
		mBalls[i] = prng1.get<block>();


	std::vector<Bin> mBins(numBins);
	std::vector<u64> cnt(numBins);

	std::vector<u64>b(2);
	block mHashSeed = prng1.get<block>(); 	AES hasher(mHashSeed);


	//init
	gTimer.reset();
	gTimer.setTimePoint("start");

	for (u64 i = 0; i < numBalls; ++i)
	{
		/*block temp = hasher.ecbEncBlock(mBalls[i]);

		u64 b1 = *(u64*)&(temp) % numBins;
		u64 b2 = *((u64*)&temp+sizeof(64)) % numBins;
		*/

		u64 b1 = rand() % numBins; u64 b2 = rand() % numBins;

		if (cnt[b1] > cnt[b2])//choosing the lightest of 2 bin
		{
			u64 t = b2;
			b2 = b1;
			b1 = t;
		}

		auto iterB2 = mBins[b1].values.find(b2);;

		if (iterB2 != mBins[b1].values.end()) { //found
			iterB2->second.emplace_back(mBalls[i]);
		}
		else
		{
			mBins[b1].values.emplace(std::make_pair(b2, std::vector<block>{ mBalls[i] }));
		}

		cnt[b1]++;

	}

	for (u64 i = 0; i < numBins; i++)
	{
		for (auto it = mBins[i].values.begin(); it != mBins[i].values.end(); ++it)
		{
			if (cnt[it->first] < bound)
				mBins[i].lightBins.emplace_back(it->first);

		}

	}



	std::vector<u64> heavyBins;
	for (u64 i = 0; i < numBins; i++)
	{
		if (cnt[i]> bound)
			heavyBins.emplace_back(i);

	}

#if 1
	int iter = 0;
	bool isXinB2 = false, isNotDone = true;
	block x;

	int cntDone = 0;
	std::cout << "heavyBins.size() " << heavyBins.size() << "\n";
	while (isNotDone && heavyBins.size()>0)
	{
		//std::cout << iter << "\t " << heavyBins.size() << "\t";

		bool isXinB2 = false;

		u64 i1 = rand() % heavyBins.size();
		u64 b1 = heavyBins[i1];
		//std::cout << mBins[b1].lightBins.size() << "\t";

		if (mBins[b1].lightBins.size() == 0)
			continue;

		u64 i2 = rand() % mBins[b1].lightBins.size();
		u64 b2 = mBins[b1].lightBins[i2]; //noHeavyBins
										  //std::cout << cnt[b2] << "\t"<< cnt[b1]<< "\t";


		if (cnt[b2] < cnt[b1]) {
			auto curSubBin = mBins[b1].values.find(b2);

			u64 rB = rand() % 2;

			if (rB == 1 || cnt[b2] + 1 != cnt[b1])
			{
				//std::cout << rB<< "\n";

				if (curSubBin->second.size() == 0)
					continue;

				u64 idxItem = rand() % curSubBin->second.size();
				x = curSubBin->second[idxItem];

				auto newSubBin = mBins[b2].values.find(b1); //place x into b2

				if (newSubBin != mBins[b2].values.end()) { //found
					newSubBin->second.emplace_back(x);
				}
				else
				{
					mBins[b2].values.emplace(std::make_pair(b1, std::vector<block>{ x}));
					mBins[b2].lightBins.emplace_back(b1);
				}

				cnt[b2]++;

				//update heavyBins
				if (cnt[b2] > bound && std::find(heavyBins.begin(), heavyBins.end(), b2) == heavyBins.end())
					heavyBins.emplace_back(b2); //add if >bound


												//remove x from b1
												//std::cout << curSubBin->second.size() << "\t";
				curSubBin->second.erase(curSubBin->second.begin() + idxItem); //remove that item from b1
				cnt[b1]--;
				//std::cout << curSubBin->second.size() << "\n";
				//update heavyBins
				if (cnt[b1] < bound)
				{
					auto it = std::find(heavyBins.begin(), heavyBins.end(), b1);
					heavyBins.erase(it);
					if (std::find(mBins[b2].lightBins.begin(), mBins[b2].lightBins.end(), b1) == mBins[b2].lightBins.end())
						mBins[b2].lightBins.emplace_back(b1);
				}
				//
				//update lightBins
				if (cnt[b2] > bound)
				{
					mBins[b1].lightBins.erase(mBins[b1].lightBins.begin() + i2);
				}


				isXinB2 = true;
				iter++;
			}


		}
		isNotDone = false;

		for (u64 i = 0; i < numBins; i++)
		{
			//std::cout << i << "\t" << cnt << "\n";

			if (cnt[i] > bound)
			{
				//std::cout << iter << "----------" << i << "\t" << bound << "\t" << cnt[i] << "\n";
				//throw UnitTestFail();
				isNotDone = true;
				break;
			}

		}
	}
	std::cout << "iter " << iter << "\n";
	gTimer.setTimePoint("finish");
	std::cout << gTimer << std::endl;

	for (u64 i = 0; i < numBins; i++)
	{
		if (cnt[i] > bound)
		{

			std::cout << "error----------" << i << "\t" << bound << "\t" << cnt[i] << "\n";
			break;
		}
	}

	//check

#endif
}
#endif 

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
