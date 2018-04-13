#include <iostream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"
#include <cryptoTools/gsl/span>

#include <cryptoTools/Common/Matrix.h>

#include <cryptoTools/Common/Defines.h>
using namespace osuCrypto;

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>


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

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>

#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"

#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "Poly/polyNTL.h"
#include "PsiDefines.h"

#include "PRTY/PrtySender.h"
#include "PRTY/PrtyReceiver.h"
#include "Tools/SimpleIndex.h"

#include <thread>
#include <vector>

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

		std::cout << temp <<"\n";
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


struct Bin
{
	std::unordered_map<u64, std::vector<block>> values;
	std::vector<u64> lightBins;
};

void seft_balance()
{
	u64 numBalls = 1 << 20,  numBins = 1 << 10;

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
		block temp = hasher.ecbEncBlock(mBalls[i]);
		
		u64 b1 = _mm_extract_epi64(temp, 0) % numBins;
		u64 b2 = _mm_extract_epi64(temp, 1) % numBins;


		//u64 b1 = rand() % numBins; u64 b2 = rand() % numBins;

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
		if (cnt[i]>= bound)
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

		if (mBins[b1].lightBins.size() == 0) //just in case...
			continue;
		
		u64 i2 = rand() % mBins[b1].lightBins.size();
		u64 b2 = mBins[b1].lightBins[i2]; //noHeavyBins
		//std::cout << cnt[b2] << "\t"<< cnt[b1]<< "\t";


		if (cnt[b2] < cnt[b1] )
		{
			auto curSubBin = mBins[b1].values.find(b2);

			u64 rB = rand() % 2;

			if (rB ==1 || cnt[b2]+1 != cnt[b1])
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
				if (cnt[b2] >= bound && std::find(heavyBins.begin(), heavyBins.end(), b2) == heavyBins.end())
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
				if (cnt[b2] >= bound)
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


void Sender(u64 setSize, span<block> inputs, u64 numThreads = 1)
{
	u64 psiSecParam = 40;

	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

	// set up networking
	std::string name = "n";
	IOService ios;
	Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);

	std::vector<Channel> sendChls(numThreads);
	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	PrtySender sender;

	sender.init(40, prng0, inputs, sendChls);

	/*std::cout << sender.mBaseOTSend[0][0] << "\t";
	std::cout << sender.mBaseOTSend[0][1] << "\n";
	std::cout << sender.mBaseOTRecv[0] << "\n";*/

	sender.output(inputs, sendChls);


	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i].close();

	ep1.stop();	ios.stop();

}

void Receiver(u64 setSize, span<block> inputs,u64 numThreads=1)
{
	u64 psiSecParam = 40;

	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

	// set up networking
	std::string name = "n";
	IOService ios;
	Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);

	std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	PrtyReceiver recv;
	gTimer.reset();
	gTimer.setTimePoint("start");
	recv.init(40, prng1, inputs, recvChls);
	gTimer.setTimePoint("offline");

		/*std::cout << recv.mBaseOTRecv[0] << "\n";
		std::cout << recv.mBaseOTSend[0][0] << "\t";
		std::cout << recv.mBaseOTSend[0][1] << "\n";*/

	recv.output(inputs, recvChls);
	//gTimer.setTimePoint("finish");
	std::cout << gTimer << std::endl;


	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i].close();

	ep0.stop(); ios.stop();

}

void PMT_Test_Impl()
{
	u64 setSize = 1 << 7, psiSecParam = 40, numThreads(1);

	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));


	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng0.get<block>();
		recvSet[i] = prng0.get<block>();
	}
	sendSet[0] = recvSet[0];
	sendSet[2] = recvSet[2];
	std::cout << "intersection: " << sendSet[0] << "\n";
	std::cout << "intersection: " << sendSet[2] << "\n";


	// set up networking
	std::string name = "n";
	IOService ios;
	Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
	Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);

	std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
	for (u64 i = 0; i < numThreads; ++i)
	{
		sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
	}


	PrtySender sender;
	PrtyReceiver recv;
	auto thrd = std::thread([&]() {
		recv.init(40, prng1, recvSet, recvChls);

		
	});

	sender.init(40, prng0, sendSet, sendChls);

thrd.join();




	for (u64 i = 0; i < numThreads; ++i)
	{
		sendChls[i].close(); recvChls[i].close();
	}

	ep0.stop(); ep1.stop();	ios.stop();

}


#include "Poly/polyFFT.h"
void Poly_Test_Impl() {

	
	long degree = 2+(1 << 6);
	long numSlice = 4;
	int subField = 128;
	int fieldSize = 440;
	std::cout << "FieldSize: " << fieldSize << "\t";
	std::cout << "subField: " << subField << "\t";
	std::cout << "numSlice: " << numSlice << "\t";
	std::cout << "degree: " << degree << "\n";

	//#################Quaratic ZZ_p################################
	{
		ZZ prime;
		GenGermainPrime(prime, fieldSize);
		ZZ_p::init(ZZ(prime));
		ZZ_p p;
		vec_ZZ_p x, y;


		for (u64 i = 0; i <= degree; ++i)
		{
			NTL::random(p);
			x.append(p);
			NTL::random(p);
			y.append(p);
		}

		gTimer.reset();
		gTimer.setTimePoint("start");

		NTL::ZZ_pX polynomial = NTL::interpolate(x, y);
		gTimer.setTimePoint("Quaratic ZZ_p");
		std::cout << gTimer << std::endl;
	}

	//#################Quaratic ZZ_p Slicing################################
	{
		ZZ prime2;
		GenGermainPrime(prime2, subField);
		ZZ_p p;
		ZZ_p::init(ZZ(prime2));


		vec_ZZ_p x;
		for (unsigned int i = 0; i <= degree; i++) {
			NTL::random(p);
			x.append(p);
		}

		std::vector<vec_ZZ_p> y2(numSlice);

		for (int j = 0; j < numSlice; j++)
		{
			for (unsigned int i = 0; i <= degree; i++)
			{
				NTL::random(p);
				y2[j].append(p);
			}
		}

		gTimer.reset();
		gTimer.setTimePoint("start");
		for (int j = 0; j < numSlice; j++)
			NTL::ZZ_pX polynomial = NTL::interpolate(x, y2[j]);
		gTimer.setTimePoint("slicing Quaratic ZZ_p");

		std::cout << gTimer << std::endl;
	}

	

	//#################Quaratic GF2EX################################
	{
		NTL::GF2X mGf2x;
		NTL::BuildIrred(mGf2x, fieldSize);
		NTL::GF2E::init(mGf2x);
		NTL::GF2E e;

		NTL::vec_GF2E vecX, vecY;

		for (u64 i = 0; i <= degree; ++i)
		{
			NTL::random(e);
			vecX.append(e);
			NTL::random(e);
			vecY.append(e);
		}

		gTimer.reset();
		gTimer.setTimePoint("start");
		NTL::GF2EX polynomial = NTL::interpolate(vecX, vecY);
		gTimer.setTimePoint("GF2EX n^2");
		std::cout << gTimer << std::endl;
	}

	//#################Slicing Quaratic GF2EX################################
	{
		NTL::GF2X gf2x;
		NTL::BuildIrred(gf2x, subField);
		NTL::GF2E::init(gf2x);
		NTL::GF2E e2;

		NTL::vec_GF2E vecX2;
		std::vector<NTL::vec_GF2E> vecY2(numSlice);

		for (u64 i = 0; i <= degree; ++i)
		{
			NTL::random(e2);
			vecX2.append(e2);
		}

		for (int j = 0; j < numSlice; j++)
		{
			for (unsigned int i = 0; i <= degree; i++)
			{
				NTL::random(e2);
				vecY2[j].append(e2);
			}
		}


		gTimer.reset();
		gTimer.setTimePoint("start");
		for (int j = 0; j < numSlice; j++)
			NTL::GF2EX polynomial = NTL::interpolate(vecX2, vecY2[j]);
		gTimer.setTimePoint("slicing GF2EX n^2");
		std::cout << gTimer << std::endl;
	}
	//#################nlog^2n Full################################
	{
		ZZ prime;
		GenGermainPrime(prime, fieldSize);

		// init underlying prime field
		ZZ_p::init(ZZ(prime));


		// interpolation points:
		ZZ_p* x = new ZZ_p[degree + 1];
		ZZ_p* y = new ZZ_p[degree + 1];
		for (unsigned int i = 0; i <= degree; i++) {
			random(x[i]);
			random(y[i]);
			//        cout << "(" << x[i] << "," << y[i] << ")" << endl;
		}

		ZZ_pX P;
		u64 numTrials = 1;
		gTimer.reset();
		gTimer.setTimePoint("start");

		for (int iTrial = 0; iTrial < numTrials; ++iTrial)
		{
			interpolate_zp(P, x, y, degree, 1, prime);
		}
		gTimer.setTimePoint("nlog^2n ");
		std::cout << gTimer << std::endl;
	}

	//#################nlog^2n Slicing################################
	{
		ZZ prime2;
		GenGermainPrime(prime2, subField);
		ZZ_p::init(ZZ(prime2));


		ZZ_p* x2 = new ZZ_p[degree + 1];
		for (unsigned int i = 0; i <= degree; i++) {
			random(x2[i]);
		}

		std::vector<ZZ_p*> y2(4);
		for (int j = 0; j < 4; j++)
		{
			y2[j] = new ZZ_p[degree + 1];
			for (unsigned int i = 0; i <= degree; i++)
			{
				random(y2[j][i]);
			}
		}


		ZZ_pX *M = new ZZ_pX[degree * 2 + 1];;
		ZZ_p *a = new ZZ_p[degree + 1];;

		gTimer.reset();
		gTimer.setTimePoint("start");

		prepareForInterpolate(x2, degree, M, a, 1, prime2);


		for (u64 j = 0; j < 4; j++)
		{
			ZZ_pX P;
			ZZ_pX* temp = new ZZ_pX[degree * 2 + 1];
			iterative_interpolate_zp(P, temp, y2[j], a, M, degree * 2 + 1, 1, prime2);

			//test_interpolation_result_zp(P, xx, yy, 1);
		}
		gTimer.setTimePoint("slicing nlog^2n");

		std::cout << gTimer << std::endl;
	}
	

}

void FFT_Poly_Test_Impl_Real() {


	ZZ prime;
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	//#################FFT Slicing################################
	GenGermainPrime(prime, 128);

	long degree = 1<<10;

	ZZ_p::init(ZZ(prime));

	ZZ_p* xx = new ZZ_p[degree + 1];
	ZZ_p* yy = new ZZ_p[degree + 1];
	ZZ zz;

	std::vector<block> X(degree + 1);
	std::vector<std::array<block, numSuperBlocks>> Y(degree + 1);
	for (u64 i = 0; i < X.size(); ++i)
	{
		X[i] = prng0.get<block>();
		for (u64 j = 0; j < numSuperBlocks; j++)
		{
			Y[i][j] = prng0.get<block>();
		}
	}


	gTimer.reset();
	gTimer.setTimePoint("start");
	for (unsigned int i = 0; i <= degree; i++) {
		ZZFromBytes(zz, (u8*)&X[i], sizeof(block));
		xx[i] = to_ZZ_p(zz);
	}

	ZZ_pX *M = new ZZ_pX[degree * 2 + 1];;
	ZZ_p *a = new ZZ_p[degree + 1];;

	prepareForInterpolate(xx, degree, M, a, 1, prime);


	for (u64 j = 0; j < numSuperBlocks; j++)
	{
		for (unsigned int i = 0; i <= degree; i++) {
			ZZFromBytes(zz, (u8*)&Y[i], sizeof(block));
			yy[i] = to_ZZ_p(zz);
		}
		ZZ_pX P;
		ZZ_pX* temp = new ZZ_pX[degree * 2 + 1];
		iterative_interpolate_zp(P, temp, yy, a, M, degree * 2 + 1, 1, prime);

		//test_interpolation_result_zp(P, xx, yy, 1);
	}
	gTimer.setTimePoint("end");

	std::cout << gTimer << std::endl;


	//#################Slicing################################


}

void usage(const char* argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t 1. For unit test: " << argv0 << " -t" << std::endl;
	std::cout << "\t 2. For simulation (2 terminal): " << std::endl;;
	std::cout << "\t\t Sender terminal: " << argv0 << " -r 0" << std::endl;
	std::cout << "\t\t Receiver terminal: " << argv0 << " -r 1" << std::endl;
}


void Hashing_Test_Impl()
{
	setThreadName("Sender");
	u64 setSize = 1 << 20, psiSecParam = 40, numThreads(1);

	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	std::vector<block> set(setSize);
	for (u64 i = 0; i < set.size(); ++i)
		set[i] = prng.get<block>();

	SimpleIndex simple;
	gTimer.reset();
	gTimer.setTimePoint("start");
	simple.init(setSize,40, 1);
	simple.insertItems(set);
	gTimer.setTimePoint("end");
	std::cout << gTimer << std::endl;
	simple.check();

//	simple.print(set);

}

void OTrow() {
	static std::vector<block> oneBlocks(128);
	fillOneBlock(oneBlocks);
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

	block temp;
	block res;

	u64 numTrials = 1 << 20;
	gTimer.reset();
	gTimer.setTimePoint("start");
	for (int iTrial = 0; iTrial < numTrials; ++iTrial)
		for (int i = 0; i < 128; ++i)
		{
			temp = prng.get<block>();
			temp = temp&oneBlocks[i];
			res = res ^ temp;
		}

	gTimer.setTimePoint("xor");
	std::cout << gTimer << std::endl;


	gTimer.reset();
	gTimer.setTimePoint("start_1");
	for (int iTrial = 0; iTrial < numTrials; ++iTrial)
	{
		std::array<block, 128> test0;
		for (int i = 0; i < 128; ++i)
			test0[i] = prng.get<block>();

		sse_transpose128(test0);
	}

	gTimer.setTimePoint("transposition");
	std::cout << gTimer << std::endl;

}


int main(int argc, char** argv)
{
	/*Poly_Test_Impl();
	return 0;*/

	/*Hashing_Test_Impl();
	return 0;*/


	/*seft_balance();
	return 0;*/

	u64 setSize = 1 << 20, numThreads=1;
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));
	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng0.get<block>();
		recvSet[i] = prng0.get<block>();
	}
	sendSet[0] = recvSet[0];
	sendSet[2] = recvSet[2];
	std::cout << "intersection: " << sendSet[0] << "\n";
	std::cout << "intersection: " << sendSet[2] << "\n";
	

#if 0
	std::thread thrd = std::thread([&]() {
		Sender(setSize, sendSet);
	});

	Receiver(setSize, recvSet);

	thrd.join();
	return 0;
#endif

	if (argc == 2 && argv[1][0] == '-' && argv[1][1] == 't') {
		
		std::thread thrd = std::thread([&]() {
			Sender(setSize,sendSet, numThreads);
		});

		Receiver(setSize, recvSet, numThreads);

		thrd.join();

	}
	else if (argc == 3 && argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 0) {
		Sender(setSize, sendSet, numThreads);
	}
	else if (argc == 3 && argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 1) {
		Receiver(setSize, sendSet, numThreads);
	}
	else {
		usage(argv[0]);
	}


	
  
	return 0;
}
