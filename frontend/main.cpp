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
#include "Tools/BalancedIndex.h"

#include <thread>
#include <vector>


static u64 expectedIntersection = 100;

void usage(const char* argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t 1. For unit test: " << argv0 << " -t" << std::endl;
	std::cout << "\t 2. For simulation (2 terminal): " << std::endl;;
	std::cout << "\t\t Sender terminal: " << argv0 << " -r 0" << std::endl;
	std::cout << "\t\t Receiver terminal: " << argv0 << " -r 1" << std::endl;
}


void Sender(span<block> inputs, u64 theirSetSize, u64 numThreads = 1)
{
	u64 psiSecParam = 40;

	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	// set up networking
	std::string name = "n";
	IOService ios;
	Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);

	std::vector<Channel> sendChls(numThreads);
	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));

	PrtySender sender;
	sender.init(inputs.size(), theirSetSize,40, prng0,sendChls);
	sender.output(inputs, sendChls);


	for (u64 i = 0; i < numThreads; ++i)
		sendChls[i].close();

	ep1.stop();	ios.stop();
}

void Receiver( span<block> inputs, u64 theirSetSize, u64 numThreads=1)
{
	u64 psiSecParam = 40;

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

	recv.init(inputs.size(), theirSetSize,40, prng1,recvChls); //offline
	
	gTimer.setTimePoint("offline");
	
	recv.output(inputs, recvChls); //online
	
	gTimer.setTimePoint("End");

	std::cout << gTimer << std::endl;

	std::cout << "recv.mIntersection  : " << recv.mIntersection.size() << std::endl;
	std::cout << "expectedIntersection: " << expectedIntersection << std::endl;
	for (u64 i = 0; i < recv.mIntersection.size(); ++i)//thrds.size()
	{
		/*std::cout << "#id: " << recv.mIntersection[i] <<
			"\t" << inputs[recv.mIntersection[i]] << std::endl;*/
	}

	for (u64 i = 0; i < numThreads; ++i)
		recvChls[i].close();

	ep0.stop(); ios.stop();

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

void Hashing_Test_Impl()
{
	setThreadName("Sender");
	u64 setSize = 1 << 20, psiSecParam = 40, numThreads(1);

	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	std::vector<block> set(setSize);
	for (u64 i = 0; i < set.size(); ++i)
		set[i] = prng.get<block>();

	BalancedIndex simple;
	gTimer.reset();
	gTimer.setTimePoint("start");
	simple.init(setSize,40, 1);
	simple.insertItems(set);
	gTimer.setTimePoint("end");
	std::cout << gTimer << std::endl;
	simple.check();

//	simple.print(set);

}

int main(int argc, char** argv)
{
	/*Poly_Test_Impl();
	return 0;*/
	

	/*Hashing_Test_Impl();
	return 0;*/


	u64 sendSetSize = 1 << 20, recvSetSize =1<<20, numThreads=4;
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	std::vector<block> sendSet(sendSetSize), recvSet(recvSetSize);
	
	std::cout << "SetSize: " << sendSetSize << " vs " << recvSetSize << "\n";
	for (u64 i = 0; i < sendSetSize; ++i)
		sendSet[i] = prng0.get<block>();

	for (u64 i = 0; i < recvSetSize; ++i)
		recvSet[i] = prng0.get<block>();

	for (u64 i = 0; i < expectedIntersection; ++i)
	{
		sendSet[i] = recvSet[i];
	}

	
#if 0
	std::thread thrd = std::thread([&]() {
		Sender(sendSet, recvSetSize, numThreads);

	});

	Receiver(recvSet, sendSetSize, numThreads);


	thrd.join();
	return 0;
#endif

	

	if (argc == 2 && argv[1][0] == '-' && argv[1][1] == 't') {
		
		std::thread thrd = std::thread([&]() {
			Sender(sendSet, recvSetSize, numThreads);
		});

		Receiver(recvSet, sendSetSize, numThreads);

		thrd.join();

	}
	else if (argc == 3 && argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 0) {
		Sender(sendSet, recvSetSize, numThreads);
	}
	else if (argc == 3 && argv[1][0] == '-' && argv[1][1] == 'r' && atoi(argv[2]) == 1) {
		Receiver(recvSet, sendSetSize, numThreads);
	}
	else {
		usage(argv[0]);
	}


	
  
	return 0;
}
