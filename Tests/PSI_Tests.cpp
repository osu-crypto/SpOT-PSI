#include "PSI_Tests.h"
#include "OT_Tests.h"

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
#include "Poly/polyFFT.h"
#include "PsiDefines.h"

#include "PRTY/PrtySender.h"
#include "PRTY/PrtyReceiver.h"
#include "Tools/BalancedIndex.h"
#include "Tools/SimpleIndex.h"

#include "Common.h"
#include <thread>
#include <vector>

#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#endif //  _MSC_VER


using namespace osuCrypto;

namespace tests_libOTe
{
	inline void sse_trans(uint8_t *inp, int nrows, int ncols) {
#   define INP(x,y) inp[(x)*ncols/8 + (y)/8]
#   define OUT(x,y) inp[(y)*nrows/8 + (x)/8]
		int rr, cc, i, h;
		union { __m128i x; uint8_t b[16]; } tmp;
		__m128i vec;
		assert(nrows % 8 == 0 && ncols % 8 == 0);

		// Do the main body in 16x8 blocks:
		for (rr = 0; rr <= nrows - 16; rr += 16) {
			for (cc = 0; cc < ncols; cc += 8) {
				vec = _mm_set_epi8(
					INP(rr + 15, cc), INP(rr + 14, cc), INP(rr + 13, cc), INP(rr + 12, cc), INP(rr + 11, cc), INP(rr + 10, cc), INP(rr + 9, cc),
					INP(rr + 8, cc), INP(rr + 7, cc), INP(rr + 6, cc), INP(rr + 5, cc), INP(rr + 4, cc), INP(rr + 3, cc), INP(rr + 2, cc), INP(rr + 1, cc),
					INP(rr + 0, cc));
				for (i = 8; --i >= 0; vec = _mm_slli_epi64(vec, 1))
					*(uint16_t*)&OUT(rr, cc + i) = _mm_movemask_epi8(vec);
			}
		}
		if (rr == nrows) return;

		// The remainder is a block of 8x(16n+8) bits (n may be 0).
		//  Do a PAIR of 8x8 blocks in each step:
		for (cc = 0; cc <= ncols - 16; cc += 16) {
			vec = _mm_set_epi16(
				*(uint16_t const*)&INP(rr + 7, cc), *(uint16_t const*)&INP(rr + 6, cc),
				*(uint16_t const*)&INP(rr + 5, cc), *(uint16_t const*)&INP(rr + 4, cc),
				*(uint16_t const*)&INP(rr + 3, cc), *(uint16_t const*)&INP(rr + 2, cc),
				*(uint16_t const*)&INP(rr + 1, cc), *(uint16_t const*)&INP(rr + 0, cc));
			for (i = 8; --i >= 0; vec = _mm_slli_epi64(vec, 1)) {
				OUT(rr, cc + i) = h = _mm_movemask_epi8(vec);
				OUT(rr, cc + i + 8) = h >> 8;
			}
		}
		if (cc == ncols) return;

		//  Do the remaining 8x8 block:
		for (i = 0; i < 8; ++i)
			tmp.b[i] = INP(rr + i, cc);
		for (i = 8; --i >= 0; tmp.x = _mm_slli_epi64(tmp.x, 1))
			OUT(rr, cc + i) = _mm_movemask_epi8(tmp.x);
#undef INP
#undef OUT
	}

	void OT_Receive_Test(BitVector& choiceBits, gsl::span<block> recv, gsl::span<std::array<block, 2>>  sender)
	{

		for (u64 i = 0; i < choiceBits.size(); ++i)
		{

			u8 choice = choiceBits[i];
			const block & revcBlock = recv[i];
			//(i, choice, revcBlock);
			const block& senderBlock = sender[i][choice];

			//if (i%512==0) {
			//    std::cout << "[" << i << ",0]--" << sender[i][0] << std::endl;
			//    std::cout << "[" << i << ",1]--" << sender[i][1] << std::endl;
			//    std::cout << (int)choice << "-- " << recv[i] << std::endl;
			//}
			if (neq(revcBlock, senderBlock))
				throw UnitTestFail();

			if (eq(revcBlock, sender[i][1 ^ choice]))
				throw UnitTestFail();
		}

	}

    void Hashing_Test_Impl()
	{
		setThreadName("Sender");
		u64 setSize = 1<<10, psiSecParam = 40,  numThreads(2);

		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


		std::vector<block> set(setSize);
		for (u64 i = 0; i < set.size(); ++i)
			set[i] = prng.get<block>();

		BalancedIndex balance;
		gTimer.reset();
		gTimer.setTimePoint("start");
		balance.init(setSize,40,1);
		balance.insertItems(set);
		gTimer.setTimePoint("end");
		std::cout << gTimer << std::endl;
		balance.check();
		balance.print(set);

		SimpleIndex simple;
		gTimer.reset();
		gTimer.setTimePoint("start");
		simple.init(setSize, 40, 1);
		simple.insertItems(set);
		gTimer.setTimePoint("end");
		std::cout << gTimer << std::endl;
		simple.print(set);

	}

	void myTest() {
		BitVector a(2);
		a[0] = 1;
		a[1] = 0;

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

		u8 aa=a[0] ^ a[1];
		std::cout << unsigned(aa) << std::endl;
		std::cout << sizeof(u8) << std::endl;
		

		block temp = prng0.get<block>();

		u64 b1 = _mm_extract_epi64(temp, 0);
		u64 b2 = _mm_extract_epi64(temp, 1);
		//u64 b2 = *(u64*)(&temp + sizeof(u64));

		block aa2 = toBlock(b1, b2);

		std::cout << temp << std::endl;


		std::cout << aa2 << std::endl;
		 aa2 = toBlock(b2, b1);

		std::cout << aa2 << std::endl;



	}

	void NTL_Poly_Test_Impl() {
		std::mutex mtx;

		auto routines = [&](u64 t)
		{

			polyNTL poly;
			poly.NtlPolyInit(8);
			PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

			std::vector<block> setX(10);
			std::vector<block> setY(10, prng0.get<block>());

			block a = prng0.get<block>();
			for (u64 i = 0; i < 4; ++i)
			{
				setX[i] = prng0.get<block>();
			}

			block b = prng0.get<block>();
			for (u64 i = 5; i < setX.size(); ++i)
			{
				setX[i] = prng0.get<block>();
			}

			setY[9] = prng0.get<block>();



			NTL::vec_GF2E x; NTL::vec_GF2E y;
			NTL::GF2E e;

			for (u64 i = 0; i < setX.size(); ++i)
			{
				poly.GF2EFromBlock(e, setX[i], poly.mNumBytes);
				//NTL::random(e);
				x.append(e);
				//NTL::random(e);
				poly.GF2EFromBlock(e, setY[i], poly.mNumBytes);

				//polyNTL::GF2EFromBlock(e, setY[i], mNumBytes);
				y.append(e);
			}


			NTL::GF2EX polynomial = NTL::interpolate(x, y);



			std::vector<block> coeffs;
			poly.getBlkCoefficients(11, setX, setY, coeffs);

			block y1 = ZeroBlock;
			poly.evalPolynomial(coeffs, setX[0], y1);

			std::lock_guard<std::mutex> lock(mtx);
			std::cout << setY[0] << "\t" << y1 << std::endl;

		};

		std::vector<std::thread> thrds(1);
		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				routines(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();
	}


	using namespace std;
	using namespace NTL;

	void Poly_Test_Impl() {

		long degree = 66;
		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


		{
			std::vector<block> X(degree + 1), Y(degree + 1), Y2(degree + 1),coeffs;
			for (u64 i = 0; i < X.size(); ++i)
			{
				X[i] = prng0.get<block>();
				Y[i] = prng0.get<block>();

			}

			polyNTL poly;
			poly.NtlPolyInit(128 / 8);
			poly.getBlkCoefficients(degree+2, X, Y, coeffs);

			block temp;
			poly.evalPolynomial(coeffs, X[0], temp);
			std::cout << Y[0] << "\t" << temp << "\n";

		}

		{
			ZZ prime;

			GenGermainPrime(prime, 128);

			

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



			/*ZZ_pX P1;
			for (unsigned int i = 0; i <= degree; i++) {
				SetCoeff(P1, i,P.rep[i]);
			}


			ZZ_p* y2 = new ZZ_p[degree + 1];

			ZZ_pX* p_tree = new ZZ_pX[degree * 2 + 1];
			build_tree(p_tree, xx, degree * 2 + 1, 1, prime);

			ZZ_pX* reminders = new ZZ_pX[degree * 2 + 1];
			evaluate(P, p_tree, reminders, degree * 2 + 1, y2, 1, prime);

			for (long i = 0; i< degree + 1; i++) {
				if (y2[i] != yy[i]) {
					cout << "Error! x = " << xx[i] << ", y = " << yy[i] << ", res = " << y2[i]<< endl;
				}
			}

			cout << "Polynomialxx is interpolated correctly!" << endl;



			ZZFromBytes(zz, (u8*)&X[0], sizeof(block));
			ZZ_p tt= to_ZZ_p(zz);

			ZZ_p res;
			eval(res, P, tt);

			block blkres;
			BytesFromZZ((u8*)&blkres, rep(res), sizeof(block));

			std::cout << blkres << "\n";
			std::cout << Y[0] << "\n";*/


			//test_interpolation_result_zp(P, x, y, long degree)

		}
	}


	void Prty_PSI_impl()
	{
		setThreadName("Sender");
		u64 setSize = 1 << 10, psiSecParam = 40, numThreads(1);

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));


		std::vector<block> sendSet(setSize), recvSet(setSize);
		for (u64 i = 0; i < setSize; ++i)
		{
			sendSet[i] = prng0.get<block>();
			recvSet[i] = prng0.get<block>();
		}
		for (u64 i = 0; i < 10; ++i)
		{
			sendSet[i] =recvSet[i] ;
		}

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

		
		fillOneBlock(mOneBlocks);

		auto thrd = std::thread([&]() {
			recv.init(40, prng1, recvSet, recvChls);
			
			
			//std::array<block, numSuperBlocks> tT,tU;
			//prfOtRows(recvSet.data(), recvSet.size(), recv.mRowT, recv.mAesT);
			//prfOtRows(recvSet.data(), recvSet.size(),recv.mRowU, recv.mAesU);

			prfOtRow(recvSet[0], recv.mRowT[0], recv.mAesT);
			prfOtRow(recvSet[0],recv.mRowU[0], recv.mAesU);
			prfOtRow(recvSet[1], recv.mRowT[1], recv.mAesT);
			prfOtRow(recvSet[1], recv.mRowU[1], recv.mAesU);

			recv.output(recvSet, recvChls);

		});

		sender.init(40, prng0, sendSet, sendChls);
		

		//prfOtRows(sendSet.data(), sendSet.size(), sender.mRowQ, sender.mAesQ);
		prfOtRow(sendSet[0], sender.mRowQ[0], sender.mAesQ);
		prfOtRow(sendSet[1], sender.mRowQ[1], sender.mAesQ);

		sender.output(sendSet, sendChls);


		thrd.join();


		std::cout << "recv.mIntersection.size(): " << recv.mIntersection.size() << std::endl;
		for (u64 i = 0; i < recv.mIntersection.size(); ++i)//thrds.size()
		{
				std::cout << "#id: " << recv.mIntersection[i] <<
					"\t" << recvSet[recv.mIntersection[i]] << std::endl;
		}
		//check correct OT
		for (int i = 0; i < 0; ++i) {

			for (int j = 0; j < numSuperBlocks; ++j) {
				std::cout << sender.mRowQ[i][j] << "\n";
				block test;
				test = recv.mRowT[i][j] ^ recv.mRowU[i][j];
				auto choiceBlocks = sender.mOtChoices.getSpan<block>();

				test = (test&choiceBlocks[j]) ^ recv.mRowT[i][j];
				std::cout << test << "\n";
			}
		}


		//check More

			for (int j = 0; j < numSuperBlocks; ++j) {
				std::cout << sender.mRowQforDebug[j] << "\t";
				std::cout << recv.mRowTforDebug[j] << "\t";
				std::cout << recv.mRowUforDebug[j]<< "\n";
				block P;
				P = recv.mRowTforDebug[j] ^ recv.mRowUforDebug[j];
				auto choiceBlocks = sender.mOtChoices.getSpan<block>();

				block q=(P&choiceBlocks[j]) ^ sender.mRowQforDebug[j];
				std::cout << q << "\n";
			}


		for (u64 i = 0; i < numThreads; ++i)

		{
			sendChls[i].close(); recvChls[i].close();
		}

		ep0.stop(); ep1.stop();	ios.stop();

		
		
	

	}

}