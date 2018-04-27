#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <array>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "Poly/polyNTL.h"
#include "PsiDefines.h"
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include "Tools/BalancedIndex.h"

using namespace NTL;

namespace osuCrypto
{

    class PrtyReceiver : public TimerAdapter
    {
    public:
     
		
		bool mHasBase;
		BalancedIndex mBalance;

		u64 mMyInputSize, mTheirInputSize, mPolyNumBytes, mPolyDegree, mPsiSecParam;
		std::vector<block> mS;
		KkrtNcoOtSender sendOprf;
		KkrtNcoOtReceiver recvOprf;
		u64 mFieldSize;

		block mTruncateBlk;

		PRNG mPrng;
		ZZ mPrime;
		ZZ mPrimeLastSlice;

		////std::vector<std::array<block, 2>> mOtKeys;
		std::vector<AES> mAesT;
		std::vector<AES> mAesU;
		std::vector<u64> mIntersection; //index

		block recvMaskForDebug;
		//AES mAesHasher;

		std::array<block, numSuperBlocks> subRowTForDebug;
		std::array<block, numSuperBlocks> subRowUForDebug;

		std::vector<block> Outputs;

		void init(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG& prng, span<Channel> chls);
		void output(span<block> inputs, span<Channel> chls);
		void outputBestComm(span<block> inputs, span<Channel> chls);
		void outputBigPoly(span<block> inputs, span<Channel> chls);

		
    };

}
