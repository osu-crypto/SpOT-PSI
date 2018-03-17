#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "Poly/polyNTL.h"

#include <array>
namespace osuCrypto {

	class PrtySender :public TimerAdapter
	{
	public:

		
		bool mHasBase;

		u64 mNumOTs, mPolyNumBytes, mPolyDegree, mStepSize, mPsiSecParam;
		std::vector<block> mS;
		KkrtNcoOtReceiver recvOprf;
		KkrtNcoOtSender sendOprf; //PQET
		

		polyNTL poly;
		PRNG mPrng;
		
		std::vector<block> mBaseOTRecv;
		BitVector mBaseChoice;
		std::vector<std::array<block, 2>> mBaseOTSend;

		void init(u64 psiSecParam, PRNG& prng, span<block> inputs, span<Channel> chls);
		void output(span<block> inputs, span<Channel> chls);
	};
}

