#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace osuCrypto
{

    class EcdhPsiReceiver
    {
    public:
        EcdhPsiReceiver();
        ~EcdhPsiReceiver();

		u64 stepSize = 1<<6;
        u64 mN, mSecParam;
        PRNG mPrng;

        std::vector<u64> mIntersection;

        void init(u64 n, u64 secParam, block seed);

		void sendInput_k283(span<block> inputs, span<Channel> chls);
		void sendInput_Curve25519(span<block> inputs, span<Channel> chls);

        void sendInput(span<block> inputs, span<Channel> chl0,int curveType);

    };

}