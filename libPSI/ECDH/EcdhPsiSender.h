#pragma once

#include "cryptoTools/Common/Defines.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace osuCrypto
{
    class EcdhPsiSender
    {
    public:
        EcdhPsiSender();
        ~EcdhPsiSender();

		u64 stepSize = 1<<6;

        u64 mN, mSecParam;
        PRNG mPrng;

        void init(u64 n, u64 secParam, block seed);
        //void init(u64 n, u64 statSecParam);


		void sendInput_k283(std::vector<block>& inputs, span<Channel> chl);
		void sendInput_Curve25519(std::vector<block>& inputs, span<Channel> chl);
		void sendInput(std::vector<block>& inputs, span<Channel> chl, int curveType);
        //void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
    };

}