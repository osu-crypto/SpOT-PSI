#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include <unordered_map>
#include "PsiDefines.h"

namespace osuCrypto
{
	

    class SimpleIndex
    {
    public:

		struct Bin
		{
			//std::vector<item> values; //index of items
			std::vector<block> blks;
			std::vector<u8> hashIdxs;
		//	std::vector<u64> Idxs;
		};


        u64 mNumBalls, mNumBins, mNumDummies, mTheirMaxBinSize;

        std::vector<Bin> mBins;
        block mHashSeed;
		AES mAesHasher;
        void print(span<block> items) ;
		void init(u64 theirInputSize, u64 theriMaxBinSize, u64 theirNumDummies, u64 statSecParam = 40);
        void insertItems(span<block> items);
    };

}
