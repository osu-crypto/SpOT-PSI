#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{
    //// a list of {{set size, bit size}}
    //std::vector<std::array<u64, 2>> binSizes
    //{
    //    {1<<12, 18},
    //    {1<<16, 19},
    //    {1<<20, 20},
    //    {1<<24, 21}
    //};
    /*{
        return mVal == u64(-1);
    }

    u64 CuckooIndex::Bin::idx() const
    {
        return mVal  & (u64(-1) >> 8);
    }

    u64 CuckooIndex::Bin::hashIdx() const
    {
        return mVal >> 56;*/

    class SimpleIndex
    {
    public:

		struct bin
		{
			std::vector<block> items;
			u64 mBinRealSizes;
		};

        u64 mMaxBinSize, mNumBins;
        std::vector<bin> mBins;
        block mHashSeed;
		block mBlkDefaut;
        void print() ;

        //static  u64 get_bin_size(u64 numBins, u64 numBalls, u64 statSecParam);

		void init(u64 numBalls, bool isSender=true, u64 statSecParam = 40);
        void insertItems(span<block> items, u64 numThreads);
    };

}
