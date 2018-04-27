#include "SimpleIndex.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <random>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include <numeric>
//#include <boost/math/special_functions/binomial.hpp>
//#include <boost/multiprecision/cpp_bin_float.hpp>

namespace osuCrypto
{


    void SimpleIndex::print(span<block> items)
    {
		std::cout << "mNumDummies=" << mNumDummies << std::endl;
		std::cout << "mNumBins=" << mNumBins << std::endl;
        for (u64 i = 0; i < mBins.size(); ++i)
        {
            std::cout << "SBin #" << i <<  " contains " << mBins[i].blks.size() << " elements" << std::endl;

			for (u64 j = 0; j < mBins[i].blks.size(); j++)
					std::cout << "\t" << mBins[i].blks[j] << "\t" << mBins[i].hashIdxs[j]<< std::endl;
			
            std::cout << std::endl;
        }

        std::cout << std::endl;
    }

    void SimpleIndex::init(u64 theirInputSize, u64 theirMaxBinSize, u64 theirNumDummies, u64 statSecParam)
    {
		mNumBins = 1 + theirInputSize / (theirMaxBinSize - theirNumDummies);
		mTheirMaxBinSize = theirMaxBinSize;
		mHashSeed = _mm_set_epi32(4253465, 3434565, 234435, 23987025); //hardcode hash
		mAesHasher.setKey(mHashSeed);
		mBins.resize(mNumBins);
    }

	
    void SimpleIndex::insertItems(span<block> items)
    {
		
		block cipher;
		u64 b1, b2; //2 bins index

		//1st pass
		for (u64 idxItem = 0; idxItem < items.size(); ++idxItem)
		{
			cipher = mAesHasher.ecbEncBlock(items[idxItem]);

			b1 = _mm_extract_epi64(cipher, 0) % mNumBins; //1st 64 bits for finding bin location
			b2 = _mm_extract_epi64(cipher, 1) % mNumBins; //2nd 64 bits for finding alter bin location
						

			mBins[b1].blks.push_back(items[idxItem]);
			mBins[b2].blks.push_back(items[idxItem]^OneBlock);

			mBins[b1].hashIdxs.push_back(0);
			mBins[b2].hashIdxs.push_back(1);

			/*mBins[b1].Idxs.push_back(idxItem);
			mBins[b2].Idxs.push_back(idxItem);
*/
				
		}
	}

}
