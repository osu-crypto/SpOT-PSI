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


    void SimpleIndex::print()
    {
		std::cout << "mMaxBinSize=" << mMaxBinSize << std::endl;
		std::cout << "mNumBins=" << mNumBins << std::endl;
        for (u64 i = 0; i < mBins.size(); ++i)
        {
            std::cout << "Bin #" << i << std::endl;

            std::cout << " contains " << mBins[i].mBinRealSizes << " elements" << std::endl;

            for (u64 j = 0; j < mBins[i].items.size(); ++j)
                std::cout << "    idx=" << mBins[i].items[j] << std::endl;
			
            std::cout << std::endl;
        }

        std::cout << std::endl;
    }

#if 0
    //template<unsigned int N = 16>
    double getBinOverflowProb(u64 numBins, u64 numBalls, u64 binSize, double epsilon = 0.0001)
    {
        if (numBalls <= binSize)
            return std::numeric_limits<double>::max();

        if (numBalls > std::numeric_limits<i32>::max())
        {
            auto msg = ("boost::math::binomial_coefficient(...) only supports " + std::to_string(sizeof(unsigned) * 8) + " bit inputs which was exceeded." LOCATION);
            std::cout << msg << std::endl;
            throw std::runtime_error(msg);
        }

        //std::cout << numBalls << " " << numBins << " " << binSize << std::endl;
        typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_bin_float<16>> T;
        T sum = 0.0;
        T sec = 0.0;// minSec + 1;
        T diff = 1;
        u64 i = binSize + 1;


        while (diff > T(epsilon) && numBalls >= i /*&& sec > minSec*/)
        {
            sum += numBins * boost::math::binomial_coefficient<T>(i32(numBalls), i32(i))
                * boost::multiprecision::pow(T(1.0) / numBins, i) * boost::multiprecision::pow(1 - T(1.0) / numBins, numBalls - i);

            //std::cout << "sum[" << i << "] " << sum << std::endl;

            T sec2 = boost::multiprecision::log2(sum);
            diff = boost::multiprecision::abs(sec - sec2);
            //std::cout << diff << std::endl;
            sec = sec2;

            i++;
        }

        return std::max<double>(0, (double)-sec);
    }

    u64 SimpleIndex::get_bin_size(u64 numBins, u64 numBalls, u64 statSecParam)
    {

        auto B = std::max<u64>(1, numBalls / numBins);

        double currentProb = getBinOverflowProb(numBins, numBalls, B);
        u64 step = 1;

        bool doubling = true;

        while (currentProb < statSecParam || step > 1)
        {
            if (!step)
                throw std::runtime_error(LOCATION);


            if (statSecParam > currentProb)
            {
                if (doubling) step = std::max<u64>(1, step * 2);
                else          step = std::max<u64>(1, step / 2);

                B += step;
            }
            else
            {
                doubling = false;
                step = std::max<u64>(1, step / 2);
                B -= step;
            }
            currentProb = getBinOverflowProb(numBins, numBalls, B);
        }

        return B;
    }

#endif

    void SimpleIndex::init(u64 numBalls, bool isReceiver, u64 statSecParam)
    {
		if (numBalls <= 1 << 8)
		{
			mNumBins = 0.0430*numBalls;
			mMaxBinSize = 63;
		}
		else if (numBalls <= 1 << 12)
		{
			mNumBins = 0.0557*numBalls;
			mMaxBinSize = 59;
		}
		else if (numBalls <= 1 << 16)
		{
			mNumBins = 0.0491*numBalls;
			mMaxBinSize = 66;
		}
		else if (numBalls <= 1 << 20)
		{
			mNumBins = 0.0470*numBalls;
			mMaxBinSize = 70;
		}
		else
			throw std::runtime_error("not implemented");

		mBins.resize(mNumBins);
		
		if (isReceiver) 
			mMaxBinSize += 1;

		/*for (u64 i = 0; i < mBins.size(); i++)
		{
			mBins[i].items.resize(mMaxBinSize);
		}*/

		mBlkDefaut = OneBlock;

    }


    void SimpleIndex::insertItems(span<block> items, u64 numThreads)
    {

        AES hasher(mHashSeed);
		u64 inputSize = items.size();
		std::mutex mtx;
		const bool isMultiThreaded = numThreads > 1;

		auto routineHashing = [&](u64 t)
		{
			u64 inputStartIdx = inputSize * t / numThreads;
			u64 tempInputEndIdx = (inputSize * (t + 1) / numThreads);
			u64 inputEndIdx = std::min(tempInputEndIdx, inputSize);

			for (u64 i = inputStartIdx; i < inputEndIdx; ++i)
			{
				block temp = hasher.ecbEncBlock(items[i]);
				u64 addr = *(u64*)&temp % mNumBins;

					if (isMultiThreaded)
					{
						std::lock_guard<std::mutex> lock(mtx);
						mBins[addr].items.push_back(items[i]);
					}
					else
					{
						mBins[addr].items.push_back(items[i]);
					}

			}
		};

		std::vector<std::thread> thrds(numThreads);
		for (u64 i = 0; i < u64(numThreads); ++i)
		{
			thrds[i] = std::thread([=] {
				routineHashing(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();


		//For debug
		mBins[1].items[1] = AllOneBlock;


		//add a default block 
			for (u64 i = 0; i < mNumBins; ++i)
			{
				if (mBins[i].items.size()<mMaxBinSize)
					mBins[i].items.push_back(mBlkDefaut);

				mBins[i].mBinRealSizes = mBins[i].items.size();
			}

			



		//pad with default block 
		//auto routineFullBins = [&](u64 t)
		//{
		//	u64 binStartIdx = mNumBins * t / numThreads;
		//	u64 tempBinEndIdx = (mNumBins * (t + 1) / numThreads);
		//	u64 binEndIdx = std::min(tempBinEndIdx, mNumBins);

		//	for (u64 i = binStartIdx; i < binEndIdx; ++i)
		//	{
		//		mBins[i].mBinRealSizes = mBins[i].items.size();
		//		mBins[i].items.push_back(mBlkDefaut);

		//		//mBins[i].items.resize(mMaxBinSize, mBlkDefaut);

		//	}
		//};

		//for (u64 i = 0; i < u64(numThreads); ++i)
		//{
		//	thrds[i] = std::thread([=] {
		//		routineFullBins(i);
		//	});
		//}

		//for (auto& thrd : thrds)
		//	thrd.join();


    }

}
