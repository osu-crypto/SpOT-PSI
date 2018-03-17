#include "PrtyReceiver.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include "libPSI/PsiDefines.h"
#include "Tools/SimpleIndex.h"

using namespace std;

namespace osuCrypto
{
	void PrtyReceiver::init(u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		mPsiSecParam = psiSecParam;
		mPrng.SetSeed(prng.get<block>());

		sendOprf.configure(false, psiSecParam, 128);
		recvOprf.configure(false, psiSecParam, 128);

		u64 baseCount= sendOprf.getBaseOTCount();

		mBaseChoice.resize(baseCount);
		mBaseChoice.randomize(mPrng);
		mBaseOTRecv.resize(baseCount);
		NaorPinkas baseOTs;
		baseOTs.receive(mBaseChoice, mBaseOTRecv, mPrng, chls[0], 1);
		sendOprf.setBaseOts(mBaseOTRecv, mBaseChoice);


		mBaseOTSend.resize(baseCount);
		baseOTs.send(mBaseOTSend, mPrng, chls[0], 1);
		recvOprf.setBaseOts(mBaseOTSend);

		

	}
	void PrtyReceiver::output(span<block> inputs, span<Channel> chls)
	{
		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;

		std::mutex mtx;

		SimpleIndex simple;
		simple.init(inputs.size(),true);
		simple.insertItems(inputs, numThreads);
		//simple.print();

		//std::cout << "Receiver: " << simple.mMaxBinSize << "\t " <<simple.mNumBins<< std::endl ;

		u64 theirMaxBinSize = simple.mMaxBinSize - 1; //assume same set size, sender has mMaxBinSize, receiver has mMaxBinSize+1
		u64	numOTs = simple.mNumBins*(theirMaxBinSize);

		std::vector<block> coeffs;
		
		std::vector<std::vector<block>> Ss(simple.mNumBins);
		for (u64 i = 0; i < simple.mNumBins; i++)
		{
			Ss[i].resize(theirMaxBinSize);
			for (u64 j = 0; j < theirMaxBinSize; j++)
				Ss[i][j] = mPrng.get<block>();
		}

		std::cout << IoStream::lock << "mBins[1].items[1]  " << simple.mBins[1].items[1] << std::endl << IoStream::unlock;
		std::cout << IoStream::lock << "Ss[1] " << Ss[1][1]<< std::endl << IoStream::unlock;

		sendOprf.init(numOTs, mPrng, chls[0]);
		recvOprf.init(numOTs, mPrng, chls[0]);//PEQT
	
		
		IknpOtExtReceiver recvIKNP;
		std::vector<std::array<block, 2>> baseOTSend(128);

		for (u64 i = 0; i < baseOTSend.size(); i++)
		{
			baseOTSend[i][0] = mBaseOTSend[i][0];
			baseOTSend[i][1] = mBaseOTSend[i][1];
		}
		recvIKNP.setBaseOts(baseOTSend);

		BitVector choicesOT(numOTs); choicesOT.randomize(mPrng);
		std::vector<block> recvOTMsg(numOTs);
		recvIKNP.receive(choicesOT, recvOTMsg, mPrng, chls[0]);

		std::cout << IoStream::lock << recvOTMsg[0] << std::endl << IoStream::unlock;

		//poly
		u64 polyMaskBytes = (mPsiSecParam + log2(simple.mMaxBinSize + 1) + 7) / 8;

		auto routine = [&](u64 t)
		{
			auto& chl = chls[t];
			u64 binStartIdx = simple.mNumBins * t / numThreads;
			u64 tempBinEndIdx = (simple.mNumBins * (t + 1) / numThreads);
			u64 binEndIdx = std::min(tempBinEndIdx, simple.mNumBins);
			
#ifdef NTL_Threads
			std::cout << IoStream::lock;
			polyNTL poly;
			poly.NtlPolyInit(polyMaskBytes);//length=lambda +log(|Y|)
			std::cout << IoStream::unlock;
#else
			polyNTL poly;
			poly.NtlPolyInit(polyMaskBytes);//length=lambda +log(|Y|)
#endif

			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);

				sendOprf.recvCorrection(chl, curStepSize*theirMaxBinSize);

				std::vector<u8> sendBuff(curStepSize*theirMaxBinSize*(simple.mMaxBinSize + 1)*polyMaskBytes);

				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 binIdx = i + k;
				}
				

			}
		};


		std::vector<std::thread> thrds(chls.size());
		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		std::cout << "Outputs.size() " <<Outputs.size() << std::endl;

	}
}
