#include "PrtySender.h"

#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/Base/naor-pinkas.h"
#include "libPSI/PsiDefines.h"
#include "Tools/SimpleIndex.h"

namespace osuCrypto
{
    using namespace std;


	void PrtySender::init(u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		mPsiSecParam = psiSecParam;
		mPrng.SetSeed(prng.get<block>());
		recvOprf.configure(false, psiSecParam, 128);
		sendOprf.configure(false, psiSecParam, 128);

		u64 baseCount = sendOprf.getBaseOTCount();


		NaorPinkas baseOTs;
		mBaseOTSend.resize(baseCount);
		baseOTs.send(mBaseOTSend, mPrng, chls[0], 1);
		recvOprf.setBaseOts(mBaseOTSend);

		mBaseChoice.resize(baseCount);
		mBaseChoice.randomize(mPrng);
		mBaseOTRecv.resize(baseCount);
		baseOTs.receive(mBaseChoice, mBaseOTRecv, mPrng, chls[0], 1);
		sendOprf.setBaseOts(mBaseOTRecv, mBaseChoice);

		
		std::cout << "baseCount "<< baseCount << std::endl;

		

	}

	void PrtySender::output(span<block> inputs, span<Channel> chls)
	{
		
		u64 numThreads(chls.size());
		SimpleIndex simple;
		simple.init(inputs.size(),false);
		simple.insertItems(inputs, numThreads);
		//simple.print();
		//std::cout << IoStream::lock << "Sender: " << simple.mMaxBinSize << "\t " << simple.mNumBins<< std::endl << IoStream::unlock;

		u64 theirMaxBinSize = simple.mMaxBinSize + 1; //assume same set size, sender has mMaxBinSize, receiver has mMaxBinSize+1
		u64	numOTs = simple.mNumBins*simple.mMaxBinSize;
	
		std::vector<std::vector<block>> Sr(simple.mNumBins);
		for (u64 i = 0; i < simple.mNumBins; i++)
			Sr[i].resize(simple.mMaxBinSize);

		recvOprf.init( numOTs, mPrng, chls[0]); 
		sendOprf.init(numOTs, mPrng, chls[0]); //PEQT

		IknpOtExtSender sendIKNP;
		BitVector baseChoices(128);
		std::vector<block> baseRecv(128);

		baseChoices.copy(mBaseChoice, 0, 128);
		baseRecv.assign(mBaseOTRecv.begin(), mBaseOTRecv.begin() + 128);

		/*for (u64 i = 0; i < baseRecv.size(); i++)
		{
			baseChoices[i] = mBaseChoice[i];
			baseRecv[i] = mBaseOTRecv[i];
		}*/

		sendIKNP.setBaseOts(baseRecv, baseChoices);
		std::vector<std::array<block, 2>> sendOTMsg(numOTs);
		sendIKNP.send(sendOTMsg, mPrng, chls[0]);


		//poly
		u64 polyMaskBytes = (mPsiSecParam + log2(theirMaxBinSize + 1) + 7) / 8;


		auto routine = [&](u64 t)
		{
			auto& chl = chls[t];
			u64 binStartIdx = simple.mNumBins * t / numThreads;
			u64 tempBinEndIdx = (simple.mNumBins * (t + 1) / numThreads);
			u64 binEndIdx = std::min(tempBinEndIdx, simple.mNumBins);
			
			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);
				std::vector<block> recvEncoding(curStepSize*simple.mMaxBinSize);

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
	}

}
