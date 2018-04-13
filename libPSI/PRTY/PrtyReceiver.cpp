#include "PrtyReceiver.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include "Tools/SimpleIndex.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "Poly/polyFFT.h"


using namespace std;
using namespace NTL;

namespace osuCrypto
{
	void PrtyReceiver::init(u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		mPsiSecParam = psiSecParam;
		mPrng.SetSeed(prng.get<block>());
		mFieldSize = 512; // TODO
		mNumBins = inputs.size()/ expBinsize;

		std::vector<block> baseOtRecv(128);
		BitVector baseOtChoices(128);
		baseOtChoices.randomize(mPrng);
		NaorPinkas baseOTs;
		baseOTs.receive(baseOtChoices, baseOtRecv, mPrng, chls[0], 1);

		IknpOtExtSender sendIKNP;
		sendIKNP.setBaseOts(baseOtRecv, baseOtChoices);
	
		std::vector<std::array<block, 2>>  OtKeys(mFieldSize);
		sendIKNP.send(OtKeys, mPrng, chls[0]);

		mAesT.resize(mFieldSize);
		mAesU.resize(mFieldSize);
		for (u64 i = 0; i < mFieldSize; i++)
		{
			mAesT[i].setKey(OtKeys[i][0]);
			mAesU[i].setKey(OtKeys[i][1]);
		}

		mRowT.resize(inputs.size());
		mRowU.resize(inputs.size());


		//+mOneBlocks.resize(128);
		fillOneBlock(mOneBlocks);

#ifdef NTL_Threads_ON
		GenGermainPrime(mPrime, primeLong);
#else
		std::cout << IoStream::lock;
		GenGermainPrime(mPrime, primeLong);
		std::cout << IoStream::unlock;
#endif // NTL_Threads_ON

	}
	void PrtyReceiver::output(span<block> inputs, span<Channel> chls)
	{
		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 hashMaskBytes = (40 + 2 * log2(inputs.size()) + 7) / 8;

		//=====================Balaced Allocation=====================
		SimpleIndex simple;
		//gTimer.reset();
		simple.init(inputs.size(), maxBinSize, numDummies);
		simple.insertItems(inputs);
		gTimer.setTimePoint("binning");
		//std::cout << gTimer << std::endl;
		
		/*std::cout << IoStream::lock;
		simple.print(inputs);
		std::cout << IoStream::unlock;*/


		//=====================Poly=====================
		auto routine = [&](u64 t)
		{
			auto& chl = chls[t];
			u64 binStartIdx = simple.mNumBins * t / numThreads;
			u64 tempBinEndIdx = (simple.mNumBins * (t + 1) / numThreads);
			u64 binEndIdx = std::min(tempBinEndIdx, simple.mNumBins);
			block temp;

			polyNTL poly;
			poly.NtlPolyInit(128 / 8);

			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);
				
				sendBuff.resize(curStepSize*simple.mMaxBinSize*numSuperBlocks*sizeof(block));
				std::unordered_map<u64, block> localMasks;
				localMasks.reserve(curStepSize*simple.mMaxBinSize);

				std::vector<std::array<block, numSuperBlocks>> rowT(curStepSize*simple.mMaxBinSize);
				std::vector<u64> subIdxItems(curStepSize*simple.mMaxBinSize);

				u64 iterSend = 0;

				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;

					std::vector<std::array<block, numSuperBlocks>> rowU(simple.mMaxBinSize);
					std::vector<std::array<block, numSuperBlocks>> rowR(simple.mMaxBinSize);
					u64 cntRows = 0;
					//=====================Compute OT row=====================
					for (auto it = simple.mBins[bIdx].values.begin(); it != simple.mBins[bIdx].values.end(); ++it)
					{
						for (u64 idx = 0; idx < it->second.size(); idx++)
						{
							//std::cout << "\t" << inputs[it->second[idx]] << std::endl;
							prfOtRow(inputs[it->second[idx]], rowT[k*simple.mMaxBinSize+cntRows], mAesT);
							prfOtRow(inputs[it->second[idx]], rowU[cntRows], mAesU);
							subIdxItems[k*simple.mMaxBinSize + cntRows] = it->second[idx];
							cntRows++;
						}
					}

					//std::cout << simple.mBins[bIdx].cnt << "\t" << cntRows << "\n";
					//comput R=T+U
					for (u64 idx = 0; idx < cntRows; ++idx)
						for (u64 j = 0; j < numSuperBlocks; ++j)
							rowR[idx][j] = rowT[k*simple.mMaxBinSize + idx][j] ^ rowU[idx][j];

					
					//=====================Pack=====================
#ifndef NTL_Threads_ON
					std::cout << IoStream::lock;
#endif // NTL_Threads_O

					u64 degree = simple.mMaxBinSize - 1;
					std::vector<block> X(cntRows), Y(cntRows), coeffs;

					for (u64 idx = 0; idx < cntRows; ++idx)
						memcpy((u8*)&X[idx], (u8*)&inputs[subIdxItems[k*simple.mMaxBinSize + idx]], sizeof(block));

					for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
					{
						for (u64 idx = 0; idx < cntRows; ++idx)
							memcpy((u8*)&Y[idx], (u8*)&rowR[idx][j], sizeof(block));

						poly.getBlkCoefficients(degree,X , Y, coeffs);  //pad with dummy here

						
						for (int c = 0; c<coeffs.size(); c++) {
							memcpy(sendBuff.data() + iterSend , (u8*)&coeffs[c], sizeof(block));
							iterSend+= sizeof(block);
						}

					}
#ifndef NTL_Threads_ON
					std::cout << IoStream::unlock;
#endif // NTL_Threads_O


#if 0

					ZZ_p::init(ZZ(mPrime));
					u64 degree = rowR.size() - 1;
					ZZ_p::init(ZZ(mPrime));
					ZZ_p* zzX = new ZZ_p[rowR.size()];
					ZZ_p* zzY = new ZZ_p[rowR.size()];
					ZZ zz;
					ZZ_pX *M = new ZZ_pX[degree * 2 + 1];;
					ZZ_p *a = new ZZ_p[degree + 1];;
					ZZ_pX* temp = new ZZ_pX[degree * 2 + 1];
					ZZ_pX Polynomial;

					for (u64 idx = 0; idx < cntRows; ++idx)
					{
						ZZFromBytes(zz, (u8*)&inputs[subIdxItems[k*simple.mMaxBinSize + idx]], sizeof(block));
						zzX[idx] = to_ZZ_p(zz);
					}

					for (u64 idx = cntRows; idx < rowR.size(); ++idx) //dummy
						random(zzX[idx]);

					prepareForInterpolate(zzX, degree, M, a, 1, mPrime);

					for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
					{
						for (u64 idx = 0; idx < rowR.size(); ++idx)
						{
							ZZFromBytes(zz, (u8*)&rowR[idx][j], sizeof(block));
							zzY[idx] = to_ZZ_p(zz);
						}

						iterative_interpolate_zp(Polynomial, temp, zzY, a, M, degree * 2 + 1, 1, mPrime);

						for (int c = 0; c<degree; c++) {
							BytesFromZZ(sendBuff.data() + (k*j*rowR.size() + c) * sizeof(block), rep(Polynomial.rep[c]), sizeof(block));
						}
					}
#endif

				}

				chl.asyncSend(std::move(sendBuff)); //send poly
				sendBuff.clear();

#if 1
				block cipher;
				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 realRows = simple.mBins[i + k].cnt;

					for (u64 idx = 0; idx < realRows; ++idx)
					{
						for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
							cipher = simple.mAesHasher.ecbEncBlock(rowT[k*simple.mMaxBinSize + idx][j]) ^ cipher; //compute H(Q+s*P)=xor of all slices
					
						localMasks.emplace(*(u64*)&cipher, cipher);
					}
				}

				chl.recv(recvBuff); //receive Hash
				if (recvBuff.size() != curStepSize*simple.mMaxBinSize*hashMaskBytes)
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}

				auto theirMasks = recvBuff.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					for (u64 idx = 0; idx < simple.mMaxBinSize; ++idx)
					{
						auto& msk = *(u64*)(theirMasks);

						// check 64 first bits
						auto match = localMasks.find(msk);

						//if match, check for whole bits
						if (match != localMasks.end())
						{
							if (memcmp(theirMasks, &match->second, hashMaskBytes) == 0) // check full mask
							{
								mIntersection.push_back(inputs[subIdxItems[k*simple.mMaxBinSize + idx]]);
								std::cout << "#id: " << subIdxItems[k*simple.mMaxBinSize + idx] << std::endl;
							}
						}
						theirMasks += hashMaskBytes;
					}
				}
#endif

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

		gTimer.setTimePoint("End");




	//	std::cout << "Outputs.size() " <<Outputs.size() << std::endl;

	}
}
