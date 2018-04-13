#include "PrtySender.h"

#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/Base/naor-pinkas.h"
#include "Tools/SimpleIndex.h"
#include <unordered_map>

namespace osuCrypto
{
    using namespace std;
	using namespace NTL;


	void PrtySender::init(u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		
		mPsiSecParam = psiSecParam;
		mPrng.SetSeed(prng.get<block>());
		mFieldSize = 512; // TODO
		 mNumBins = inputs.size() / expBinsize;
		 std::cout << "mNumBins "<< mNumBins << "\n";
		std::vector<std::array<block, 2>> baseOtSend(128);
		NaorPinkas baseOTs;
		baseOTs.send(baseOtSend, mPrng, chls[0], 1);


		
		IknpOtExtReceiver recvIKNP;
		recvIKNP.setBaseOts(baseOtSend);

		mOtChoices.resize(mFieldSize);
		mOtChoices.randomize(mPrng);
		std::vector<block> OtKeys(mFieldSize);

		recvIKNP.receive(mOtChoices, OtKeys, mPrng, chls[0]);

		mAesQ.resize(mFieldSize);
		for (u64 i = 0; i < mFieldSize; i++)
			mAesQ[i].setKey(OtKeys[i]);

		mRowQ.resize(inputs.size());
		//mOneBlocks.resize(128);
		fillOneBlock(mOneBlocks);
		
#ifdef NTL_Threads_ON
		GenGermainPrime(mPrime, primeLong);
#else
		std::cout << IoStream::lock;
		GenGermainPrime(mPrime, primeLong);
		std::cout << IoStream::unlock;
#endif // NTL_Threads_ON

		

	}

	void PrtySender::output(span<block> inputs, span<Channel> chls)
	{
		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 hashMaskBytes = (40+2*log2(inputs.size())+7) / 8;
		auto choiceBlocks = mOtChoices.getSpan<block>(); //s

		//=====================Balaced Allocation=====================
		SimpleIndex simple;
		//gTimer.reset();
		//gTimer.setTimePoint("start");
		simple.init(inputs.size(),mNumBins, numDummies);
		simple.insertItems(inputs);
		//gTimer.setTimePoint("balanced");
		//std::cout << gTimer << std::endl;

	/*	std::cout << IoStream::lock;
		simple.print(inputs);
		std::cout << IoStream::unlock;*/

		//=====================Compute OT row=====================
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

				
				std::vector<std::array<block, numSuperBlocks>> rowQ(curStepSize*simple.mMaxBinSize);
				std::vector<u64> subIdxItems(curStepSize*simple.mMaxBinSize);


				u64 iterSend = 0, iterRecv = 0;


				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					u64 cntRows = 0;

					//=====================Compute OT row=====================
					for (auto it = simple.mBins[bIdx].values.begin(); it != simple.mBins[bIdx].values.end(); ++it)
					{
						for (u64 idx = 0; idx < it->second.size(); idx++)
						{
							//std::cout << "\t" << inputs[it->second[idx]] << std::endl;
							prfOtRow(inputs[it->second[idx]], rowQ[k*simple.mMaxBinSize + cntRows], mAesQ);
							subIdxItems[k*simple.mMaxBinSize + cntRows] = it->second[idx];
							cntRows++;
						}
					}

				}
				
				chl.recv(recvBuff); //receive Poly


			/*		if (recvBuff.size() != curStepSize*simple.mMaxBinSize*numSuperBlocks * sizeof(block));
					{
						int aa = curStepSize*simple.mMaxBinSize*numSuperBlocks * sizeof(block);
						std::cout << recvBuff.size() << "\t" <<aa << std::endl;

						std::cout << "error @ " << (LOCATION) << std::endl;
						throw std::runtime_error(LOCATION);
					}*/

					//=====================Unpack=====================
				for (u64 k = 0; k < curStepSize; ++k)
				{
					sendBuff.resize(curStepSize*simple.mMaxBinSize*hashMaskBytes);
					u64 bIdx = i + k;
					u64 realRows = simple.mBins[bIdx].cnt;
					std::vector<block> finalHashes(simple.mMaxBinSize);

#ifndef NTL_Threads_ON
					std::cout << IoStream::lock;
#endif // NTL_Threads_O
					

					u64 degree = simple.mMaxBinSize - 1;
					std::vector<block> X(realRows), R(realRows), coeffs(simple.mMaxBinSize);
					block rcvBlk;
					NTL::GF2E e;
					NTL::vec_GF2E vecX;

					for (u64 idx = 0; idx < realRows; ++idx)
					{
						poly.GF2EFromBlock(e, inputs[subIdxItems[k*simple.mMaxBinSize + idx]], poly.mNumBytes);
						vecX.append(e);
					}

					for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
					{
						for (int c = 0; c < coeffs.size(); c++) {
							memcpy((u8*)&coeffs[c], recvBuff.data() + iterSend, sizeof(block));
							iterSend += sizeof(block);
						}
						poly.evalPolynomial(coeffs, vecX, R);

						for (int idx = 0; idx < realRows; idx++) {
							rcvBlk = rowQ[k*simple.mMaxBinSize + idx][j] ^ (R[idx] & choiceBlocks[j]); //Q+s*P

							finalHashes[idx] = simple.mAesHasher.ecbEncBlock(rcvBlk) ^ finalHashes[idx]; //compute H(Q+s*P)=xor of all slices
						}

						for (int idx = realRows; idx < simple.mMaxBinSize; idx++) {
							finalHashes[idx] = mPrng.get<block>(); //dummy
						}

					}

					for (int idx = 0; idx < finalHashes.size(); idx++) {
						memcpy(sendBuff.data() + iterRecv, (u8*)&finalHashes[idx], hashMaskBytes);
						iterRecv += hashMaskBytes;
					}
#ifndef NTL_Threads_ON
					std::cout << IoStream::unlock;
#endif // NTL_Threads_O

				}

#if 0

					u64 degree = rowQ.size() - 1;
					ZZ_p::init(ZZ(mPrime));
					ZZ zz;
					ZZ_p* zzX = new ZZ_p[subIdxItems.size()];
					ZZ_p* zzY = new ZZ_p[rowQ.size()];
					ZZ_pX* p_tree = new ZZ_pX[degree * 2 + 1];
					block rcvBlk;
					ZZ_pX recvPoly;
					ZZ_pX* reminders = new ZZ_pX[degree * 2 + 1];



					for (u64 idx = 0; idx < subIdxItems.size(); ++idx)
					{
						ZZFromBytes(zz, (u8*)&inputs[subIdxItems[idx]], sizeof(block));
						zzX[idx] = to_ZZ_p(zz);
					}

					build_tree(p_tree, zzX, degree * 2 + 1, 1, mPrime);


					for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
					{
						for (int c = 0; c<degree; c++) {
							memcpy((u8*)&rcvBlk, recvBuff.data() + (k*j*rowQ.size() + c) * sizeof(block), sizeof(block));
							ZZFromBytes(zz, (u8*)&rcvBlk, sizeof(block));
							SetCoeff(recvPoly, c, to_ZZ_p(zz));
						}

						evaluate(recvPoly, p_tree, reminders, degree * 2 + 1, zzY, 1, mPrime);

						for (int idx = 0; idx < rowQ.size(); idx++) {
							BytesFromZZ((u8*)&rcvBlk, rep(zzY[idx]), sizeof(block));
							rcvBlk = rowQ[idx][j]^(rcvBlk&choiceBlocks[j]); //Q+s*P

							finalHashes[idx]=simple.mAesHasher.ecbEncBlock(rcvBlk)^ finalHashes[idx]; //compute H(Q+s*P)=xor of all slices
						}

					}

					for (int idx = 0; idx < finalHashes.size(); idx++) {
						memcpy(sendBuff.data() + (k*simple.mMaxBinSize+idx)*hashMaskBytes, (u8*)&finalHashes[idx], hashMaskBytes);
					}
#endif
				
				chl.asyncSend(std::move(sendBuff)); //send H(Q+s*P)

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
