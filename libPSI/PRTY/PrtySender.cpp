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
		mFieldSize = fieldSize; // TODO
		std::vector<std::array<block, 2>> baseOtSend(128);
		NaorPinkas baseOTs;
		baseOTs.send(baseOtSend, mPrng, chls[0], 1);

		fillOneBlock(mOneBlocks);

		
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
#if 1
		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 hashMaskBytes = (40+2*log2(inputs.size())+7) / 8;
	
		//u8 bit = 0;
		//block mTruncateBlk;
		//for (u64 i = 0; i < numSuperBlocks * 128 - mFieldSize; i++)
		//{
		//	mOtChoices.pushBack(bit);
		//	block temp = mm_bitshift_left(OneBlock,i);
		//}

		//u64 ishift = 0;
		//for (u64 i = (numSuperBlocks - 1) * 128; i < mFieldSize; i++)
		//{
		//	block temp = mm_bitshift_right(OneBlock, ishift++);
		//	mTruncateBlk = mTruncateBlk^temp;
		//}


		auto choiceBlocks = mOtChoices.getSpan<block>(); //s


		std::array<std::vector<u8>,2> globalHash;
		globalHash[0].resize(inputs.size()*hashMaskBytes);
		globalHash[1].resize(inputs.size()*hashMaskBytes);

		std::array<std::vector<u64>, 2>permute;
		int idxPermuteDone[2];
		for (u64 j = 0; j < 2; j++)
		{
			permute[j].resize(inputs.size());
			for (u64 i = 0; i < inputs.size(); i++)
				permute[j][i] = i;

			//permute position
			//std::shuffle(permute[j].begin(), permute[j].end(), mPrng);
			idxPermuteDone[j] = 0; //count the number of permutation that is done.
		}


		//=====================Balaced Allocation=====================
		SimpleIndex simple;
		//gTimer.reset();
		//gTimer.setTimePoint("start");
		simple.init(inputs.size(), recvMaxBinSize, recvNumDummies);
		simple.insertItems(inputs);
		inputs[simple.mBins[2].values[0].mIdx] = OneBlock;
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

			polyNTL poly;
			poly.NtlPolyInit(sizeof(block));

			/*polyNTL poly_lastBlk;
			u64 lastBlkByteSize = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);
			poly_lastBlk.NtlPolyInit(lastBlkByteSize);*/


			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);

				u64 totalStepRows=0;
				for (u64 k = 0; k < curStepSize; ++k)
					totalStepRows += simple.mBins[i + k].values.size();  //i + k=bIdx, count all items;

				std::vector<std::array<block, numSuperBlocks>> rowQ(curStepSize*totalStepRows);

				u64 iterSend = 0, iterRecv = 0;

				u64 iterRowQ = 0;
				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					//=====================Compute OT row=====================
					for (u64 idx = 0; idx < simple.mBins[bIdx].values.size(); idx++)
					{
						prfOtRow(inputs[simple.mBins[bIdx].values[idx].mIdx], rowQ[iterRowQ], mAesQ);

						//std::cout << IoStream::lock;
						//std::cout << idx << "\t S: " << inputs[simple.mBins[bIdx].values[idx].mIdx] <<
						//	"\t" << rowQ[iterRowQ][0] << "\n";
						//std::cout << IoStream::unlock;

						if (bIdx == 2 && idx==0)
						{
							for (int j = 0; j < numSuperBlocks; ++j) {
								mRowQforDebug[j] = rowQ[iterRowQ][j];
							}
						}

						iterRowQ++;
					}
				}
				std::vector<u8> recvBuff;
				chl.recv(recvBuff); //receive Poly


			/*		if (recvBuff.size() != curStepSize*simple.mMaxBinSize*numSuperBlocks * sizeof(block));
					{
						int aa = curStepSize*simple.mMaxBinSize*numSuperBlocks * sizeof(block);
						std::cout << recvBuff.size() << "\t" <<aa << std::endl;

						std::cout << "error @ " << (LOCATION) << std::endl;
						throw std::runtime_error(LOCATION);
					}*/

					//=====================Unpack=====================
				iterRowQ = 0;
				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					u64 realNumRows = simple.mBins[bIdx].values.size();
					std::vector<block> localHashes(realNumRows);

#ifndef NTL_Threads_ON
					std::cout << IoStream::lock;
#endif // NTL_Threads_O
					

					u64 degree = simple.mTheirMaxBinSize - 1;
					std::vector<block> X(realNumRows), R(realNumRows), coeffs(degree+1); //
					block rcvBlk;
					NTL::GF2E e;
					NTL::vec_GF2E vecX;

					for (u64 idx = 0; idx < realNumRows; ++idx)
					{
						poly.GF2EFromBlock(e, inputs[simple.mBins[bIdx].values[idx].mIdx], poly.mNumBytes);
						vecX.append(e);
					}

					for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
					{
						//if (j == numSuperBlocks - 1)
						//{
						//	for (int c = 0; c < coeffs.size(); c++) {
						//		memcpy((u8*)&coeffs[c], recvBuff.data() + iterSend, lastBlkByteSize);
						//		iterSend += lastBlkByteSize;
						//	}
						//	poly_lastBlk.evalPolynomial(coeffs, vecX, R);
						//}
						//else
						{
							for (int c = 0; c < coeffs.size(); c++) {
								memcpy((u8*)&coeffs[c], recvBuff.data() + iterSend, sizeof(block));
								iterSend += sizeof(block);
							}
							poly.evalPolynomial(coeffs, vecX, R);
						}

						for (int idx = 0; idx < realNumRows; idx++) {

							rcvBlk = rowQ[iterRowQ+idx][j] ^ (R[idx] & choiceBlocks[j]); //Q+s*P

							/*if (j == numSuperBlocks - 1)
								rcvBlk = rcvBlk&mTruncateBlk;*/

							if (bIdx == 2 && idx == 0)
								std::cout << "R[idx]" << R[idx] << "\t" << rcvBlk<<"\t"<<"\n";
							
							localHashes[idx] = simple.mAesHasher.ecbEncBlock(rcvBlk) ^ localHashes[idx]; //compute H(Q+s*P)=xor of all slices
						}

					}

					if (bIdx == 2)
						std::cout << "sendMask " << localHashes[0] << "\n";

					iterRowQ += realNumRows;

					//std::cout << IoStream::lock;
					for (int idx = 0; idx < localHashes.size(); idx++) {
						u64 hashIdx = simple.mBins[bIdx].values[idx].mHashIdx;
						memcpy(globalHash[hashIdx].data() + permute[hashIdx][idxPermuteDone[hashIdx]++] * hashMaskBytes, (u8*)&localHashes[idx], hashMaskBytes);
					}
					//std::cout << IoStream::unlock;


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

							localHashes[idx]=simple.mAesHasher.ecbEncBlock(rcvBlk)^ localHashes[idx]; //compute H(Q+s*P)=xor of all slices
						}

					}

					for (int idx = 0; idx < localHashes.size(); idx++) {
						memcpy(sendBuff.data() + (k*simple.mMaxBinSize+idx)*hashMaskBytes, (u8*)&localHashes[idx], hashMaskBytes);
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

		//Dummy
		for (u64 hIdx = 0; hIdx < 2; hIdx++)
		{
			u64 currIdxPermuteDone = idxPermuteDone[hIdx];
			if (currIdxPermuteDone < inputs.size())
			{
				for (u64 i = currIdxPermuteDone; i < inputs.size(); i++)
				{
					block blkRandom = mPrng.get<block>();
					memcpy(globalHash[hIdx].data() + permute[hIdx][idxPermuteDone[hIdx]++] * hashMaskBytes, (u8*)&blkRandom, hashMaskBytes);
				}
			}
		}

#ifdef PSI_PRINT
	
		//Dummy
		for (u64 hIdx = 0; hIdx < 2; hIdx++)
		{
			if (idxPermuteDone[hIdx] < inputs.size())
			{
				u64 iii = inputs.size() - idxPermuteDone[hIdx];
				std::cout << "idxPermuteDone" << hIdx << "\t" << iii << "\n";
			}
		}

		for (u64 hIdx = 0; hIdx < 2; hIdx++)
			for (u64 k = 0; k < inputs.size(); ++k)
			{
				block globalTest;
				memcpy((u8*)&globalTest, globalHash[hIdx].data() + k* hashMaskBytes, hashMaskBytes);
				std::cout << IoStream::lock;
				std::cout << "globalHash " << hIdx << " " << k << "\t" << globalTest << "\n";
				std::cout << IoStream::unlock;
			}
#endif // PSI_PRINT

		auto sendingMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = inputs.size() * t / numThreads;
			u64 tempEndIdx = (inputs.size() * (t + 1) / numThreads);
			u64 endIdx = std::min(tempEndIdx, (u64)inputs.size());


			for (u64 i = startIdx; i < endIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, endIdx - i);
				std::array<std::vector<u8>, 2> sendBuffs;

				for (u64 hIdx = 0; hIdx < 2; hIdx++)
				{
					sendBuffs[hIdx].resize(curStepSize*hashMaskBytes);
					memcpy(sendBuffs[hIdx].data(), globalHash[hIdx].data() + i*hashMaskBytes, curStepSize*hashMaskBytes);
					chl.asyncSend(sendBuffs[hIdx]);

#ifdef PSI_PRINT
					for (u64 k = 0; k < curStepSize; ++k)
					{
						block globalTest;
						memcpy((u8*)&globalTest, sendBuffs[hIdx].data() + k* hashMaskBytes, hashMaskBytes);
						std::cout << IoStream::lock;
						std::cout << "sendBuffs " << hIdx << " " << k << "\t" << globalTest << "\n";
						std::cout << IoStream::unlock;
					}
#endif // PSI_PRINT
				}
				
			}
		};

		for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		{
			thrds[i] = std::thread([=] {
				sendingMask(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		
#endif
	}

}
