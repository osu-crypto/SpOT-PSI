#include "PrtyReceiver.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include "Tools/BalancedIndex.h"
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
		mFieldSize = fieldSize; // TODO

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
#if 1
		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 hashMaskBytes = (40 + 2 * log2(inputs.size()) + 7) / 8;


		//block mTruncateBlk;
		//u64 ishift = 0;
		//for (u64 i = (numSuperBlocks-1) * 128; i <  mFieldSize; i++)
		//{
		//	block temp = mm_bitshift_right(OneBlock, ishift++);
		//	mTruncateBlk = mTruncateBlk^temp;
		//}



		//=====================Balaced Allocation=====================
		//gTimer.reset();
		BalancedIndex mBalance;
		mBalance.init(inputs.size(), recvMaxBinSize, recvNumDummies);
		mBalance.insertItems(inputs);
		gTimer.setTimePoint("binning");
		//std::cout << gTimer << std::endl;
		
		/*std::cout << IoStream::lock;
		mBalance.print(inputs);
		std::cout << IoStream::unlock;*/

		std::array<std::unordered_map<u64, std::pair<block, u64>>, 2> localMasks; //for hash 0 and 1
		//localMasks[0].reserve(inputs.size());//for hash 0
		//localMasks[1].reserve(inputs.size());//for hash 1

		bool changeInputForDebug = true;

		//=====================Poly=====================
		auto routine = [&](u64 t)
		{
			auto& chl = chls[t];
			u64 binStartIdx = mBalance.mNumBins * t / numThreads;
			u64 tempBinEndIdx = (mBalance.mNumBins * (t + 1) / numThreads);
			u64 binEndIdx = std::min(tempBinEndIdx, mBalance.mNumBins);

			polyNTL poly;
			poly.NtlPolyInit(sizeof(block));

			/*polyNTL poly_lastBlk;
			u64 lastBlkByteSize = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);
			poly_lastBlk.NtlPolyInit(lastBlkByteSize);*/




			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);

				std::vector<u8> sendBuff;
				sendBuff.resize(curStepSize*mBalance.mMaxBinSize*numSuperBlocks * sizeof(block));

				std::vector<std::array<block, numSuperBlocks>> rowT(curStepSize*mBalance.mMaxBinSize);
				std::vector<item> subIdxItems(curStepSize*mBalance.mMaxBinSize);

				u64 iterSend = 0;

				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;

					std::vector<std::array<block, numSuperBlocks>> rowU(mBalance.mMaxBinSize);
					std::vector<std::array<block, numSuperBlocks>> rowR(mBalance.mMaxBinSize);
					u64 cntRows = 0;
					//=====================Compute OT row=====================
					for (auto it = mBalance.mBins[bIdx].values.begin(); it != mBalance.mBins[bIdx].values.end(); ++it)
					{
						for (u64 idx = 0; idx < it->second.size(); idx++)
						{
							if (changeInputForDebug && bIdx==2)
							{
								inputs[it->second[idx].mIdx] = OneBlock;
								changeInputForDebug = false;
								mIdxForDebug = it->second[idx].mIdx;
								mIdxRowTForDebug=idx; mKIdxForDebug = k;
								//std::cout << mIdxForDebug << "\t";
							}

							prfOtRow(inputs[it->second[idx].mIdx], rowT[k*mBalance.mMaxBinSize + cntRows], mAesT);
							prfOtRow(inputs[it->second[idx].mIdx], rowU[cntRows], mAesU);
							subIdxItems[k*mBalance.mMaxBinSize + cntRows] = it->second[idx];


						/*	std::cout << IoStream::lock;
							std::cout << idx << "\t " << inputs[it->second[idx].mIdx]<<
								"\t"<<rowT[k*mBalance.mMaxBinSize + cntRows][0] <<
								"\t" << rowU[cntRows][0] << "\n";
							std::cout << IoStream::unlock;*/


							if (it->second[idx].mIdx == mIdxForDebug && bIdx==2)
							{
								for (int j = 0; j < numSuperBlocks; ++j) {
									mRowTforDebug[j] = rowT[k*mBalance.mMaxBinSize + cntRows][j];
									mRowUforDebug[j] = rowU[cntRows][j];

										block tempR = mRowTforDebug[j] ^ mRowUforDebug[j];
									std::cout << mIdxForDebug << ": "<<mRowTforDebug[j] << "\t"
											 << mRowUforDebug[j] << "\t"
											<< tempR <<" tempR===\n";
								}
							}

							cntRows++;

						}
					}

					//std::cout << mBalance.mBins[bIdx].cnt << "\t" << cntRows << "\n";
					//comput R=T+U
					for (u64 idx = 0; idx < cntRows; ++idx)
						for (u64 j = 0; j < numSuperBlocks; ++j)
						{
							rowR[idx][j] = rowT[k*mBalance.mMaxBinSize + idx][j] ^ rowU[idx][j];
							

						}

					//=====================Pack=====================
#ifndef NTL_Threads_ON
					std::cout << IoStream::lock;
#endif // NTL_Threads_O

					u64 degree = mBalance.mMaxBinSize - 1;
					std::vector<block> X(cntRows), Y(cntRows), coeffs;

					for (u64 idx = 0; idx < cntRows; ++idx)
						memcpy((u8*)&X[idx], (u8*)&inputs[subIdxItems[k*mBalance.mMaxBinSize + idx].mIdx], sizeof(block));

					for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
					{
						for (u64 idx = 0; idx < cntRows; ++idx)
							memcpy((u8*)&Y[idx], (u8*)&rowR[idx][j], sizeof(block));

					
						//if (j == numSuperBlocks - 1)
						//{
						//	poly_lastBlk.getBlkCoefficients(degree, X, Y, coeffs);  //pad with dummy here
						//	for (int c = 0; c < coeffs.size(); c++) {
						//		memcpy(sendBuff.data() + iterSend, (u8*)&coeffs[c], lastBlkByteSize);
						//		iterSend += lastBlkByteSize;
						//	}
						//}
						//else
						{
							poly.getBlkCoefficients(degree, X, Y, coeffs);  //pad with dummy here
							for (int c = 0; c < coeffs.size(); c++) {
								memcpy(sendBuff.data() + iterSend, (u8*)&coeffs[c], sizeof(block));
								iterSend += sizeof(block);
							}
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
						ZZFromBytes(zz, (u8*)&inputs[subIdxItems[k*mBalance.mMaxBinSize + idx]], sizeof(block));
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

						for (int c = 0; c < degree; c++) {
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
					u64 realRows = mBalance.mBins[i + k].cnt;

					for (u64 idx = 0; idx < realRows; ++idx)
					{
						item it = subIdxItems[k*mBalance.mMaxBinSize + idx];

						cipher = ZeroBlock;
						for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
						{
							//if (j == numSuperBlocks - 1)
							//{
							//	block temp= rowT[k*mBalance.mMaxBinSize + idx][j] &mTruncateBlk;
							//	cipher = mBalance.mAesHasher.ecbEncBlock(temp) ^ cipher; //compute H(Q+s*P)=xor of all slices

							//}
							//else
								cipher = mBalance.mAesHasher.ecbEncBlock(rowT[k*mBalance.mMaxBinSize + idx][j]) ^ cipher; //compute H(Q+s*P)=xor of all slices
						}

						if (it.mIdx == mIdxForDebug)
						{
							std::cout << "recvMask " << cipher << "\n";
						}
						//std::cout << IoStream::lock;
						localMasks[it.mHashIdx].emplace(*(u64*)&cipher, std::pair<block, u64>(cipher, it.mIdx));
						//std::cout << IoStream::unlock;
					}
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

		gTimer.setTimePoint("poly");

#ifdef PSI_PRINT
		for (int j = 0; j<2; j++)
			for (auto it = localMasks[j].begin(); it != localMasks[j].end(); ++it)//for each bin, list all alter light bins
			{
				block globalTest;
				memcpy((u8*)&globalTest, (u8*)&it->first, sizeof(u64));
				std::cout << "localMasks " << j << "\t" << globalTest << "\n";
			}
#endif // PSI_PRIN
//#####################Receive Mask #####################
			

		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = inputs.size() * t / numThreads;
			u64 tempEndIdx = (inputs.size() * (t + 1) / numThreads);
			u64 endIdx = std::min(tempEndIdx, (u64)inputs.size());


			for (u64 i = startIdx; i < endIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, endIdx - i);
				std::array<std::vector<u8>, 2> recvBuffs;


				//receive the sender's marks, we have 2 buffs that corresponding to the mask of elements used hash index 0,1
				for (u64 hIdx = 0; hIdx < 2; hIdx++)
				{
					chl.recv(recvBuffs[hIdx]); //receive Hash
					/*if (recvBuffs[hIdx].size() != curStepSize*hashMaskBytes)
					{
						std::cout << "error @ " << (LOCATION) << std::endl;
						throw std::runtime_error(LOCATION);
					}*/

					auto theirMasks = recvBuffs[hIdx].data();


					if (hashMaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
					{
						for (u64 k = 0; k < curStepSize; ++k)
						{

							auto& msk = *(u64*)(theirMasks);
							// check 64 first bits
							auto match = localMasks[hIdx].find(msk);

							//if match, check for whole bits
							if (match != localMasks[hIdx].end())
							{
								if (memcmp(theirMasks, &match->second.first, hashMaskBytes) == 0) // check full mask
								{
									
									mIntersection.push_back(match->second.second);

									/*std::cout << "#id: " << match->second.second <<
										"\t" << inputs[match->second.second] << std::endl;*/
									/*block globalTest;
									memcpy((u8*)&globalTest, (u8*)msk, hashMaskBytes);
									std::cout << "theirMasks " << hIdx << " " << k << "\t" << globalTest << "\n";*/
								
								
								}
							}
							theirMasks += hashMaskBytes;
						}
					}
					else //for small set, do O(n^2) check
					{
						for (u64 k = 0; k < curStepSize; ++k)
						{

							for (auto match = localMasks[hIdx].begin(); match != localMasks[hIdx].end(); ++match)
							{
								if (memcmp(theirMasks, &match->second.first, hashMaskBytes) == 0) // check full mask
								{
									mIntersection.push_back(match->second.second);
								}
								theirMasks += hashMaskBytes;
							}
						}
					}


				}

#endif

				
			
			}
		
		};

		for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		{
			thrds[i] = std::thread([=] {
				receiveMask(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();
		


	//	std::cout << "Outputs.size() " <<Outputs.size() << std::endl;
#endif
	}
}
