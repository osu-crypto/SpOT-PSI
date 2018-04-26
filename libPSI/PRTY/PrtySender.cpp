#include "PrtySender.h"

#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/Base/naor-pinkas.h"
#include <unordered_map>

namespace osuCrypto
{
    using namespace std;
	using namespace NTL;


	void PrtySender::init(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<Channel> chls)
	{
		mPsiSecParam = psiSecParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;

		mPrng.SetSeed(prng.get<block>());
		mFieldSize = getFieldSizeInBits(mTheirInputSize);

		fillOneBlock(mOneBlocks);

		u64 ishift = 0;
		mTruncateBlk = ZeroBlock;
		for (u64 i = (numSuperBlocks - 1) * 128; i < mFieldSize; i++)
		{
			mTruncateBlk = mTruncateBlk^mOneBlocks[ishift++];
		}

		std::vector<std::array<block, 2>> baseOtSend(128);
		NaorPinkas baseOTs;
		baseOTs.send(baseOtSend, mPrng, chls[0], chls.size());

		IknpOtExtReceiver recvIKNP;
		recvIKNP.setBaseOts(baseOtSend);

		mOtChoices.resize(mFieldSize);
		mOtChoices.randomize(mPrng);
		std::vector<block> OtKeys(mFieldSize);

		recvIKNP.receive(mOtChoices, OtKeys, mPrng, chls[0]);

		mAesQ.resize(mFieldSize);
		for (u64 i = 0; i < mFieldSize; i++)
			mAesQ[i].setKey(OtKeys[i]);

		u8 bit = 0; //fill up to numSuperBlocks 
		for (u64 i = 0; i < numSuperBlocks * 128 - mFieldSize; i++)
		{
			mOtChoices.pushBack(bit);
			block temp = mm_bitshift_left(OneBlock, i);
		}

		simple.init(mTheirInputSize, recvMaxBinSize, recvNumDummies);

		//mAesHasher.setKey(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
	

	}

	void PrtySender::output(span<block> inputs, span<Channel> chls)
	{
#if 1
		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 hashMaskBytes = (40+log2(mTheirInputSize*mMyInputSize)+7) / 8;
		u64 lastPolyMaskBytes = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);

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
		//gTimer.reset();
		//gTimer.setTimePoint("start");
		simple.insertItems(inputs);
		gTimer.setTimePoint("s_binning");
		//std::cout << gTimer << std::endl;

		/*std::cout << IoStream::lock;
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


#ifdef GF2X_Slicing
			poly.NtlPolyInit(sizeof(block));
			/*polyNTL poly_lastBlk;
			u64 lastBlkByteSize = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);
			poly_lastBlk.NtlPolyInit(lastBlkByteSize);*/
#else
			poly.NtlPolyInit(polyMaskBytes);
#endif // GF2X_Slicing

			


			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);
				std::vector<std::vector<std::array<block, numSuperBlocks>>> rowQ(curStepSize);

				u64 iterSend = 0, iterRecv = 0;

				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					rowQ[k].resize(simple.mBins[bIdx].blks.size());
					//=====================Compute OT row=====================
					prfOtRows(simple.mBins[bIdx].blks, rowQ[k], mAesQ);

				}

				std::vector<u8> recvBuff;
				chl.recv(recvBuff); //receive Poly
		/*			if (recvBuff.size() != curStepSize*simple.mTheirMaxBinSize*polyMaskBytes);
					{
						int aa = curStepSize*simple.mTheirMaxBinSize*polyMaskBytes;
						std::cout << recvBuff.size() << "\t" <<aa << std::endl;

						std::cout << "error @ " << (LOCATION) << std::endl;
						throw std::runtime_error(LOCATION);
					}*/

					//=====================Unpack=====================
				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					u64 realNumRows = simple.mBins[bIdx].blks.size();
					
#ifdef GF2X_Slicing
					std::vector<block> localHashes(realNumRows);
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

#else
					u64 degree = simple.mTheirMaxBinSize - 1;
					std::vector<std::array<block, numSuperBlocks>> R(realNumRows), coeffs(degree + 1); //
					block rcvBlk;

					
					for (int c = 0; c < coeffs.size(); c++)
					{
						memcpy((u8*)&coeffs[c], recvBuff.data() + iterSend, polyMaskBytes);
						iterSend += polyMaskBytes;
					}

					poly.evalSuperPolynomial(coeffs, simple.mBins[bIdx].blks, R);

					//if (bIdx == 2)
					//{
					//	std::cout << "rX= " << X[0] << "\t X2.size() " << X.size() << "\t  coeffs.size()" << coeffs.size() << "\n";
					//	std::cout << "rY= ";

					//	for (int j = 0; j < numSuperBlocks; ++j) {
					//		std::cout << R[0][j] << "\t";
					//	}
					//	std::cout << "\n";
					//}


					std::array<block, numSuperBlocks> recvRowT;
					std::vector<block> cipher(4);

					for (int idx = 0; idx < realNumRows; idx++) {
						for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
						{
							recvRowT[j] = rowQ[k][idx][j] ^ (R[idx][j] & choiceBlocks[j]); //Q+s*P

							if (j == numSuperBlocks - 1) //get last 440-3*128 bits
								recvRowT[j] = recvRowT[j] & mTruncateBlk;
						}

						simple.mAesHasher.ecbEncFourBlocks(recvRowT.data(), cipher.data());

						for (u64 j = 1; j < numSuperBlocks; ++j)
							cipher[0] = cipher[0] ^ cipher[j];
						
						u64 hashIdx = simple.mBins[bIdx].hashIdxs[idx];
						memcpy(globalHash[hashIdx].data() + permute[hashIdx][idxPermuteDone[hashIdx]++] * hashMaskBytes
							, (u8*)&cipher[0], hashMaskBytes);

					}
					

#endif
					/*if (bIdx == bIdxForDebug)
					{
						idxPermuteDoneforDebug = idxPermuteDone[1];

						std::cout << "sendMask " << localHashes[iIdxForDebug]
							<< " X= " << inputs[simple.mBins[bIdx].values[iIdxForDebug].mIdx]
							<< " hIdx " << simple.mBins[bIdx].values[iIdxForDebug].mHashIdx 
							<<" idxPer " << idxPermuteDoneforDebug << "\n";
					}*/

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

		gTimer.setTimePoint("s_poly");

#ifdef PSI_PRINT
	
		
		for (u64 hIdx = 0; hIdx < 2; hIdx++)
			for (u64 k = 0; k < inputs.size(); ++k)
			{
				block globalTest;
				memcpy((u8*)&globalTest, globalHash[hIdx].data() + k* hashMaskBytes, hashMaskBytes);
				std::cout << IoStream::lock;
				std::cout << "globalHash " << hIdx << " " << k << "\t" << globalTest << "\n";
				std::cout << IoStream::unlock;
			}

		block globalTest;
		memcpy((u8*)&globalTest, globalHash[1].data() + permute[1][idxPermuteDoneforDebug] * hashMaskBytes, hashMaskBytes);
		std::cout << "globalHash " << globalTest << "\n";

#endif // PSI_PRINT


		auto sendingMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = inputs.size() * t / numThreads;
			u64 tempEndIdx = (inputs.size() * (t + 1) / numThreads);
			u64 endIdx = std::min(tempEndIdx, (u64)inputs.size());


			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);

				for (u64 hIdx = 0; hIdx < 2; hIdx++)
				{
					std::vector<u8> sendBuff(curStepSize*hashMaskBytes);
					memcpy(sendBuff.data(), globalHash[hIdx].data() + i*hashMaskBytes, curStepSize*hashMaskBytes);
					chl.asyncSend(std::move(sendBuff));

#ifdef PSI_PRINT
					for (u64 k = 0; k < curStepSize; ++k)
					{
						block globalTest;
						memcpy((u8*)&globalTest, sendBuff[hIdx].data() + k* hashMaskBytes, hashMaskBytes);
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

	//static bool wayToSort(block i,  block j) { 
	//	if (i < j)
	//		return true;

	//	return false;

	//	//return static_cast<bool>(i < j); 
	//
	//}

	void PrtySender::outputBestComm(span<block> inputs, span<Channel> chls)
	{
#if 1
		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 hashMaskBytes = (40 + log2(mTheirInputSize) + 7) / 8;
		u64 lastPolyMaskBytes = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);

		auto choiceBlocks = mOtChoices.getSpan<block>(); //s

		std::array<std::vector<block>, 2> globalHash;
		globalHash[0].resize(inputs.size());
		globalHash[1].resize(inputs.size());

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
		//gTimer.reset();
		//gTimer.setTimePoint("start");
		simple.insertItems(inputs);
		gTimer.setTimePoint("s_binning");
		//std::cout << gTimer << std::endl;

		/*std::cout << IoStream::lock;
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


#ifdef GF2X_Slicing
			poly.NtlPolyInit(sizeof(block));
			/*polyNTL poly_lastBlk;
			u64 lastBlkByteSize = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);
			poly_lastBlk.NtlPolyInit(lastBlkByteSize);*/
#else
			poly.NtlPolyInit(polyMaskBytes);
#endif // GF2X_Slicing




			for (u64 i = binStartIdx; i < binEndIdx; i += stepSize)
			{
				auto curStepSize = std::min(stepSize, binEndIdx - i);
				std::vector<std::vector<std::array<block, numSuperBlocks>>> rowQ(curStepSize);

				u64 iterSend = 0, iterRecv = 0;

				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					rowQ[k].resize(simple.mBins[bIdx].blks.size());
					//=====================Compute OT row=====================
					prfOtRows(simple.mBins[bIdx].blks, rowQ[k], mAesQ);

				}

				std::vector<u8> recvBuff;
				chl.recv(recvBuff); //receive Poly
									/*			if (recvBuff.size() != curStepSize*simple.mTheirMaxBinSize*polyMaskBytes);
									{
									int aa = curStepSize*simple.mTheirMaxBinSize*polyMaskBytes;
									std::cout << recvBuff.size() << "\t" <<aa << std::endl;

									std::cout << "error @ " << (LOCATION) << std::endl;
									throw std::runtime_error(LOCATION);
									}*/

									//=====================Unpack=====================
				for (u64 k = 0; k < curStepSize; ++k)
				{
					u64 bIdx = i + k;
					u64 realNumRows = simple.mBins[bIdx].blks.size();

#ifdef GF2X_Slicing
					std::vector<block> localHashes(realNumRows);
					u64 degree = simple.mTheirMaxBinSize - 1;
					std::vector<block> X(realNumRows), R(realNumRows), coeffs(degree + 1); //
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

							rcvBlk = rowQ[iterRowQ + idx][j] ^ (R[idx] & choiceBlocks[j]); //Q+s*P

																						   /*if (j == numSuperBlocks - 1)
																						   rcvBlk = rcvBlk&mTruncateBlk;*/

							if (bIdx == 2 && idx == 0)
								std::cout << "R[idx]" << R[idx] << "\t" << rcvBlk << "\t" << "\n";

							localHashes[idx] = simple.mAesHasher.ecbEncBlock(rcvBlk) ^ localHashes[idx]; //compute H(Q+s*P)=xor of all slices
						}

					}

#else
					u64 degree = simple.mTheirMaxBinSize - 1;
					std::vector<std::array<block, numSuperBlocks>> R(realNumRows), coeffs(degree + 1); //
					block rcvBlk;


					for (int c = 0; c < coeffs.size(); c++)
					{
						memcpy((u8*)&coeffs[c], recvBuff.data() + iterSend, polyMaskBytes);
						iterSend += polyMaskBytes;
					}

					poly.evalSuperPolynomial(coeffs, simple.mBins[bIdx].blks, R);

					//if (bIdx == 2)
					//{
					//	std::cout << "rX= " << X[0] << "\t X2.size() " << X.size() << "\t  coeffs.size()" << coeffs.size() << "\n";
					//	std::cout << "rY= ";

					//	for (int j = 0; j < numSuperBlocks; ++j) {
					//		std::cout << R[0][j] << "\t";
					//	}
					//	std::cout << "\n";
					//}


					std::array<block, numSuperBlocks> recvRowT;
					std::vector<block> cipher(4);

					for (int idx = 0; idx < realNumRows; idx++) {
						for (u64 j = 0; j < numSuperBlocks; ++j) //slicing
						{
							recvRowT[j] = rowQ[k][idx][j] ^ (R[idx][j] & choiceBlocks[j]); //Q+s*P

							if (j == numSuperBlocks - 1) //get last 440-3*128 bits
								recvRowT[j] = recvRowT[j] & mTruncateBlk;
						}

						simple.mAesHasher.ecbEncFourBlocks(recvRowT.data(), cipher.data());

						for (u64 j = 1; j < numSuperBlocks; ++j)
							cipher[0] = cipher[0] ^ cipher[j];

						u64 hashIdx = simple.mBins[bIdx].hashIdxs[idx];
						
						//globalHash[hashIdx][idxPermuteDone[hashIdx]++] = cipher[0];
						memcpy(globalHash[hashIdx].data() + permute[hashIdx][idxPermuteDone[hashIdx]++] 
							, (u8*)&cipher[0], sizeof(block));

					}


#endif
					/*if (bIdx == bIdxForDebug)
					{
					idxPermuteDoneforDebug = idxPermuteDone[1];

					std::cout << "sendMask " << localHashes[iIdxForDebug]
					<< " X= " << inputs[simple.mBins[bIdx].values[iIdxForDebug].mIdx]
					<< " hIdx " << simple.mBins[bIdx].values[iIdxForDebug].mHashIdx
					<<" idxPer " << idxPermuteDoneforDebug << "\n";
					}*/

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
						rcvBlk = rowQ[idx][j] ^ (rcvBlk&choiceBlocks[j]); //Q+s*P

						localHashes[idx] = simple.mAesHasher.ecbEncBlock(rcvBlk) ^ localHashes[idx]; //compute H(Q+s*P)=xor of all slices
					}

				}

				for (int idx = 0; idx < localHashes.size(); idx++) {
					memcpy(sendBuff.data() + (k*simple.mMaxBinSize + idx)*hashMaskBytes, (u8*)&localHashes[idx], hashMaskBytes);
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

		gTimer.setTimePoint("s_poly");

#ifdef PSI_PRINT


		for (u64 hIdx = 0; hIdx < 2; hIdx++)
			for (u64 k = 0; k < inputs.size(); ++k)
			{
				block globalTest;
				memcpy((u8*)&globalTest, globalHash[hIdx].data() + k* hashMaskBytes, hashMaskBytes);
				std::cout << IoStream::lock;
				std::cout << "globalHash " << hIdx << " " << k << "\t" << globalTest << "\n";
				std::cout << IoStream::unlock;
			}

		block globalTest;
		memcpy((u8*)&globalTest, globalHash[1].data() + permute[1][idxPermuteDoneforDebug] * hashMaskBytes, hashMaskBytes);
		std::cout << "globalHash " << globalTest << "\n";

#endif // PSI_PRINT


		//=====================Sort=====================
		
		auto ss = [](const block& lhs, const block& rhs) -> bool {
			return memcmp(&lhs, &rhs, sizeof(block)) < 0;		
		};


		globalHash[0][0] = ZeroBlock;
		globalHash[0][1] = ZeroBlock;

		std::sort(globalHash[1].begin(), globalHash[1].end(), ss);
		std::sort(globalHash[0].begin(), globalHash[0].end(), ss);

		gTimer.setTimePoint("s_sort");

		std::cout << "globalHash " << globalHash[0][0] << "\n";
		std::cout << "globalHash " << globalHash[0][1] << "\n";
		std::cout << "globalHash " << globalHash[0][2] << "\n";
		std::cout << "globalHash " << globalHash[0][3] << "\n";



		auto sendingMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = inputs.size() * t / numThreads;
			u64 tempEndIdx = (inputs.size() * (t + 1) / numThreads);
			u64 endIdx = std::min(tempEndIdx, (u64)inputs.size());


			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);

				for (u64 hIdx = 0; hIdx < 2; hIdx++)
				{
					std::vector<u8> sendBuff(curStepSize*hashMaskBytes);

					memcpy(sendBuff.data(), (u8*)&globalHash[hIdx][startIdx], hashMaskBytes);

					block diff;
					for (u64 idx = 1; idx < curStepSize; idx++)
					{
						diff = globalHash[hIdx][idx]^globalHash[hIdx][idx - 1];
						memcpy(sendBuff.data()+idx*hashMaskBytes, (u8*)&diff, hashMaskBytes);

					}
					chl.asyncSend(std::move(sendBuff));

#ifdef PSI_PRINT
					for (u64 k = 0; k < curStepSize; ++k)
					{
						block globalTest;
						memcpy((u8*)&globalTest, sendBuff[hIdx].data() + k* hashMaskBytes, hashMaskBytes);
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


	void PrtySender::outputBigPoly(span<block> inputs, span<Channel> chls)
	{
#if 1
		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::mutex mtx;
		u64 polyMaskBytes = (mFieldSize + 7) / 8;
		u64 hashMaskBits = (40 + log2(mTheirInputSize) + 2 ) ;
		u64 hashMaskBytes =  (hashMaskBits + 7) / 8;

		u64 lastPolyMaskBytes = polyMaskBytes - (numSuperBlocks - 1) * sizeof(block);
		u64 n1n2MaskBits = (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits+7)/8;



		auto choiceBlocks = mOtChoices.getSpan<block>(); //s

		std::vector<block> globalHash(inputs.size());
		

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


		//=====================OT row=====================

		std::vector<std::vector<std::array<block, numSuperBlocks>>> subRowQ(numThreads);
		
		auto computeOtRows = [&](u64 t)
		{
			u64 startIdx = mMyInputSize * t / numThreads;
			u64 tempEndIdx = mMyInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mMyInputSize);
			std::vector<block> X(endIdx - startIdx);

			subRowQ[t].resize(endIdx - startIdx);

			for (u64 i = 0; i < X.size(); i++)
				memcpy(&X[i], &inputs[startIdx + i], sizeof(block));

			prfOtRows(X, subRowQ[t], mAesQ);

		};



		std::vector<std::thread> thrds(chls.size());
		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				computeOtRows(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("OT Row");

		for (u64 i = 0; i < numSuperBlocks; i++)
			subRowQForDebug[i] = subRowQ[0][0][i];
	


		//=====================Poly=====================

		std::array<std::vector<u8>, numSuperBlocks> recvBuffs;

		if (thrds.size() >= numSuperBlocks)
		{
			for (u64 t = 0; t < thrds.size(); ++t)
			{
				thrds[t] = std::thread([=] {
					auto& chl = chls[t];
					chl.recv(recvBuffs[t]); //receive Poly
				});
			}

			for (auto& thrd : thrds)
				thrd.join();
		}
		else
		{
			chls[0].recv(recvBuffs[0]);
			chls[0].recv(recvBuffs[1]);
			chls[0].recv(recvBuffs[2]);
			chls[0].recv(recvBuffs[3]);
		}

		u64 degree = mTheirInputSize - 1;
		mPrime = mPrime128;
		ZZ_p::init(ZZ(mPrime));
		
		ZZ_p* zzX = new ZZ_p[inputs.size()];
		ZZ zz;
		u64 maskLength;


		for (u64 idx = 0; idx < inputs.size(); idx++)
		{
			ZZFromBytes(zz, (u8*)&inputs[idx], sizeof(block));
			zzX[idx] = to_ZZ_p(zz);
		}


		ZZ_pX* p_tree = new ZZ_pX[degree * 2 + 1];
		ZZ_pX* reminders = new ZZ_pX[degree * 2 + 1];

		std::array<ZZ_p*, numSuperBlocks> zzY1;
		for (u64 i = 0; i < numSuperBlocks; i++)
			zzY1[i] = new ZZ_p[inputs.size()];

		build_tree(p_tree, zzX, degree * 2 + 1, 1, mPrime);
		block rcvBlk;

		std::array<ZZ_pX, numSuperBlocks> recvPolynomials;

		for (u64 idxBlk = 0; idxBlk < numSuperBlocks; idxBlk++)
		{
			u64 iterRecvs = 0;
			maskLength = (idxBlk == numSuperBlocks - 1) ? lastPolyMaskBytes : sizeof(block);

			for (int c = 0; c <= degree; c++) {
				memcpy((u8*)&rcvBlk, recvBuffs[idxBlk].data() + iterRecvs, maskLength);
				iterRecvs += maskLength;

				ZZFromBytes(zz, (u8*)&rcvBlk, maskLength);
				SetCoeff(recvPolynomials[idxBlk], c, to_ZZ_p(zz));
			}


			evaluate(recvPolynomials[idxBlk], p_tree, reminders, degree * 2 + 1, zzY1[idxBlk], numThreads, mPrime);

			block rcvRowR;
			BytesFromZZ((u8*)&rcvRowR, rep(zzY1[idxBlk][0]), maskLength);
			std::cout << "s rcvRowR: " << rcvRowR << std::endl;

		}


		auto computeGlobalHash = [&](u64 t)
		{
			u64 startIdx = mMyInputSize * t / numThreads;
			u64 tempEndIdx = mMyInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mMyInputSize);
			std::array<block, numSuperBlocks> recvRowT;
			std::vector<block> cipher(4);

			for (u64 idx = 0; idx < endIdx - startIdx; idx++)
			{
				u64 idxItem = startIdx + idx;

				for (u64 idxBlk = 0; idxBlk < numSuperBlocks; ++idxBlk) //slicing
				{
					block rcvRowR;
					maskLength = (idxBlk == numSuperBlocks - 1) ? lastPolyMaskBytes : sizeof(block);
					BytesFromZZ((u8*)&rcvRowR, rep(zzY1[idxBlk][idxItem]), maskLength);

					recvRowT[idxBlk] = subRowQ[t][idx][idxBlk] ^ (rcvRowR & choiceBlocks[idxBlk]); //Q+s*P

					if (idxBlk == numSuperBlocks - 1) //get last 440-3*128 bits
						recvRowT[idxBlk] = recvRowT[idxBlk] & mTruncateBlk;

					if (idxItem == 0)
						std::cout << "s recvRowT: " << recvRowT[idxBlk] << std::endl;

				}

				simple.mAesHasher.ecbEncFourBlocks(recvRowT.data(), cipher.data());

				for (u64 j = 1; j < numSuperBlocks; ++j)
					cipher[0] = cipher[0] ^ cipher[j];

				if(idxItem==0)
					std::cout << cipher[0] << " " << idxItem <<" == S cipher[0]\n";


				memcpy(globalHash.data() + idxItem, (u8*)&cipher[0], sizeof(block));
			}

		};


		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				computeGlobalHash(i);
			});
		}
		for (auto& thrd : thrds)
			thrd.join();

		gTimer.setTimePoint("computeMask");

#if 1
		//=====================Sort=====================



		std::cout << globalHash.size() << " globalHash.size()\n";

		auto ss = [](const block& lhs, const block& rhs) -> bool {
			return memcmp(&lhs, &rhs, sizeof(block)) < 0;
		};

		std::sort(globalHash.begin(), globalHash.end(), ss);

		gTimer.setTimePoint("s_sort");

		std::vector<u8> sendBuff(1.02*inputs.size()*(hashMaskBytes));

		
		//block 
		block boundMaskDiff = ZeroBlock;
		for (u64 i = 0; i < hashMaskBytes*8; i++)
			boundMaskDiff = boundMaskDiff^mOneBlocks[i];

		std::cout << boundMaskDiff << "  boundMaskDiff\n";


		
		u64 iterSendDiff = 0;

		memcpy(sendBuff.data(), (u8*)&globalHash[0], n1n2MaskBytes);
		iterSendDiff += n1n2MaskBytes;

		block diff;
		for (u64 idx = 0; idx < inputs.size()-1; idx++)
		{
			diff = globalHash[idx + 1] - globalHash[idx];

			if (memcmp(&diff, &boundMaskDiff, hashMaskBytes) < 0)
			{
				//std::cout << diff << "  " << idx << "\t ==diff==\t" << globalHash[idx + 1] << "\t" << globalHash[idx] << "\n";
				memcpy(sendBuff.data()+ iterSendDiff, (u8*)&diff, hashMaskBytes);
				iterSendDiff += hashMaskBytes;
			}
			else
			{
				//std::cout << diff << "  " << idx << "\t ==dddddiff==\t" << globalHash[idx + 1] << "\t" << globalHash[idx] << "\n";

				memcpy(sendBuff.data() + iterSendDiff, (u8*)&ZeroBlock, hashMaskBytes);
				iterSendDiff += hashMaskBytes;
			
				memcpy(sendBuff.data() + iterSendDiff, (u8*)& globalHash[idx+1], n1n2MaskBytes);
				iterSendDiff += n1n2MaskBytes;
			}
			if (iterSendDiff > sendBuff.size())
			{
				std::cout << "iterSendDiff > sendBuff.size(): " << iterSendDiff << "\t" << sendBuff.size() << "\n";
				sendBuff.resize(sendBuff.size() + (inputs.size() - iterSendDiff)*hashMaskBytes);
			}
			//std::cout << idx << " idx \n";
		}
		//memcpy(sendBuff.data() + iterSendDiff, (u8*)& ZeroBlock, sendBuff.size()- iterSendDiff);

		
		block aaa=ZeroBlock;
		memcpy( (u8*)&aaa, sendBuff.data(), n1n2MaskBytes);
		std::cout << aaa << " sendBuff[0] \t" << globalHash[0] << "\n";

		chls[0].asyncSend(std::move(sendBuff));


		auto sendingMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = inputs.size() * t / numThreads;
			u64 tempEndIdx = (inputs.size() * (t + 1) / numThreads);
			u64 endIdx = std::min(tempEndIdx, (u64)inputs.size());


			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);

					std::vector<u8> sendBuff(curStepSize*hashMaskBytes);

					memcpy(sendBuff.data(), (u8*)&globalHash[startIdx], hashMaskBytes);

					block diff;
					for (u64 idx = 1; idx < curStepSize; idx++)
					{
						//diff = globalHash[idx] ^ globalHash[idx - 1];
						diff = globalHash[startIdx+idx];
						memcpy(sendBuff.data() + idx*hashMaskBytes, (u8*)&diff, hashMaskBytes);

					}
					chl.asyncSend(std::move(sendBuff));

#ifdef PSI_PRINT
					for (u64 k = 0; k < curStepSize; ++k)
					{
						block globalTest;
						memcpy((u8*)&globalTest, sendBuff[hIdx].data() + k* hashMaskBytes, hashMaskBytes);
						std::cout << IoStream::lock;
						std::cout << "sendBuffs " << hIdx << " " << k << "\t" << globalTest << "\n";
						std::cout << IoStream::unlock;
					}
#endif // PSI_PRINT

			}
		};

		//for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		//{
		//	thrds[i] = std::thread([=] {
		//		sendingMask(i);
		//	});
		//}

		//for (auto& thrd : thrds)
		//	thrd.join();


#endif
#endif
	}


}

