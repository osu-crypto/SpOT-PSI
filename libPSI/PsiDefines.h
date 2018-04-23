#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>
#define NTL_Threads
#define  DEBUG
#include "PsiDefines.h"
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
using namespace NTL;
#define NTL_Threads_ON
#ifdef _MSC_VER
//#define PSI_PRINT
#endif


namespace osuCrypto
{
	static const u64 stepSize(1 << 8);
	static const u64 stepSizeMaskSent(1<<11);
	static const u8 numSuperBlocks(4); //wide of T (or field size)
	static const u64 recvNumDummies(1);
	static const u64 recvMaxBinSize(40);
	static std::vector<block> mOneBlocks(128); 
	static const u64 primeLong(128);
	static const u64 fieldSize(440); //TODO 4*sizeof(block)

	static const u64 bIdxForDebug(3), iIdxForDebug(0), hIdxForDebug(0);



	inline u64 getFieldSizeInBits(u64 setSize)
	{
		if (setSize <= (1 << 10))
			return 416;
		else if (setSize <= (1 << 12))
			return 420;
		else if (setSize <= (1 << 14))
			return 424;
		else if (setSize <= (1 << 16))
			return 428;
		else if (setSize <= (1 << 18))
			return 432;
		else if (setSize <= (1 << 20))
			return 436;

		return 436;
	}
	
	struct item
	{
		u64 mHashIdx;
		u64 mIdx;
	};


	static __m128i mm_bitshift_right(__m128i x, unsigned count)
	{
		__m128i carry = _mm_slli_si128(x, 8);   // old compilers only have the confusingly named _mm_slli_si128 synonym
		if (count >= 64)
			return _mm_slli_epi64(carry, count - 64);  // the non-carry part is all zero, so return early
													   // else
		return _mm_or_si128(_mm_slli_epi64(x, count), _mm_srli_epi64(carry, 64 - count));

	}


	static __m128i mm_bitshift_left(__m128i x, unsigned count)
	{
		__m128i carry = _mm_srli_si128(x, 8);   // old compilers only have the confusingly named _mm_slli_si128 synonym
		if (count >= 64)
			return _mm_srli_epi64(carry, count - 64);  // the non-carry part is all zero, so return early

		return _mm_or_si128(_mm_srli_epi64(x, count), _mm_slli_epi64(carry, 64 - count));
	}

	inline void fillOneBlock(std::vector<block>& blks)
	{
		for (int i = 0; i < blks.size(); ++i)
			blks[i] = mm_bitshift_right(OneBlock, i);
	}

	static void prfOtRows(std::vector<block>& inputs,  std::vector<std::array<block, numSuperBlocks>>& outputs, std::vector<AES>& arrAes)
	{
		std::vector<block> ciphers(inputs.size());
		outputs.resize(inputs.size());

		for (int j = 0; j < numSuperBlocks - 1; ++j) //1st 3 blocks
			for (int i = 0; i < 128; ++i) //for each column
			{
				arrAes[j * 128 + i].ecbEncBlocks(inputs.data(), inputs.size(), ciphers.data()); //do many aes at the same time for efficeincy

				for (u64 idx = 0; idx < inputs.size(); idx++)
				{
					ciphers[idx] = ciphers[idx]&mOneBlocks[i];
					outputs[idx][j] = outputs[idx][j] ^ ciphers[idx];
				}
			}

		
		int j = numSuperBlocks - 1;
		for (int i = j * 128; i < arrAes.size(); ++i)
		{
				arrAes[i].ecbEncBlocks(inputs.data(), inputs.size(), ciphers.data()); //do many aes at the same time for efficeincy
				for (u64 idx = 0; idx < inputs.size(); idx++)
				{
					ciphers[idx] = ciphers[idx] & mOneBlocks[i-j*128];
					outputs[idx][j] = outputs[idx][j] ^ ciphers[idx];
				}
			
		}

	}

	static void prfOtRow(block& input, std::array<block, numSuperBlocks>& output, std::vector<AES> arrAes, u64 hIdx=0)
	{
		block cipher;

		for (int j = 0; j < numSuperBlocks - 1; ++j) //1st 3 blocks
			for (int i = 0; i < 128; ++i) //for each column
			{
				if(hIdx==1)
					arrAes[j * 128 + i].ecbEncBlock(input^OneBlock, cipher);
				else
					arrAes[j * 128 + i].ecbEncBlock(input, cipher);

				cipher= cipher& mOneBlocks[i];
				output[j] = output[j] ^ cipher;
			}


		int j = numSuperBlocks - 1;
		for (int i = 0; i < 128; ++i)
		{
			if (j * 128 + i < arrAes.size()) {

				if (hIdx == 1)
					arrAes[j * 128 + i].ecbEncBlock(input^OneBlock, cipher);
				else
					arrAes[j * 128 + i].ecbEncBlock(input, cipher);
				
				cipher = cipher& mOneBlocks[i];
				output[j] = output[j] ^ cipher;
			}
			else {
				break;
			}
		}

		//std::cout << IoStream::lock;
		//std::cout << "\t output " << output[0] << "\n";
		//std::cout << IoStream::unlock;

	}

}
