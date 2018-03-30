#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <chrono>
//#include <sys/resource.h>
#include <iostream>

#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include <vector>

using namespace std;
using namespace NTL;
using namespace chrono;


namespace osuCrypto
{

	class polyFFT2 : public TimerAdapter
	{
	public:
		struct node
		{
			ZZ_pX data;
			struct node* left;
			struct node* right;
		};

		polyFFT2();
		~polyFFT2();
		ZZ mPrime;
		u64 mNumThreads;
		void init(ZZ &prime, u64 numThreads);
		void build_tree(ZZ_pX* tree, ZZ_p* points);

	};

}
