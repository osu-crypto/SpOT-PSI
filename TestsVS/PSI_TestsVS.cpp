#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"
#include "PSI_Tests.h"
#include "NcoOT_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace tests_libOTe
{
    TEST_CLASS(nOPRF_Tests)
    {
    public:

		
		TEST_METHOD(Hashing_TestVS)
		{
			InitDebugPrinting();
			Hashing_Test_Impl();
		}
		TEST_METHOD(myTestVS)
		{
			InitDebugPrinting();
			myTest();
		}
		

	};
}
#endif


