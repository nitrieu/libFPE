/*
File:   TestsVS.cpp
Author: Ni Trieu (trieun@oregonstate.edu)
Date:   01 January 2018
Brief:	TestsVS
*/

#pragma once
#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"
#include "Common.h"
#include "FpeEncDecTests.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace tests_lib
{
    TEST_CLASS(nOPRF_Tests)
    {
    public:
       
		TEST_METHOD(DTP_enc_testVS)
		{
			InitDebugPrinting();
			DTP_enc_test();
		}
		 
		TEST_METHOD(FF3_enc_testVS)
		{
			InitDebugPrinting();
			FF3_enc_test();
		}

		
		
	
    };
}
#endif