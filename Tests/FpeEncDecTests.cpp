/*
File:   FpeEncDecTests.cpp
Author: Ni Trieu (trieun@oregonstate.edu)
Date:   01 January 2018
Brief:	Test
*/

#include "FpeEncDecTests.h"
#include <libFPE/FpeUtils.h>
#include <libFPE/Feistel/FF3.h>
#include <libFPE/DTP/DTP.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "Common.h"
#include <thread>
#include <vector>
#include <algorithm>
#include <cryptoTools/Common/Timer.h>
#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#pragma warning(disable:4996)
#endif //  _MSC_VER
using namespace osuCrypto;


namespace tests_lib
{
	void FF3_enc_test()
	{
		PRNG prng(_mm_set_epi64x(12345678, 24324324));
		block userKey = _mm_set_epi64x(12345678, 1234567);
		int D = 256, radix = 10, len = 16;
		FF3 ff3(userKey);

		for (int idxTrial = 0; idxTrial < 100; idxTrial++)
		{
			u8* plainText = ByteArray(prng.get<block>());;//TODO: contains 2 plaintexts (64 bits each)
			for (int i = 0; i < len; i++)
				plainText[i] = plainText[i] % radix; //get radix domain => TODO: reuse another 4 first bits of each byte

			u8* tweak = ByteArray(prng.get<block>());

			//std::cout << toBlock(plainText) << std::endl;
			//printArrU8(plainText, len);
			//std::cout << "tweak: " << toBlock(tweak) << std::endl;

			u8* cipherText = ff3.encrypt(plainText, tweak, len, radix);
			u8* X1 = ff3.decrypt(cipherText, tweak, len, radix);

			if (memcmp(X1, plainText, len))
			{
				std::cout << "ciphertex:"; printArrU8(cipherText, len);
				std::cout << "new plaintext: "; printArrU8(X1, len);
				std::cout << "org plaintext: "; printArrU8(plainText, len);
				std::cout << "bad enc/dec FF3" << idxTrial << std::endl;
				throw std::exception();
			}
		}
		std::cout << "good enc/dec FF3!"<< std::endl;

	}

	void DTP_enc_test()
	{
		PRNG prng(_mm_set_epi64x(12345678, 24324324));
		block userKey = _mm_set_epi64x(12345678, 1234567);
		int D = 256, radix = 10, len = 16;
		DTP dtp(userKey);

		for (int idxTrial = 0; idxTrial < 100; idxTrial++)
		{
			u8* plainText = ByteArray(prng.get<block>());;//TODO: contains 2 plaintexts (64 bits each)
			for (int i = 0; i < len; i++)
				plainText[i] = plainText[i] % radix; //get radix domain => TODO: reuse another 4 first bits of each byte

			u8* tweak = ByteArray(prng.get<block>());

			//std::cout << toBlock(plainText) << std::endl;
			//printArrU8(plainText, len);
			//std::cout << "tweak: " << toBlock(tweak) << std::endl;

			u8* cipherText = dtp.encrypt(plainText, tweak, len, radix);
			u8* X1 = dtp.decrypt(cipherText, tweak, len, radix);

			if (memcmp(X1, plainText, len))
			{
				std::cout << "ciphertex:"; printArrU8(cipherText, len);
				std::cout << "new plaintext: "; printArrU8(X1, len);
				std::cout << "org plaintext: "; printArrU8(plainText, len);
				std::cout << "bad enc/dec DTP" << idxTrial << std::endl;
				throw std::exception();
			}
		}
		std::cout << "good enc/dec DTP!" << std::endl;

	}

}