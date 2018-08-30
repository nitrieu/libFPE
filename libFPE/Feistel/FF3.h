/*
File:   FF3.h
Author: Ni Trieu (trieun@oregonstate.edu)
Date:   01 August 2018
Brief:  https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38g.pdf
*/

#pragma once
#include "libFPE/FpeUtils.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <thread>
#include <vector>
#include <cryptoTools/Common/Timer.h>
#include <algorithm>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>


#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#pragma warning(disable:4996)
#endif //  _MSC_VER


namespace osuCrypto
{
	class FF3
	{
	public:
		AES mAesEnc;

		FF3() {};
		FF3(const FF3&) = default;
		// Constructor to initialize the class with the given key for aes
		FF3(const block& userKey);

		// Set the key to be used for AES encryption.
		void setKey(const block& userKey);

		u8* encrypt(u8* plainText, u8* tweak, int n, int radix, int numRound = FF3_ROUNDS);
		u8* decrypt(u8* cipherText, u8* tweak, int n, int radix, int numRound = FF3_ROUNDS);
	
	};

}
