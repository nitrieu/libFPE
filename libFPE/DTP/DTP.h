/*
File:   DTP.h
Author: Ni Trieu (trieun@oregonstate.edu)
Date:   11 January 2018
Brief:
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
	class DTP
	{
	public:
		AES mAesEnc;

		DTP() {};
		DTP(const DTP&) = default;
		// Constructor to initialize the class with the given key for aes
		DTP(const block& userKey);

		// Set the key to be used for AES encryption.
		void setKey(const block& userKey);

		u8* encrypt(u8* plainText, u8* tweak, int len, int radix);
		u8* decrypt(u8* cipherText, u8* tweak, int len, int radix);
	};

}
