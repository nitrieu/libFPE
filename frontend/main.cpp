/*
File:   main.cpp
Author: Ni Trieu (trieun@oregonstate.edu)
Date:   01 January 2018
Brief:
*/

#include <iostream>
#include <thread>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libFPE/FpeUtils.h>
#include <libFPE/Feistel/FF3.h>
#include <libFPE/DTP/DTP.h>
#include "CLP.h"
#include "main.h"

using namespace osuCrypto;


void FF3_Sample()
{
	PRNG prng(_mm_set_epi64x(12345678, 24324324));
	block userKey = _mm_set_epi64x(12345678, 1234567);
	int radix = 10, len = 16;
	FF3 ff3(userKey);

	u8* plainText = ByteArray(prng.get<block>());;//TODO: contains 2 plaintexts (64 bits each)
	for (int i = 0; i < len; i++)
		plainText[i] = plainText[i] % radix; //get radix domain => TODO: reuse another 4 first bits of each byte

	u8* tweak = ByteArray(prng.get<block>());
	u8* cipherText = ff3.encrypt(plainText, tweak, len, radix);
	u8* decryptText = ff3.decrypt(cipherText, tweak, len, radix);

	std::cout << "plainText:  \t"; printArrU8(plainText, len);
	std::cout << "tweak    :  \t"; printArrU8(tweak, 64/8);
	std::cout << "cipherText: \t"; printArrU8(cipherText, len);
	std::cout << "decryptText:\t"; printArrU8(decryptText, len);

	if (memcmp(decryptText, plainText, len))
	{
		std::cout << "bad enc/dec FF3"  << std::endl;
		throw std::exception();
	}
	else
		std::cout << "good enc/dec FF3!" << std::endl;

}


void DTP_Sample()
{
	PRNG prng(_mm_set_epi64x(12345678, 24324324));
	block userKey = _mm_set_epi64x(12345678, 1234567);
	int radix = 10, len = 16;
	DTP dtp(userKey);

	u8* plainText = ByteArray(prng.get<block>());;//TODO: contains 2 plaintexts (64 bits each)
	for (int i = 0; i < len; i++)
		plainText[i] = plainText[i] % radix; //get radix domain => TODO: reuse another 4 first bits of each byte

	u8* tweak = ByteArray(prng.get<block>());
	u8* cipherText = dtp.encrypt(plainText, tweak, len, radix);
	u8* decryptText = dtp.decrypt(cipherText, tweak, len, radix);

	std::cout << "plainText:  \t"; printArrU8(plainText, len);
	std::cout << "tweak    :  \t"; printArrU8(tweak, 64 / 8);
	std::cout << "cipherText: \t"; printArrU8(cipherText, len);
	std::cout << "decryptText:\t"; printArrU8(decryptText, len);

	if (memcmp(decryptText, plainText, len))
	{
		std::cout << "bad enc/dec DTP" << std::endl;
		throw std::exception();
	}
	else
		std::cout << "good enc/dec DTP!" << std::endl;

}

int main(int argc, char** argv)
{
	std::cout << "================FF3_Sample================" << std::endl;
	FF3_Sample();

	std::cout << "================DTP_Sample================" << std::endl;
	DTP_Sample();
    return 0;
}
