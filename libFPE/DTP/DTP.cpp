/*
File:   DTP.cpp
Author: Ni Trieu (trieun@oregonstate.edu)
Date:   11 January 2018
Brief:
*/

#include "DTP.h"

namespace osuCrypto
{
	const DTP mDTPFixedKey(_mm_set_epi8(2, -1, -3, -22, 92, -26, 49, 9, -82, -86, -51, -96, 98, -20, 29, -13));

	DTP::DTP(const block & userKey)
	{
		setKey(userKey);
	}

	void DTP::setKey(const block & userKey)
	{
		mAesEnc.setKey(userKey);
	}

	u8* DTP::encrypt( u8* plainText, u8* tweak,  int len,int radix)
	{
		u8* Z = new u8[BIT128];  //128 bits
		block temp;
		u8* Y = new u8[len]; //depend on len

		for (int i = 0; i < len; i++)
		{
			temp=mAesEnc.ecbEncBlock(toBlock(tweak));
			Z = ByteArray(temp);

			Y[i] = pMod(plainText[i] + Z[0], radix);

			temp = SHR128(toBlock(Z), 8); //faster shift
			tweak = ByteArray(temp);
			tweak[15] = plainText[i];
		}
		return Y;
	}

	u8* DTP::decrypt( u8* cipherText, u8* tweak, int len, int radix)//TODO: enc 2 plaintexts each time
	{
		u8* Z = new u8[BIT128]; //128 bits
		u8* X = new u8[len]; //depend on len

		block temp;

		for (int i = 0; i < len; i++)
		{
			temp=mAesEnc.ecbEncBlock(toBlock(tweak));
			Z = ByteArray(temp);

			X[i] = pMod(cipherText[i] - Z[0], radix);

			temp = SHR128(toBlock(Z), 8);
			tweak = ByteArray(temp);

			tweak[15] = X[i];
		}
		return X;
	}
}
