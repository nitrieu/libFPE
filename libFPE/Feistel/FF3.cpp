/*
File:   FF3.cpp
Author: Ni Trieu (trieun@oregonstate.edu)
Date:   01 August 2018
Brief:  https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38g.pdf
*/

#include "FF3.h"

namespace osuCrypto
{
	const FF3 mFF3FixedKey(_mm_set_epi8(2, -1, -3, -22, 92, -26, 49, 9, -82, -86, -51, -96, 98, -20, 29, -13));

	FF3::FF3(const block & userKey)
	{
		setKey(userKey);
	}

	void FF3::setKey(const block & userKey)
	{
		mAesEnc.setKey(userKey);
	}

	u8* FF3::encrypt(u8* plainText, u8* tweak, int n, int radix, int numRound)
	{
		u8* cipherText = new u8[n];
		int u = ceil((double)n / 2), v = n - u;

		u8* A = new u8[u]; u8* B = new u8[v];
		u8* TL = new u8[32 / 8]; u8* TR = new u8[32 / 8]; //bit representation
		memcpy(A, plainText, u * sizeof(BYTE)); //A=X[1...u]
		memcpy(B, plainText + u, v * sizeof(BYTE)); //B=X[u+1...n]
		memcpy(TL, tweak, 32 / 8); //first 32 bits
		memcpy(TR, tweak + 32 / 8, 32 / 8); //2nd 32 bits
		//std::cout << toBlock(TL) << "\t" << toBlock(TR) << std::endl;
		
		int m; u8* W = new u8[32 / 8];

		for (int i = 0; i < numRound; i++)
		{
			//================4i================
			int idx = i % 2; //even or old
			m = idx ? v : u;
			W = idx ? TL : TR;

			//================4ii================
			u8* revB = Rev(B, v);
			//std::cout << "printArrU8(B, v); printArrU8(revB, v);: " << std::endl; printArrU8(B, v); printArrU8(revB, v);
			int numRadixRevB = NumRadix(revB, v, radix);

			block idxBlock = _mm_setr_epi8(0, 0, 0, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
			//std::cout << "idxBlock: " << idxBlock << std::endl;

			block blkP = ZeroBlock;
			memcpy((u8*)&blkP, W, 32 / 8); //P=W
			//std::cout << "P=W: " << blkP << std::endl;
			blkP = blkP ^ idxBlock; //P=W+[i]^4
			//std::cout << "P=W+[i]^4: " << blkP << std::endl;

			auto bytes = to_bytes(numRadixRevB);

			block blkNum = ZeroBlock;
			int j = 4; //shift 4 bytes
			for (u8 b : bytes) //stupid copy...
			{
				memcpy((u8*)&blkNum + j, &b, 1);
				j++;
			}
			//std::cout << "blkNum: " << blkNum << std::endl;

			blkP = blkP ^ blkNum; //done with P
			//std::cout << "blkP ^ blkNum: " << blkP << std::endl;

			//================4iii================
			u8* revbP = RevB(ByteArray(blkP), 128 / 8);
			//std::cout << "revbP=" << toBlock(revbP) << std::endl;

			block cipher=mAesEnc.ecbEncBlock(toBlock(revbP)); //dont need to rev the key
			//std::cout << "cipher: " << cipher << std::endl;

			u8* S = RevB(ByteArray(cipher), 128 / 8);
			//std::cout << "S=" << toBlock(S) << std::endl;

			//================4iv================
			int y = Num(S, 16, radix, m);
			//std::cout << "y: " << y << std::endl;

			//================4v================
			u8* revA = Rev(A, u);
			//std::cout << "printArrU8(A, u);; printArrU8(revA, u);;: " << std::endl;
			//printArrU8(A, u); printArrU8(revA, u);
			int numRadixRevA = NumRadix(revA, u, radix);
			//std::cout << "numRadixRevA: " << numRadixRevA << std::endl;

			int c = (numRadixRevA + y) % ((int)pow(radix, m));
			//std::cout << "c: " << c << std::endl;

			//================4vi================
			u8* strRadixC = StrRadixIn8(c, m, radix);
			u8* C = Rev(strRadixC, m);
			//std::cout << "C: " << std::endl; printArrU8(strRadixC, m); printArrU8(C, m);

			A = B;
			B = C;
		}

		memcpy(cipherText, A, u * sizeof(BYTE)); //A=X[1...u]
		memcpy(cipherText + u, B, v * sizeof(BYTE)); //B=X[u+1...n]

		return cipherText;
	}

	u8* FF3::decrypt(u8* cipherText, u8* tweak, int n, int radix, int numRound)
	{
		u8* plainText = new u8[n];
		int u = ceil((double)n / 2), v = n - u;

		u8* A = new u8[u]; u8* B = new u8[v];
		u8* TL = new u8[32 / 8]; u8* TR = new u8[32 / 8]; //bit representation

		memcpy(A, cipherText, u * sizeof(BYTE)); //A=X[1...u]
		memcpy(B, cipherText + u, v * sizeof(BYTE)); //B=X[u+1...n]
		memcpy(TL, tweak, 32 / 8); //first 32 bits
		memcpy(TR, tweak + 32 / 8, 32 / 8); //2nd 32 bits
		//std::cout << toBlock(TL) << "\t dd \t" << toBlock(TR) << std::endl;

		int m; u8* W = new u8[32 / 8];

		for (int i = numRound - 1; i >= 0; i--)
		{
			//================4i================
			int idx = i % 2; //even or old
			m = idx ? v : u;
			W = idx ? TL : TR;

			//================4ii================
			u8* revA = Rev(A, u);
			//std::cout << "printArrU8(A, u); printArrU8(revA, u);: " << std::endl;
			//printArrU8(A, u); printArrU8(revA, u);
			int numRadixRevA = NumRadix(revA, u, radix);

			block idxBlock = _mm_setr_epi8(0, 0, 0, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
			//std::cout << "dd idxBlock: " << idxBlock << std::endl;

			block blkP = ZeroBlock;
			memcpy((u8*)&blkP, W, 32 / 8); //P=W
			//std::cout << "dd P=W: " << blkP << std::endl;
			blkP = blkP ^ idxBlock; //P=W+[i]^4
			//std::cout << "dd P=W+[i]^4: " << blkP << std::endl;

			const auto bytes = to_bytes(numRadixRevA);

			block blkNum = ZeroBlock;
			int j = 4; //shift 4 bytes
			for (u8 b : bytes) //stupid copy...
			{
				memcpy((u8*)&blkNum + j, &b, 1);
				j++;
			}
			//std::cout << "dd blkNum: " << blkNum << std::endl;

			blkP = blkP ^ blkNum; //done with P
			//std::cout << "dd blkP ^ blkNum: " << blkP << std::endl;

			//================4iii================
			u8* revbP = RevB(ByteArray(blkP), 128 / 8);
			//std::cout << "dd revbP=" << toBlock(revbP) << std::endl;

			block cipher=mAesEnc.ecbEncBlock(toBlock(revbP)); //dont need to rev the key
			//std::cout << "dd cipher: " << cipher << std::endl;

			u8* S = RevB(ByteArray(cipher), 128 / 8);
			//std::cout << "S=" << toBlock(S) << std::endl;

			//================4iv================
			int y = Num(S, 16, radix, m);
			//std::cout << "y: " << y << std::endl;

			//================4v================
			u8* revB = Rev(B, v);
			//printArrU8(B, v); printArrU8(revB, v);
			int numRadixRevB = NumRadix(revB, v, radix);
			//std::cout << "numRadixRevB: " << numRadixRevB << std::endl;

			int c = (numRadixRevB - y + (int)pow(radix, m)) % ((int)pow(radix, m)); //get possitive value
			//std::cout << "c: " << c << std::endl;

			//================4vi================
			u8* strRadixC = StrRadixIn8(c, m, radix);
			u8* C = Rev(strRadixC, m);
			//std::cout << "C: " << std::endl;printArrU8(strRadixC, m);printArrU8(C, m);

			B = A;
			A = C;
		}

		memcpy(plainText, A, u * sizeof(BYTE)); //A=X[1...u]
		memcpy(plainText + u, B, v * sizeof(BYTE)); //B=X[u+1...n]

		return plainText;
	}

}
