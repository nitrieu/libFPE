/*
File:   FpeUtils.h
Author: Ni Trieu (trieun@oregonstate.edu)
Date:   02 January 2018
Brief:  Utils
*/

#pragma once
#include <iostream>
#include <map>
#include <set>
#include <algorithm>
#include <functional>
#include <algorithm>
#include <array>
#include <memory>
#include <type_traits>
#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <string>
#include <iostream>
#include <string>
#include <numeric>
#include <iterator>
#include <cstdint>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <thread>
#include <vector>
#include <cryptoTools/Common/Timer.h>
#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#pragma warning(disable:4996)
#endif //  _MSC_VER

using namespace osuCrypto;

# define FF3_ROUNDS 8
#define BIT128 16
#define BIT2BYTE 8

namespace osuCrypto
{
	#define BIT128 16
	inline block SHR128(block v, int n)
	{
		__m128i v1, v2;
		if ((n) >= 64)
		{
			v1 = _mm_srli_si128(v, 8);
			v1 = _mm_srli_epi64(v1, (n)-64);
		}
		else
		{
			v1 = _mm_srli_epi64(v, n);
			v2 = _mm_srli_si128(v, 8);
			v2 = _mm_slli_epi64(v2, 64 - (n));
			v1 = _mm_or_si128(v1, v2);
		}
		return v1;
	}

	inline block SHL128(block v, int n)
	{
		__m128i v1, v2;

		if ((n) >= 64)
		{
			v1 = _mm_slli_si128(v, 8);
			v1 = _mm_slli_epi64(v1, (n)-64);
		}
		else
		{
			v1 = _mm_slli_epi64(v, n);
			v2 = _mm_slli_si128(v, 8);
			v2 = _mm_srli_epi64(v2, 64 - (n));
			v1 = _mm_or_si128(v1, v2);
		}
		return v1;
	}

	inline void printArrU8(u8* Z, int size) {

		for (int i = 0; i < size; i++)
			std::cout << static_cast<unsigned int>(Z[i]);

		std::cout << std::endl;
	}

	inline std::string arrU8toString(u8* Z, int size)
	{
		std::string sss;
		for (int j = 0; j < size; j++)
			sss.append(ToString(static_cast<unsigned int>(Z[j])));

		return sss;
	}
	
	inline int roundUp(int n, int round)
	{
		return (n + round - 1) / round;
	}

	inline void printHex(u8* bytes, int size)
	{
		std::cout << std::hex << std::setfill('0');
		for (int i = 0; i < size; i++)
			std::cout << std::setw(2) << int(bytes[i]) << ' ';
		std::cout << '\n';
	}

	inline bool getBit(unsigned char byte, int position) // position in range 0-7
	{
		return (byte >> position) & 0x1;
	}

	inline int NumRadix(u8* numX, int len, int radix)
	{
		int res = 0;
		for (int i = 0; i < len; i++)
		{
			res = res * radix + numX[i];
		}
		//std::cout << res << std::endl;
		return res;
	}

	inline int Num(u8* byteX, int lenInByte, int radix, int m) // bits to bigint => avoid big number by mod radix^m 
	{
		int radix_m = pow(radix, m);
		//std::cout << "radix_m: " << radix_m << '\n';

		int res = 0;
		for (int i = lenInByte - 1; i >= 0; i--)
		{
			//std::cout << std::hex << std::setfill('0') << std::setw(2) << int(byteX[i]) << ' ';
			//std::cout << ": ";
			//std::cout << getBit(byteX[i], 7) << getBit(byteX[i], 6) << getBit(byteX[i], 5) << getBit(byteX[i], 4) << ' '
			//	<< getBit(byteX[i], 3) << getBit(byteX[i], 2) << getBit(byteX[i], 1) << getBit(byteX[i], 0) << "\n";

			for (int j = 7; j >= 0; j--)
				res = (res * 2 + ((byteX[i] >> j) & 0x1)) % radix_m;
		}

		//std::cout << '\n';

		return res;
	}

	inline u8* StrRadixIn8(int x, int lenIn8, int radix)
	{
		u8* numX = new u8[lenIn8];
		for (int i = 0; i < lenIn8; i++)
		{
			numX[lenIn8 - 1 - i] = x % radix;
			x = floor(x / radix);
		}

		return numX;
	}

	inline u8* Rev(u8* input, int len) //numeral string, each u8 contains value of each number 
	{
		u8* output = new u8[len];

		for (int i = 0; i < len; i++)
			output[i] = input[len - 1 - i];

		return output;
	}

	inline u8* RevB(u8* input, int lenInByte) //bit representation
	{
		u8* output = new u8[lenInByte];

		for (int i = 0; i < lenInByte; i++)
			output[i] = input[lenInByte - 1 - i];

		return output;
	}
	
	template< typename T > std::array< u8, sizeof(T) >  to_bytes(const T& object)
	{
		std::array< u8, sizeof(T) > bytes;

		const u8* begin = reinterpret_cast<const u8*>(std::addressof(object));
		const u8* end = begin + sizeof(T);
		std::copy(begin, end, std::begin(bytes));

		return bytes;
	}
	
	inline int arrU8ToInt(u8* X, int len, int radix)
	{
		u8* revX = Rev(X, len);
		return NumRadix(revX, len, radix);
	}

	inline u8* intToArrU8(int num, int len, int radix)
	{
		u8* revX = StrRadixIn8(num, len, radix);
		return Rev(revX, len);
	}


	//############DTP##################
	inline int pMod(int i, int n) {
		return (i % n + n) % n;
	}

}