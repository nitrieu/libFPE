# Format Preserving Encryption
A fast and portable C++ library for Format Preserving Encryption which currently implements:
 * FF3: http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
 * DTP (Data-type Preserving Encryption): https://eprint.iacr.org/2009/257

## Installations

### Required libraries
 C++ compiler with C++14 support. There are several library dependencies including [`Boost`](https://sourceforge.net/projects/boost/), [`Miracl`](https://github.com/miracl/MIRACL), [`cryptoTools`](https://github.com/ladnir/cryptoTools). Our code has been tested on both Windows (Microsoft Visual Studio) and Linux. To install the required libraries: 
  * windows: open PowerShell,  `cd ./cryptoTools/thirdparty/win`, and `.\getBoost.ps1`  `.\getMiracl.ps1`
  * linux: `cd ./thirdparty/linux`, and `bash all.get`.   


### Building the Project
After cloning project from git,
##### Windows:
1. build cryptoTools and libFPE in order (cd `libFPE/thirdparty/linux/`, `bash all.get`, `cd ../.. && cmake . && make`, `cd .. && cmake . && make`

2. main project is `frontend` 
3. run `frontend` project
 
##### Linux:
1. make (requirements: `CMake`, `Make`, `g++` or similar)
2. for test:
	./bin/frontend.exe 
	
## Usage
```c++
FF3 ff3(userKey); //assign encryption key for AES-NI
u8* cipherText = ff3.encrypt(plainText, tweak, len, radix);
u8* decryptText = ff3.decrypt(cipherText, tweak, len, radix);
```

## Help
For any questions on building or running the library, please contact [`Ni Trieu`](http://people.oregonstate.edu/~trieun/) at trieun at oregonstate dot edu
