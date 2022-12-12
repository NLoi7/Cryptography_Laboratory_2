#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include <cryptopp/integer.h>
#include "cryptopp/modarith.h"
#include <cryptopp/nbtheory.h> // a_times_b_mod_c
#include <iomanip>

#include <codecvt>
using std::codecvt_utf8;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

#include <stdexcept>
using std::runtime_error;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/dsa.h"
using CryptoPP::DSA;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include <cryptopp/cryptlib.h>
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

wstring integer_to_wstring(const CryptoPP::Integer &t)
    {
        std::ostringstream oss;
        oss.str("");
        oss.clear();
        oss << t;                       // pumb t to oss
        std::string encoded(oss.str()); // to string
        std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
        return towstring.from_bytes(encoded); // string to wstring
    }
void PrintKeys(RSA::PrivateKey &privateKey, RSA::PublicKey &publicKey)
    {
        wcout << "##### RSA parameters #####" << endl;
        wcout << "Public modulo n = " << integer_to_wstring(publicKey.GetModulus()) << endl;
        wcout << endl;
        wcout << "Private prime number p = " << integer_to_wstring(privateKey.GetPrime1()) << endl;
        wcout << endl;
        wcout << "Private prime number q = " << integer_to_wstring(privateKey.GetPrime2()) << endl;
        wcout << endl;
        wcout << "Public key e = " << integer_to_wstring(publicKey.GetPublicExponent()) << endl;
        wcout << endl;
        wcout << "Secret key d = " << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
        wcout << endl;
    }

void Load(const string &filename, BufferedTransformation &bt)
    {
        FileSource file(filename.c_str(), true /*pumpAll*/);
        file.TransferTo(bt);
        bt.MessageEnd();
    }
void SetupVietnameseSupport()
{
     #ifdef __linux__
        setlocale(LC_ALL, "");
    #elif _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #endif
}
void Save(const string &filename, const BufferedTransformation &bt)
    {
        FileSink file(filename.c_str());
        bt.CopyTo(file);
        file.MessageEnd();
    }
void SavePrivateKey(const string &filename, const PrivateKey &key)
    {
        ByteQueue queue;
        key.Save(queue);
        Save(filename, queue);
    }
void SavePublicKey(const string &filename, const PublicKey &key)
    {
        ByteQueue queue;
        key.Save(queue);
        Save(filename, queue);
    }
void LoadPrivateKey(const string &filename, PrivateKey &key)
    {
        ByteQueue queue;
        Load(filename, queue);
        key.Load(queue);
    }

int main(int argc, char **argv)
{
	SetupVietnameseSupport();
	AutoSeededRandomPool rnd;

	try
	{
		// Generate private key
		RSA::PrivateKey rsaPrivate;
		rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

		// Generate public key deriving from the private key
		RSA::PublicKey rsaPublic(rsaPrivate);

// Save keys to files
#ifdef _WIN32
		SavePrivateKey("rsa-private.key", rsaPrivate);
		SavePublicKey("rsa-public.key", rsaPublic);
#elif __linux__
		SavePrivateKey("rsa-private.key", rsaPrivate);
		SavePublicKey("rsa-public.key", rsaPublic);
#endif

		PrintKeys(rsaPrivate, rsaPublic);
		////////////////////////////////////////////////////////////////////////////////////
		/* Check the keys */
		CryptoPP::Integer n, p, q, e, d;
		n = rsaPublic.GetModulus();
		p = rsaPrivate.GetPrime1();
		q = rsaPrivate.GetPrime2();
		CryptoPP::ModularArithmetic ma(n);
		//wcout << "Modunlo  n= " << integer_to_wstring(rsaPublic.GetModulus()) << endl;
		//wcout << " p.q=" << integer_to_wstring(ma.Multiply(p, q)) << endl;
		//wcout << integer_to_wstring(a_times_b_mod_c(p,q,n)) << endl;

		DSA::PrivateKey dsaPrivate;
		dsaPrivate.GenerateRandomWithKeySize(rnd, 2048);

		DSA::PublicKey dsaPublic;
		dsaPrivate.MakePublicKey(dsaPublic);

#ifdef _WIN32
		SavePrivateKey("dsa-private.key", dsaPrivate);
		SavePublicKey("dsa-public.key", dsaPublic);
#elif __linux__
		SavePrivateKey("dsa-private.key", dsaPrivate);
		SavePublicKey("dsa-public.key", dsaPublic);
#endif

		////////////////////////////////////////////////////////////////////////////////////

		RSA::PrivateKey r1, r2;
		r1.GenerateRandomWithKeySize(rnd, 3072);

#ifdef _WIN32
		SavePrivateKey("rsa-roundtrip.key", r1);
		LoadPrivateKey("rsa-roundtrip.key", r2);
#elif __linux__
		SavePrivateKey("rsa-roundtrip.key", r1);
		LoadPrivateKey("rsa-roundtrip.key", r2);
#endif

		r1.Validate(rnd, 3);
		r2.Validate(rnd, 3);

		if (r1.GetModulus() != r2.GetModulus() ||
			r1.GetPublicExponent() != r2.GetPublicExponent() ||
			r1.GetPrivateExponent() != r2.GetPrivateExponent())
		{
			throw runtime_error("key data did not round trip");
		}

		////////////////////////////////////////////////////////////////////////////////////

		wcout << "Successfully generated and saved RSA and DSA keys" << endl;
	}

	catch (CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch (std::exception &e)
	{
		cerr << e.what() << endl;
		return -1;
	}

	return 0;
}