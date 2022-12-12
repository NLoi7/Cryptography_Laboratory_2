#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::cin;

#include <sstream>
using std::ostringstream;

#include <codecvt>
using std::codecvt_utf8;

#include <sstream>
using std::ostringstream;

#include <stdexcept>
using std::runtime_error;

#include <string>
using std::string;

//lib for reading a files
#include <fstream>
using std::ifstream;

#include <stdexcept>
using std::runtime_error;
//header from crypto
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/dsa.h"
using CryptoPP::DSA;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation; // using for load function
using CryptoPP::DecodingResult;
using CryptoPP::Exception;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/nbtheory.h"
#include "cryptopp/modarith.h"
#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

//print key
void PrintKeys(RSA::PrivateKey &privateKey, RSA::PublicKey &publicKey)
{
        cout << "----------------PARAMETER-----------------------" << endl;
        cout << "Public modulo n = " << publicKey.GetModulus() << endl;
        cout << endl;
        cout << "Private prime number p = " << privateKey.GetPrime1() << endl;
        cout << endl;
        cout << "Private prime number q = " << privateKey.GetPrime2() << endl;
        cout << endl;
        cout << "Public key e = " <<publicKey.GetPublicExponent() << endl;
        cout << endl;
        cout << "Secret key d = " << privateKey.GetPrivateExponent() << endl;
        cout << endl;
}
void Load(const string &filename, BufferedTransformation &bt)
{
        FileSource file(filename.c_str(), true );
        file.TransferTo(bt);
        bt.MessageEnd();
}
    // load pr key
void LoadPrivateKey(const string &filename, PrivateKey &key)
{
        ByteQueue queue;
        Load(filename, queue);
        key.Load(queue);
}
// load public key 
void LoadPublicKey(const string &filename, PublicKey &key)
{
        ByteQueue queue;
        Load(filename, queue);
        key.Load(queue);
}
//load key from a files
void Loadkey(RSA::PrivateKey &PrivateKey, RSA::PublicKey &PublicKey)
{
    try
    {
        AutoSeededRandomPool rng;
#ifdef _WIN32
        LoadPublicKey(".\\rsa-public.key", PublicKey);
        LoadPrivateKey(".\\rsa-private.key", PrivateKey);
#elif __linux__
        LoadPublicKey("\rsa-public.key", PublicKey);
        LoadPrivateKey("\rsa-private.key", PrivateKey);
#endif

        if (!PrivateKey.Validate(rng, 3))
        {
            throw runtime_error("private key invalid.");
        }
        if (!PublicKey.Validate(rng, 3))
        {
            throw runtime_error("public key invalid.");
        }
    }
    catch (CryptoPP::Exception &e)
    {
        cout << "Exception on reading keys from files: " << e.what() << endl;
        exit(1);
    }
}
// encyption funcion RSA
string Encrypt_fun_RSA(AutoSeededRandomPool &rng, RSA::PublicKey &PublicKey, string &plaintext)
{
    string ciphertext;
    RSAES_OAEP_SHA_Encryptor encryptor(PublicKey); // using OAEP 
    StringSource(plaintext, true,
                 new PK_EncryptorFilter(rng, encryptor,
                                        new StringSink(ciphertext)));
    return ciphertext;
}
// Main Encryption
void ENCRYPTION(string plaintext)
{
    AutoSeededRandomPool rng;

    //set up key
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    Loadkey(privateKey, publicKey);
    PrintKeys(privateKey, publicKey);
    
    //encrypt
    string ciphertext;
    double time = 0;
    for (int i = 0; i < 10000; ++i)
    {
        int start = clock();
        ciphertext = Encrypt_fun_RSA(rng, publicKey, plaintext);
        int end = clock();
        time += double(end - start) / CLOCKS_PER_SEC;
    }

    cout << "Ciphertext: "<<ciphertext;
    cout << endl;
    cout << "Average encryption time: " << 1000 * time / 10000 << " ms." << endl;
}
// decryption function RSA
string Decrypt_fun_RSA(AutoSeededRandomPool &rng, RSA::PrivateKey &PrivateKey, string &ciphertext)
{
    string recoveredtext;
    RSAES_OAEP_SHA_Decryptor decryptor(PrivateKey);
    StringSource(ciphertext, true,
                 new PK_DecryptorFilter(rng, decryptor,
                                        new StringSink(recoveredtext)));
    return recoveredtext;
}
// Main Decryption
void DECRYPTION(string ciphertext)
{
    AutoSeededRandomPool rng;

    // set up keys
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    Loadkey(privateKey, publicKey);
    PrintKeys(privateKey, publicKey);
    cout << endl;
    //decrypt

    string recovered_text;
    double etime = 0;
    for (int i = 0; i < 10000; ++i)
    {
        int start = clock();
        recovered_text = Decrypt_fun_RSA(rng, privateKey, ciphertext);
        int end = clock();
        etime += double(end - start) / CLOCKS_PER_SEC;
    }

    cout << "Recovered text: " << recovered_text << endl;
    cout << "Average decryption time: " << 1000 * etime / 10000 << " ms." << endl;
}
// input function from screen
string input_plaintext_func_from_screen()
{
    string  plaintext;
    cin.ignore();
    cout<<"Please enter the plaintext : ";
    getline(cin,plaintext);
    return plaintext;
}
//input function from files
string input_plaintext_func_from_files()
{
    string plaintext;
    ifstream input_file;
    input_file.open("plaintext_inputfile/1KB.txt");
    input_file >> plaintext;
    return plaintext;
}
//input function for decryption from a screen
string input_cyphertext_func_from_screen()
{
    string  cyphertext;
    cin.ignore();
    cout<<"Please enter the plaintext : ";
    getline(cin,cyphertext);
    return cyphertext;
}
//input function for deryption from a files
string input_cyphertext_func_from_files()
{
    string cyphertext;
    ifstream input_file;
    input_file.open("cyphertext_inputfile/cipher.txt");
    input_file >> cyphertext;
    return cyphertext;
}
//fuction for encryption
string input_for_encryption()
{
    int Choose_input=0;
    string plaintext;
    cout<<"--> Step 2 ";
    cout<<"Please choose the type of input : \n";
    cout<<"1 : Input from screen \n";
    cout<<"2 : Input from files \n";
    while(true)
    {
        cout<<"Please choose the option : ";
        cin>>Choose_input;
        if (Choose_input < 1 && Choose_input > 2)
            cout<<"Error !! Please choose again !\n";
        break;
    }
    switch (Choose_input)
    {
        case 1: 
            {
                plaintext=input_plaintext_func_from_screen();
                break;;
            }
        case 2:
            {
                plaintext=input_plaintext_func_from_files();
                break;
            }
        default : break;
    }
    return plaintext;
}
//input for decyption
string input_for_decryption()
{
    int Choose_input=0;
    string cyphertext;
    cout<<"----------------MENU---------------------\n";
    cout<<"Please choose the type of input : \n";
    cout<<"1 : Input from screen \n";
    cout<<"2 : Input from files \n";
    while(true)
    {
        cout<<"Please choose the option : ";
        cin>>Choose_input;
        if (Choose_input < 1 && Choose_input > 2)
            cout<<"Error !! Please choose again !\n";
        break;
    }
    switch (Choose_input)
    {
        case 1: 
            {
                cyphertext=input_cyphertext_func_from_screen();
                break;;
            }
        case 2:
            {
                cyphertext=input_cyphertext_func_from_files();
                break;
            }
        default : break;
    }
    return cyphertext;
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
int main()
{
    
    string plaintext,cyphertext, recoverytext;
    int Choose=0;
    // choose the encryption or the decryption 
    cout<<"----------------MENU---------------------\n";
    cout<<"Please choose encryption or decryption : \n";
    cout<<"1 : Encryption \n";
    cout<<"2 : Decryption \n";
    while (true)
    {
        cout<<"Please choose the option : ";
        cin>>Choose;
        if (Choose < 1 && Choose > 2)
            cout<<"Error !! Please choose again !\n";
        break;
    }
    switch (Choose)
    {
    case 1:
        {
            plaintext=input_for_encryption();
            ENCRYPTION(plaintext);
            break;;
        }
    case 2 : 
        {
            cyphertext=input_for_decryption();
            DECRYPTION(cyphertext);
            break;
        }
    default:
        break;
    }

}