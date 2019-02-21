#include "AES.h"


void CryptoAES128(Botan::SecureVector<Botan::byte>& input, std::string passphrase, Botan::Cipher_Dir opt, Botan::SecureVector<Botan::byte>& output)
{
	Botan::HashFunction* hash = Botan::get_hash("MD5");
	//秘钥
	Botan::SymmetricKey key = hash->process(passphrase);
	//向量
	Botan::SecureVector<Botan::byte> raw_iv = hash->process('0' + passphrase);
	Botan::InitializationVector iv(raw_iv, 16);

	Botan::Pipe pipe(get_cipher("AES-128/CFB", key, iv, opt));

	try
	{
		pipe.process_msg(input);
	}
	catch (Botan::Decoding_Error &e)
	{
		return ;
	}
	output = pipe.read_all();
}


void CryptoAES256(Botan::SecureVector<Botan::byte>& input, std::string passphrase, Botan::Cipher_Dir opt, Botan::SecureVector<Botan::byte>& output)
{
	Botan::HashFunction* hash = Botan::get_hash("SHA-256");
	//秘钥
	Botan::SymmetricKey key = hash->process(passphrase);
	//向量
	Botan::SecureVector<Botan::byte> raw_iv = hash->process('0' + passphrase);
	Botan::InitializationVector iv(raw_iv, 16);

	Botan::Pipe pipe(get_cipher("AES-256/CFB", key, iv, opt));

	try
	{
		pipe.process_msg(input); 
	}
	catch (Botan::Decoding_Error &e)
	{
		return;
	}
	output = pipe.read_all();
}

