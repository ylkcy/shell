#ifndef _AES_H
#define _AES_H

#include <string>
using namespace std;

#include <botan/botan.h>

// input  输入字节串
// passphrase 用于生成128位密钥的字符串,本函数使用MD5生成128位长度的密钥
// Cipher_Dir opt  ENCRYPTION 加密 DECRYPTION 解密
// @return 返回操作后的字节串. 
void CryptoAES128(Botan::SecureVector<Botan::byte>& input, std::string passphrase, Botan::Cipher_Dir opt, Botan::SecureVector<Botan::byte>& output);

// string input  输入字节串
// string passphrase 用于生成128位密钥的字符串,本函数使用MD5生成128位长度的密钥
// Cipher_Dir opt  ENCRYPTION 加密 DECRYPTION 解密
// @return 返回操作后的字节串.
void CryptoAES256(Botan::SecureVector<Botan::byte>& input, std::string passphrase, Botan::Cipher_Dir opt, Botan::SecureVector<Botan::byte>& output);


#endif