#ifndef _AES_H
#define _AES_H

#include <string>
using namespace std;

#include <botan/botan.h>

// input  �����ֽڴ�
// passphrase ��������128λ��Կ���ַ���,������ʹ��MD5����128λ���ȵ���Կ
// Cipher_Dir opt  ENCRYPTION ���� DECRYPTION ����
// @return ���ز�������ֽڴ�. 
void CryptoAES128(Botan::SecureVector<Botan::byte>& input, std::string passphrase, Botan::Cipher_Dir opt, Botan::SecureVector<Botan::byte>& output);

// string input  �����ֽڴ�
// string passphrase ��������128λ��Կ���ַ���,������ʹ��MD5����128λ���ȵ���Կ
// Cipher_Dir opt  ENCRYPTION ���� DECRYPTION ����
// @return ���ز�������ֽڴ�.
void CryptoAES256(Botan::SecureVector<Botan::byte>& input, std::string passphrase, Botan::Cipher_Dir opt, Botan::SecureVector<Botan::byte>& output);


#endif