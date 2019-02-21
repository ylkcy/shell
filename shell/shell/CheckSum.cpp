#include "CheckSum.h"


unsigned int CRC32(unsigned char *buffer, unsigned int size)
{
	unsigned int crcTable[256];
	unsigned int crcTmp;
	unsigned int crc = 0xFFFFFFFF;
	
	//��̬����CRC-32��
	for (int i = 0; i < 256; i++)
	{
		crcTmp = i;
		for (int j = 8; j > 0; j--)
		{
			if (crcTmp & 1)
				crcTmp = (crcTmp >> 1) ^ CRCPOLY;
			 else 
			 	crcTmp >>= 1;
		}
		crcTable[i] = crcTmp;
	}
	//����CRC32ֵ
	for (int i = 0; i < size; i++) 
	{
		crc = crcTable[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
	}
	
	return (crc ^ 0xFFFFFFFF);
}