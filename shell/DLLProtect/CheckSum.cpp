#include "CheckSum.h"


unsigned int get_crc32(unsigned char *buffer, unsigned int size)
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
		
		while(size--)
		{
				crc = ((crc>>8) & 0x00FFFFFF) ^ crcTable[ (crc^(*buffer)) & 0xFF ];
				buffer++;
		}
		
	return (crc^0xFFFFFFFF);
}