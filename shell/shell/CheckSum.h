#ifndef _CRC_H
#define _CRC_H


#define CRCPOLY 0xedb88320L


unsigned int CRC32(unsigned char *buffer, unsigned int size);


#endif