/*
* we use jhash to calculate the even key,
*and uniformlly dispatch it to the downstream worker
*/

#include "dns_main.h"
uint32_t calculate_dispatch_index(__dbg unsigned char * key,__dbg int ilength)
{
	uint32_t ret;
	ret=jhash(key,ilength,0x0);
	return ret;
}
uint32_t calculate_signature(uint8_t * key,int length)
{
	return jhash(key,length,0x1);
}
uint32_t calculate_hash(uint8_t *key,int length)
{
	return jhash(key,length,0x0);
}
