#include "dns_main.h"
/*
*preserve some tunnel decapsulation interface in case needed 
*/
int dns_tunel_decapsulate(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context *context)
{
	#ifdef DNS_CONFIG_GRE_TUNNEL

	#else
	context->is_encap=FALSE;
	context->encap_len=0;
	
	#endif

	
	return 0;
}

