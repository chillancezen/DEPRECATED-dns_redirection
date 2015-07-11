
#include "dns_main.h"
/***********************************
*this utility function help to find a mempool which may be index locally according to lcore_id,if no target matched ,then 
*a LCORE_ID_ANY will be returned ,and NULL if even no LCORE_ID_ANY item matched.
*/
struct rte_mempool* find_sutiable_mempool(struct mbuf_conf_item*arr,int isize,int socket_id)
{
	int any_id_idx=-1;
	int any_id_lowest_refcnt=0x8000;//the number should be big enough
	int idx=0;
	for(;idx<isize;idx++){
		if(!arr[idx].mempool)
			continue;
		if(arr[idx].socket_id==(int)LCORE_ID_ANY){
			if(arr[idx].ref_cnt<any_id_lowest_refcnt){
				any_id_lowest_refcnt=arr[idx].ref_cnt;
				any_id_idx=idx;
			}
			continue;
		}
		if(arr[idx].socket_id==socket_id)
			break;
	}
	if(idx<isize)
		return arr[idx].mempool;
	if(any_id_idx==-1)
		return NULL;
	arr[any_id_idx].ref_cnt++;
	return arr[any_id_idx].mempool;
}
#define __offsetof(type, field)  ((size_t) &( ((type *)0)->field))

int  reset_user_conext(struct mbuf_user_context*context)
{
	//printf("%lu,%lu\n",sizeof(struct mbuf_user_context),__offsetof(struct mbuf_user_context,dummy));
	memset(context,0x0,__offsetof(struct mbuf_user_context,dummy));
	
	return 0;
}

int copy_hash_node(struct dns_hash_node* dst_node, const struct dns_hash_node*src_node)
{
	dst_node->hash_key_len=src_node->hash_key_len;
	memcpy(dst_node->hash_key,src_node->hash_key,dst_node->hash_key_len);
	//dst_node->last_tsc=rte_rdtsc();
	dst_node->signature=src_node->signature;
	dst_node->original_ip=src_node->original_ip;
	dst_node->next=dst_node->prev=NULL;
	memcpy(dst_node->original_mac,src_node->original_mac,6);
	return 0;
}
int is_hash_nodes_equal(struct dns_hash_node*node1,struct dns_hash_node*node2)
{
	if(node1->hash_key_len!=node2->hash_key_len)
		return 0;
	int idx=0;
	for(;idx<node1->hash_key_len;idx++)
		if(node1->hash_key[idx]!=node1->hash_key[idx])
			return 0;
		
	return 1;
	
}
uint16_t wrap_csum(uint16_t oldsum,uint16_t oldval,uint16_t newval)
{	
	uint32_t newsum=((0xffff)&(~oldsum));	
	newsum+=((0xffff)&(~oldval))+newval;	
	while(newsum&0xffff0000)		
		newsum=(newsum&0xffff)+((newsum>>16)&0xffff);	
	return (uint16_t)((~newsum)&0xffff);
}


