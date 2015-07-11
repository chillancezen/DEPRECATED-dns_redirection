#include "dns_main.h"
extern struct dns_server_item dns_server[];
extern int dns_server_nb;
uint64_t  system_hz;

extern struct lcore_conf_item * tx_lcore_array[MAX_PORTS_NB][MAX_LCORE_NB];
extern int tx_lci_nb[MAX_PORTS_NB];

extern int port_mapping[MAX_PORTS_NB];

/*
*extract metadata encapsulated in the tail of the pkts,if failure occurrs,we may indicate this through next block action
*/
int dns_nat_extract_context(struct rte_mbuf*mbuf,struct mbuf_user_context*context)
{
	#if 1
	struct dns_hash_node *dhn=&context->hash_node;
	#endif
 	struct packet_parameter *pp;
	int pkt_len=rte_pktmbuf_data_len(mbuf);
	if(pkt_len<(int)sizeof(struct packet_parameter))
		goto except_flag;
	int header_offset=pkt_len-sizeof(struct packet_parameter);
	context->eh=rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
	pp=(struct packet_parameter*)(header_offset+(char*)context->eh);
	context->ipp=(struct ipv4_hdr*)(pp->ip_offset+(char*)context->eh);
	context->udpp=(struct udp_hdr*)(pp->udp_offset+(char*)context->eh);
	context->payload=(void*)(pp->payload_offset+(char*)context->eh);
	context->dn_length=pp->dn_length;
	memcpy(context->domain_name,((char*)pp)-pp->dn_length,pp->dn_length);
	context->domain_name[pp->dn_length]='\0';
	context->dnsp=(struct dns_common_hdr*)context->payload;

	rte_pktmbuf_trim(mbuf,pp->dn_length+sizeof(struct packet_parameter));
	context->next_action=block_action_next_block;
	#if 1
	dhn->hash_key_len=8;
	if((0x80&(context->dnsp->lefty_byte))==0){
		memcpy(dhn->hash_key,&context->ipp->src_addr,sizeof(uint32_t));
		memcpy(dhn->hash_key+4,&context->udpp->src_port,sizeof(uint16_t));
		memcpy(dhn->hash_key+6,&context->dnsp->id,sizeof(uint16_t));
		memcpy(&dhn->original_ip,&context->ipp->dst_addr,sizeof(uint32_t));//store original IP address and mac_address
		memcpy(dhn->original_mac,context->eh->d_addr.addr_bytes,6);
		
		context->packet_type=dns_packet_type_query;
	}else{
		memcpy(dhn->hash_key,&context->ipp->dst_addr,sizeof(uint32_t));
		memcpy(dhn->hash_key+4,&context->udpp->dst_port,sizeof(uint16_t));
		memcpy(dhn->hash_key+6,&context->dnsp->id,sizeof(uint16_t));
		context->packet_type=dns_packet_type_response;
	}
	dhn->signature=calculate_signature(dhn->hash_key,dhn->hash_key_len);
	context->hash_index=calculate_hash(dhn->hash_key,dhn->hash_key_len);
	#endif
	
	return 0;
	except_flag:
		context->next_action=block_action_drop;
		return -1;
		
}
/*
*remove an entry item in the hash table,
*after the function is invoked ,the node will never be referenced again
*so make it clear when to invoke this function
*/
int dns_private_recollect_mempool_obj(struct rte_mempool *mempool,struct dns_hash_node **hash_tbl,int hash_idx,struct dns_hash_node* dhn)
{

	if(dhn->prev)
		dhn->prev->next=dhn->next;
	else 
		hash_tbl[hash_idx]=dhn->next;
	if(dhn->next)
				dhn->next->prev=dhn->prev;
	rte_mempool_sp_put(mempool,dhn);//recollect the dns-hash-node
	return 0;
}
struct dns_hash_node * dns_private_insert_mempool_obj(struct rte_mempool * mempool,struct dns_hash_node**  hash_tbl,int hash_idx,struct dns_hash_node*dhn)
{
	int ret;
	struct dns_hash_node *dhn_target=NULL;
	void * data;
	ret=rte_mempool_sc_get(mempool,(void**)&data);
	if(ret==-ENOENT)
		goto ret_flag;
	dhn_target=(struct dns_hash_node*)data;
	copy_hash_node(dhn_target,dhn);
	dhn_target->last_tsc=rte_rdtsc();

	dhn_target->next=hash_tbl[hash_idx];
	hash_tbl[hash_idx]=dhn_target;
	
	return dhn_target;
	ret_flag:
	return NULL;
}
int dns_hash_index(__dbg struct rte_mempool *mempool,__dbg struct dns_hash_node**hash_tbl,__dbg struct rte_mbuf*mbuf,struct mbuf_user_context*context)
{
	int hash_idx=0;
	struct dns_hash_node *dhn=NULL,*dhn_tmp,*dhn_next;
	if(context->next_action!=block_action_next_block)
		return 0;
	hash_idx=context->hash_index&SCHED_HASH_MASK;
	dhn=hash_tbl[hash_idx];
	/*try to find this a matched entry*/
	dhn_tmp=&context->hash_node;
	uint64_t clear_diff=DNS_ENTRY_CLEAR_TIME*system_hz;
	uint64_t cur_tsc;
	uint64_t gap_diff;
	
	cur_tsc=rte_rdtsc();
	

	while(dhn){
		dhn_next=dhn->next;/*keep it here*/
		
		if(dhn->signature==dhn_tmp->signature)
			if(is_hash_nodes_equal(dhn,dhn_tmp))
				break;
		/*check whether the item  expires£¬if so remove it*/
		gap_diff=cur_tsc-dhn->last_tsc;
		if(gap_diff>clear_diff)
			dns_private_recollect_mempool_obj(mempool,hash_tbl,hash_idx,dhn);
		dhn=dhn_next;
	}
	if(dhn){
		dhn->last_tsc=rte_rdtsc();//update timestamp countre
	}else if(context->packet_type==dns_packet_type_query){//if not found,and this paket is a DNS query packet,we establish a entry item here
		dhn=dns_private_insert_mempool_obj(mempool,hash_tbl,hash_idx,dhn_tmp);
	}
	if(dhn){
		context->hash_real_node=dhn;
		context->next_action=block_action_next_block;
	}
	else 
		context->next_action=block_action_forward;
	
	return 0;
}

/*
* no matter what policy is  applied,when reaching this block,and the next_action is block_action_next_block,
* dst address translation will be made.
*/
int dns_nat_translate_addr(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context*context)
{
	if(context->next_action!=block_action_next_block)
		return 0;
	struct dns_server_item *dsi=&dns_server[0];
	
	#ifdef USE_SERVER_LOAD_BALANCE
	uint8_t server_key[4];
	memcpy(server_key,&context->ipp->dst_addr,4);
	int server_idx=calculate_dispatch_index(server_key,4);
	server_idx%=dns_server_nb;
	dsi=&dns_server[server_idx];
	#endif 
	struct dns_hash_node *dhn=context->hash_real_node;
	if(context->packet_type==dns_packet_type_query){//alter dst ip address and mac address,and update check-sum
		/*change ip hdr checksum*/
		uint16_t * lpnew=(uint16_t*)&dsi->ip_addr;
		uint16_t * lpdst=(uint16_t*)&context->ipp->dst_addr;
		uint16_t * lpsum=(uint16_t*)&context->ipp->hdr_checksum;
		uint16_t sum=*lpsum;
		sum=wrap_csum(sum,lpdst[0],lpnew[0]);
		sum=wrap_csum(sum,lpdst[1],lpnew[1]);
		context->ipp->hdr_checksum=sum;
		/*change udp check sum if needed*/
		if(context->udpp->dgram_cksum){
			lpsum=&context->udpp->dgram_cksum;
			sum=*lpsum;
			sum=wrap_csum(sum,lpdst[0],lpnew[0]);
			sum=wrap_csum(sum,lpdst[1],lpnew[1]);
			context->udpp->dgram_cksum=sum;
		}
		memcpy(&context->ipp->dst_addr,&dsi->ip_addr,sizeof(uint32_t));
		memcpy(context->eh->d_addr.addr_bytes,dsi->mac,8);
	}
	else{
		uint16_t * lpnew=(uint16_t*)&dhn->original_ip;
		uint16_t * lpdst=(uint16_t*)&context->ipp->src_addr;
		uint16_t * lpsum=(uint16_t*)&context->ipp->hdr_checksum;
		uint16_t sum=*lpsum;
		sum=wrap_csum(sum,lpdst[0],lpnew[0]);
		sum=wrap_csum(sum,lpdst[1],lpnew[1]);
		context->ipp->hdr_checksum=sum;
		if(context->udpp->dgram_cksum){
			lpsum=&context->udpp->dgram_cksum;
			sum=*lpsum;
			sum=wrap_csum(sum,lpdst[0],lpnew[0]);
			sum=wrap_csum(sum,lpdst[1],lpnew[1]);
			context->udpp->dgram_cksum=sum;
		}
		memcpy(&context->ipp->src_addr,&dhn->original_ip,sizeof(uint32_t));
		memcpy(context->eh->s_addr.addr_bytes,dhn->original_mac,6);
	}
	context->next_action=block_action_forward;
	return 0;
	//except_flag:
		context->next_action=block_action_drop;
		return -1;
}

int  dns_nat_action(struct rte_mbuf*mbuf,struct mbuf_user_context*context)
{
	int input_port;
	int dst_port;
	int dis_idx;
	struct lcore_conf_item * lci;
	int rc;
	switch(context->next_action)
	{
		case block_action_redirect:
		case block_action_next_block:
		case block_action_drop:
			rte_pktmbuf_free(mbuf);
			break;
		case block_action_forward:
			input_port=mbuf->pkt.in_port;
			dst_port=port_mapping[input_port];

			if(context->ipp){
					context->dn_length=8;
					memcpy(context->dis_key,&context->ipp->src_addr,sizeof(uint32_t));
					memcpy(context->dis_key+4,&context->ipp->dst_addr,sizeof(uint32_t));
			}else{//even its an IPv6 packet
					context->dn_length=12;
					memcpy(context->dis_key,context->eh->d_addr.addr_bytes,sizeof(uint32_t));
					memcpy(context->dis_key+6,context->eh->s_addr.addr_bytes,sizeof(uint32_t));
			}
			
			dis_idx=calculate_dispatch_index(context->dis_key,context->key_len);
			dis_idx%=tx_lci_nb[dst_port];

			lci=tx_lcore_array[dst_port][dis_idx];
		
			rc=rte_ring_mp_enqueue(lci->ring,mbuf);
			if(rc==-ENOBUFS)
					rte_pktmbuf_free(mbuf);
			break;
		default:
			
			break;
	}
	
	return 0;
}
