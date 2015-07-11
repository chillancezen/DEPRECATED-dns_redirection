#include "dns_main.h"
extern struct lcore_conf_item * sched_lcore_array[MAX_LCORE_NB];
extern int sched_lci_nb;

extern struct lcore_conf_item * tx_lcore_array[MAX_PORTS_NB][MAX_LCORE_NB];
extern int tx_lci_nb[MAX_PORTS_NB];

extern int port_mapping[MAX_PORTS_NB];


/*
*in this function,we parse L2 protocols,mainly we just care about IPv4 upper protocl
*parsing position requirment:next following gre tunnel module
*additional features:vlan header sensable
*/

int dns_l2_decap(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context*context)
{
	if(context->is_encap)
		rte_pktmbuf_adj(mbuf,context->encap_len);//shrink data
	
	context->eh=rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
	
	context->l2_upper_proto=HTONS(context->eh->ether_type);
	switch(context->l2_upper_proto)
	{
		case ETHER_TYPE_IPv4:
			context->next_action=block_action_next_block;
			break;
		default :
			context->next_action=block_action_forward;
			break;
	}
	return 0;
	
}
/*
*still figure out whether it's a UDP-ipv4 packet
*parsing postion requirment:next following l2 decapsulation module
*/

int dns_l3_decap(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context*context)
{

	if(context->next_action!=block_action_next_block)
		return -1;
	//struct ether_hdr *eh=rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
	context->ipp=(struct ipv4_hdr*)(sizeof(struct ether_hdr)+(char*)context->eh);
	context->l3_upper_proto=context->ipp->next_proto_id;
	
	switch(context->l3_upper_proto)
	{
		case IP_UDP_FIELD:
			context->next_action=block_action_next_block;
			break;
		default:
			context->next_action=block_action_forward;
			break;
	}
	return 0;
	
}
/*
*checking L4 proto field,mainly about src&dst port
*this block must  tightly follow L3 decap module
*/
int dns_l4_decap(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context*context)
{	
	if(context->next_action!=block_action_next_block)
		return -1;
	//struct ether_hdr *eh=rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
	//struct ipv4_hdr *iph=(struct ipv4_hdr*)(sizeof(struct ether_hdr)+(char*)eh);
	context->udpp=(struct udp_hdr*)((context->ipp->version_ihl&0xf)*4+(char*)context->ipp);

	#if 0
	switch(context->udpp->dst_port)
	{
		case HTONS(53):
			context->payload=(void*)(sizeof(struct udp_hdr)+(char*)context->udpp);
			context->next_action=block_action_next_block;
			break;
		default:
			context->next_action=block_action_forward;
			break;
	}
	#endif
	if((context->udpp->src_port==HTONS(53)) || (context->udpp->dst_port==HTONS(53))){
		context->payload=(void*)(sizeof(struct udp_hdr)+(char*)context->udpp);
		context->next_action=block_action_next_block;
	}else{
		context->next_action=block_action_forward;
	}
	return 0;
}

/*
* try to resolve domain name from str buff,if any problem occurs,
*this function return -1 indicating this
*and if name buffer length exceed MAX_DOMAIN_NAME_LENGTH,the function will fails too
*/
int resolve_domain_name( const char *str,int ilen,char* name,int* name_len)
{
	int idx=0;
	*name_len=0;
	int ilocal_len=0;
	int ilocal_idx=0;
	int ileft;

	do{
		ilocal_len=str[idx];
		if(ilocal_len>63)
			goto illegal;
		if(ilocal_len<0)
			goto illegal;
		if(!ilocal_len)
			break;
		idx++;
		ileft=ilen-idx;
		if(ileft<=ilocal_len)
			goto illegal;
		
		// copy these data into name buffer
		for(ilocal_idx=0;ilocal_idx<ilocal_len;ilocal_idx++){
			if(*name_len==MAX_DOMAIN_NAME_LENGTH)
				break;
			name[*name_len]=str[idx+ilocal_idx];
			(*name_len)++;
		}
		//add a dot  after the name segment
		if(*name_len==MAX_DOMAIN_NAME_LENGTH)
			break;
		name[*name_len]='.';
		(*name_len)++;
		idx+=ilocal_len;
		if(idx==ilen)
			goto illegal;
	}while(1);
	if(*name_len>0){
		name[*name_len-1]='\0';
		(*name_len)--;
	}
	return 0;

	illegal:
		return -1;
}

/**
*DNS protocol data unit format check,
*if check past,we will deliver it to worker ,maybe for now we only check part of the entire dns payload
* we preserve this interface to meet some requirments if needed later
*/
int dns_format_check(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context* context)
{//here we are sure this destined port-53 packet is DNS query and source port-53 packets is a DNS response packet,so we do some format checking
	struct dns_common_hdr*dch=NULL;
	int rc;
	if(context->next_action!=block_action_next_block)//this ensure this packet may be normal  packets belonging to DNS traffic class
		return -1;
	dch=(struct dns_common_hdr*) context->payload;
	void * pkt_start=rte_pktmbuf_mtod(mbuf,void*);
	int hdr_length=(char*)dch-(char*)pkt_start;
	int pkt_length=rte_pktmbuf_data_len(mbuf);
	int payload_length=pkt_length-hdr_length;


	/*payload length check*/
	if(payload_length<(int)sizeof(struct dns_common_hdr))//exact 12 bytes
		goto illegal;
	if(payload_length>512)
		goto illegal;
	
	if(((dch->lefty_byte)&0x80)==0){//DNS query packet
		/*make surce transport layer ports is correct*/
		if(context->udpp->dst_port!=HTONS(53))
			goto illegal;
		if(dch->nb_query!=HTONS(1))
			goto illegal;
		if(dch->nb_rr||dch->nb_authority||dch->nb_extra)
			goto illegal;
		rc=resolve_domain_name((char*)(sizeof(struct dns_common_hdr)+(char*)dch),payload_length-sizeof(struct dns_common_hdr),context->domain_name,&context->dn_length);
		if(rc)
			goto illegal;
		//fullfil dispatch key buffer
		memcpy(context->dis_key,&context->ipp->src_addr,sizeof(uint32_t));//here the word remains big endian
		memcpy(context->dis_key+4,&context->udpp->src_port,sizeof(uint16_t));
		memcpy(context->dis_key+6,&dch->id,sizeof(uint16_t));
		context->key_len=8;
		
	}else{
		if(context->udpp->src_port!=HTONS(53))
			goto illegal;
		if(dch->nb_query!=HTONS(1))
			goto illegal;
		rc=resolve_domain_name((char*)(sizeof(struct dns_common_hdr)+(char*)dch),payload_length-sizeof(struct dns_common_hdr),context->domain_name,&context->dn_length);
		if(rc)
			goto illegal;
		memcpy(context->dis_key,&context->ipp->dst_addr,sizeof(uint32_t));//here the word remains big endian
		memcpy(context->dis_key+4,&context->udpp->dst_port,sizeof(uint16_t));
		memcpy(context->dis_key+6,&dch->id,sizeof(uint16_t));
		context->key_len=8;
	}
	context->next_action=block_action_next_block;//which means this packet is legal  DNS query packet
	//printf("got correct DNS\n");
	return 0;

illegal://illegal DNS 53 destined packet,take drop or redirection action
	context->next_action=block_action_drop;
	return -1;
}
int dns_rx_action(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context* context)
{
	int rc;
	struct packet_parameter *pp;
	unsigned char * lptr;
	uint32_t dis_idx;
	struct lcore_conf_item *lci;
	int input_port=mbuf->pkt.in_port;
	int dst_port;
	action_start:
		switch(context->next_action)
		{
			case block_action_next_block:
				
				lptr=(unsigned char*)rte_pktmbuf_append(mbuf,(int)sizeof(struct packet_parameter)+context->dn_length);
				

				if(!lptr){//since DNS packet has a maximum length of 512 bytes,this case may never happen
					context->next_action=block_action_forward;
					goto action_start;
				}
				pp=(struct packet_parameter*)(lptr+context->dn_length);
				pp->dn_length=context->dn_length;
				pp->ip_offset= ((char*)context->ipp)-((char*)context->eh);
				pp->udp_offset=((char*)context->udpp)-((char*)context->eh);
				pp->payload_offset=((char*)context->payload)-((char*)context->eh);
				memcpy(lptr,context->domain_name,context->dn_length);
				//their should be a dispatcher between RX and Sched lcores ,
				//and for the same DNS request ,the QUERY and RESPONSE packet will be diretced to the same lcores
				dis_idx=calculate_dispatch_index(context->dis_key,context->key_len);
				dis_idx%=sched_lci_nb;
				
				lci=sched_lcore_array[dis_idx];
				rc=rte_ring_mp_enqueue(lci->ring,mbuf);
				
				if(rc==-ENOBUFS){
					rte_pktmbuf_free(mbuf);

				}
				
				break;
			case block_action_forward:
				/*even we use source mac or(and) dst mac address as dispatch key,it's not sufficient since mac address is L2 feature which means the traffic scope may be limited
				*so we use IP address load balancing at first,and if the packet is not an IP we use L2 address instead
				*/
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
				dst_port=port_mapping[input_port];
				dis_idx%=tx_lci_nb[dst_port];

				lci=tx_lcore_array[dst_port][dis_idx];
				rc=rte_ring_mp_enqueue(lci->ring,mbuf);
				if(rc==-ENOBUFS)
					rte_pktmbuf_free(mbuf);
				break;
			case block_action_redirect:
			case block_action_drop:
				rte_pktmbuf_free(mbuf);
				break;
			default:
				break;
		}
	return 0;
}
