#include "dns_main.h"


int gnb_ports;
int gnb_lcores;

struct mbuf_conf_item gmca[]={
	{
		.id=0,
		.socket_id=LCORE_ID_ANY,
		.nb_mbuf=1024*8,
		.mbuf_size=(2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM),
	},
	{
		.id=1,
		.socket_id=LCORE_ID_ANY,
		.nb_mbuf=1024*8,
		.mbuf_size=(2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM),
	},

};
const int gmca_size=sizeof(gmca)/sizeof(struct mbuf_conf_item);
struct port_conf_item gpca[MAX_PORTS_NB];

struct lcore_conf_item glca[]=
{
	{
		.lcore_id=0,
		.lcore_role=LCORE_ROLE_RX,
	},
	{
		.lcore_id=1,
		.lcore_role=LCORE_ROLE_SCHED,
	},
	{
		.lcore_id=2,
		.lcore_role=LCORE_ROLE_SCHED,
	},
	{
		.lcore_id=3,
		.lcore_role=LCORE_ROLE_TX,
	}
	
};
const int glca_size=sizeof(glca)/sizeof(struct lcore_conf_item);

static const struct rte_eth_conf port_conf = {//port conf struct,,imported from l2fwd main.c
	.link_speed=ETH_LINK_SPEED_AUTONEG,
	.link_duplex=ETH_LINK_AUTONEG_DUPLEX,
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};
static  __dbg uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static  __dbg uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg.,imported from l2fwd */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. ,imported from l2fwd*/
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg.,imported from l2fwd */
struct rte_eth_rxconf rx_conf={//imported from l2fwd
.rx_thresh={
	.pthresh=RX_PTHRESH,
	.hthresh=RX_HTHRESH,
	.wthresh=RX_WTHRESH,
},
};
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg.,imported from l2fwd*/
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg.,imported from l2fwd */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg.,imported from l2fwd */
static const struct rte_eth_txconf tx_conf = {//imported from l2fwd
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
	.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};

/*lcore schedule variables*/
struct lcore_conf_item * sched_lcore_array[MAX_LCORE_NB];
int sched_lci_nb=0;

struct lcore_conf_item * tx_lcore_array[MAX_PORTS_NB][MAX_LCORE_NB];
int tx_lci_nb[MAX_PORTS_NB];

int port_mapping[MAX_PORTS_NB]={1/*0->1*/,0/*1->0*/,3/*2->3*/,2/*3->2*/};

struct dns_server_item dns_server[]=/*at least one element present*/
{
	{
		.ip_addr=HTONL(0x12345678),
		.mac={0x1,0x2,0x3,0x4,0x5,0x6},
		.target_port=-1,
	},
	{
		.ip_addr=0x12345678,
		.mac={0x6,0x5,0x4,0x3,0x2,0x1},
		.target_port=-1,
	}
};
int dns_server_nb=sizeof(dns_server)/sizeof(struct dns_server_item);

uint64_t  system_hz;
int main(__dbg int argc, __dbg char**argv)
{
	int ret;
	int idx;
	int idx_buff;
	int lcore_id;
	__dbg int idx_tmp=0;

	/*eal initialization*/

	////////////////////////////
	
	////////////////////////////
	ret = rte_eal_init(argc, argv);
	if(ret<0)
		goto rte_error;
	
	ret=rte_pmd_init_all();
	if(ret<0)
		goto rte_error;
	ret=rte_eal_pci_probe();
	if(ret<0)
		goto rte_error;
	gnb_ports=rte_eth_dev_count();
	gnb_lcores=rte_lcore_count();
	printf(">>>there are %d ports and %d lcores detected\n",gnb_ports,gnb_lcores);

	system_hz=rte_get_tsc_hz();

	/*mempool initialization*/
	for(idx=0;idx<gmca_size;idx++){
		char name[64];
		memset(name,0x0,sizeof(name));
		sprintf(name,"port_mempool_%d",gmca[idx].id);
		gmca[idx].mempool=rte_mempool_create(name,gmca[idx].nb_mbuf,gmca[idx].mbuf_size,32,sizeof(struct rte_pktmbuf_pool_private),rte_pktmbuf_pool_init,NULL,rte_pktmbuf_init,NULL,gmca[idx].socket_id,0);
		printf(">>>%s creation on socket %d %s \n",name,gmca[idx].socket_id,!!gmca[idx].mempool?"succeeds":"fails");
	}
	/*get port dev information*/
	int ports_list[MAX_PORTS_NB];
	int ports_rx_q[MAX_PORTS_NB];
	int ports_tx_q[MAX_PORTS_NB];
	int ports_idx=0;
	for(idx=0;idx<gnb_ports;idx++)
	{
		gpca[idx].id=idx;
		gpca[idx].is_enabled=TRUE;//assume all ports are enabled
		rte_eth_dev_info_get(gpca[idx].id,&gpca[idx].port_info);
		printf(">>>port[%s] %d  has %d rx queues and %d tx queues\n",
			gpca[idx].is_enabled?"enabled":"disabled",
			gpca[idx].id,
			gpca[idx].port_info.max_rx_queues,
			gpca[idx].port_info.max_tx_queues);
		if(gpca[idx].is_enabled){
			ports_list[ports_idx]=idx;
			ports_rx_q[ports_idx]=gpca[idx].port_info.max_rx_queues;
			ports_tx_q[ports_idx]=gpca[idx].port_info.max_tx_queues;
			ports_idx++;
		}
	}
	/*assign lcore RX and TX  resource to ports */
	int irx_ptr=0;
	int irx_last_ptr=0;
	int iptr=0;
	for(idx=0;idx<ports_idx;idx++)
		for(idx_buff=0;idx_buff<ports_rx_q[idx];idx_buff++){//find a RX roled lcore to setup this port-queue 
			do{//make sure that we need at least one LCORE_ROLE_RX lcore configured in glca global data structure
				irx_last_ptr=irx_ptr;
				if(glca[irx_ptr].lcore_role==LCORE_ROLE_RX){
					iptr=irx_ptr;
					irx_ptr=(irx_ptr+1)%glca_size;
					break;
				}
				irx_ptr=(irx_ptr+1)%glca_size;
			}while(irx_ptr!=irx_last_ptr);
			printf(">>>assign lcore %d RX  port %d on queue %d\n",iptr,idx,idx_buff);
			glca[iptr].port_list[glca[iptr].port_nb]=idx;
			glca[iptr].queue_list[glca[iptr].port_nb]=idx_buff;
			glca[iptr].port_nb++;
		}
	int itx_ptr=0;
	int itx_last_ptr=0;
	for(idx=0;idx<ports_idx;idx++)
		for(idx_buff=0;idx_buff<ports_tx_q[idx];idx_buff++){//find a TX roled lcore to setup this port-queue 
			do{//make sure that we need at least one LCORE_ROLE_TX lcore configured in glca global data structure
				itx_last_ptr=itx_ptr;
				if(glca[itx_ptr].lcore_role==LCORE_ROLE_TX){
					iptr=itx_ptr;
					itx_ptr=(itx_ptr+1)%glca_size;
					break;
				}
				itx_ptr=(itx_ptr+1)%glca_size;
			}while(itx_ptr!=itx_last_ptr);
			printf(">>>assign lcore %d TX  port %d on queue %d\n",iptr,idx,idx_buff);
			glca[iptr].port_list[glca[iptr].port_nb]=idx;
			glca[iptr].queue_list[glca[iptr].port_nb]=idx_buff;
			glca[iptr].port_nb++;
		}
	/*configure ports*/
	for(idx=0;idx<gnb_ports;idx++){
		if(gpca[idx].is_enabled==FALSE)
			continue;
		ret=rte_eth_dev_configure(gpca[idx].id,gpca[idx].port_info.max_rx_queues,gpca[idx].port_info.max_tx_queues,&port_conf);
		printf(">>>configure port %d %s\n",gpca[idx].id,ret<0?"fails":"succeeds");
	}
	/*configure queues of ports*/
	struct rte_mempool *mempool;
	for(idx=0;idx<glca_size;idx++){
		if(glca[idx].lcore_role!=LCORE_ROLE_RX)
			continue;
		
		for(idx_buff=0;idx_buff<glca[idx].port_nb;idx_buff++){
			mempool=find_sutiable_mempool(gmca,gmca_size,rte_lcore_to_socket_id(glca[idx].lcore_id));
			if(!mempool){
				printf(">>>can not find suitable mempool for lcore %d\n",glca[idx].lcore_id);
				exit(0);
			}
			
			ret=rte_eth_rx_queue_setup(glca[idx].port_list[idx_buff],
				glca[idx].queue_list[idx_buff],
				nb_rxd,
				rte_lcore_to_socket_id(glca[idx].lcore_id),
				&rx_conf,mempool);
			printf(">>>configure RX queue %d of port %d on lcore %d %s\n",glca[idx].queue_list[idx_buff],
				glca[idx].port_list[idx_buff],
				glca[idx].lcore_id,
				ret<0?"fails":"succeeds");
		}
	}
	for(idx=0;idx<glca_size;idx++){
		if(glca[idx].lcore_role!=LCORE_ROLE_TX)
			continue;
		for(idx_buff=0;idx_buff<glca[idx].port_nb;idx_buff++){
			ret=rte_eth_tx_queue_setup(glca[idx].port_list[idx_buff],
				glca[idx].queue_list[idx_buff],
				nb_txd,
				rte_lcore_to_socket_id(glca[idx].lcore_id),
				&tx_conf);
			printf(">>>configure TX queue %d of port %d on lcore %d %s\n",glca[idx].queue_list[idx_buff],
				glca[idx].port_list[idx_buff],
				glca[idx].lcore_id,
				ret<0?"fails":"succeeds");
			
		}
	}
	/*start up ports*/
	for(idx=0;idx<gnb_ports;idx++)
		if(gpca[idx].is_enabled==TRUE){
			rte_eth_dev_start(gpca[idx].id);
			rte_eth_promiscuous_enable(gpca[idx].id);
		}

	/*setup rings for scheduler and tx worker*/
	char name[64];
	for(idx=0;idx<glca_size;idx++){
		switch(glca[idx].lcore_role)
		{
			case LCORE_ROLE_SCHED:
				sprintf(name,"ring_%d",glca[idx].lcore_id);
				glca[idx].ring=rte_ring_create(name,DEFAULT_SCHED_RING_SIZE,rte_lcore_to_socket_id(glca[idx].lcore_id),RING_F_SC_DEQ);
				printf(">>>craete ring %s on lcore %d %s\n",name,glca[idx].lcore_id,glca[idx].ring?"succeeds":"fails");
				break;
			case LCORE_ROLE_TX:
				sprintf(name,"ring_%d",glca[idx].lcore_id);
				glca[idx].ring=rte_ring_create(name,DEFAULT_TX_RING_SIZE,rte_lcore_to_socket_id(glca[idx].lcore_id),RING_F_SC_DEQ);
				printf(">>>craete ring %s on lcore %d %s\n",name,glca[idx].lcore_id,glca[idx].ring?"succeeds":"fails");
				break;
			default:
				break;
		}
	}
	/*generate lcore variables,and ease to lookup in dispatching phaze*/
	for(idx=0;idx<glca_size;idx++)
		if(glca[idx].lcore_role==LCORE_ROLE_SCHED)
			sched_lcore_array[sched_lci_nb++]=&glca[idx];

	for(idx=0;idx<MAX_PORTS_NB;idx++)
		tx_lci_nb[idx]=0;
	
	for(idx=0;idx<glca_size;idx++)
	{
		if(glca[idx].lcore_role!=LCORE_ROLE_TX)
			continue;
		for(idx_buff=0;idx_buff<glca[idx].port_nb;idx_buff++){
			
			struct lcore_conf_item *lci_buff=&glca[idx];
			int port_tmp=lci_buff->port_list[idx_buff];
			
			for(idx_tmp=0;idx_tmp<tx_lci_nb[port_tmp];idx_tmp++)
				if(tx_lcore_array[port_tmp][idx_tmp]==lci_buff)
					break;
			if(idx_tmp<tx_lci_nb[port_tmp])
				continue;
			tx_lcore_array[port_tmp][idx_tmp]=lci_buff;
			tx_lci_nb[port_tmp]++;
		}
	}
 
	#if 0

	for(idx=0;idx<MAX_PORTS_NB;idx++){
		printf("ports %d, lcore nb %d :",idx,tx_lci_nb[idx]);
		for(idx_tmp=0;idx_tmp<tx_lci_nb[idx];idx_tmp++)
			printf("%d,",tx_lcore_array[idx][idx_tmp]->lcore_id);
		puts("");
	}

	#endif
	
	/*spawn lcore thread*/
	for(idx=0;idx<glca_size;idx++){
		switch(glca[idx].lcore_role)
		{
			case LCORE_ROLE_RX:
				glca[idx].entry=dns_rx_lcore_entry;
				break;
			case LCORE_ROLE_SCHED:
				glca[idx].entry=dns_sched_lcore_entry;
				break;
			case LCORE_ROLE_TX:
				glca[idx].entry=dns_tx_lcore_entry;
				break;
			default:
				break;
		}
	}

	for(idx=0;idx<glca_size;idx++){
		if(glca[idx].lcore_id==0)
			continue;
		ret=rte_eal_remote_launch(glca[idx].entry,&glca[idx],glca[idx].lcore_id);	
	}
	for(idx=0;idx<glca_size;idx++){
		if(glca[idx].lcore_id==0){
			glca[idx].entry((void*)&glca[idx]);
			break;
		}
	}
	/*wait for lcores joining*/
	RTE_LCORE_FOREACH_SLAVE(lcore_id){
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
	return 0;
	rte_error:
		printf(">>>init error\n");
		return -1;
	
}
int dns_rx_lcore_entry(__dbg void*arg)
{
	struct lcore_conf_item *lci=(struct lcore_conf_item*)arg;
	struct rte_mbuf * rx_mbuf[MAX_BURST_RX_SIZE];
	__dbg int lcore_id=rte_lcore_id();
	int nb_mbuf=0;
	int port_idx;
	int portid;
	int queueid;
	int pkt_idx;
	struct mbuf_user_context context;
	
	while(TRUE)
	{
		for(port_idx=0;port_idx<lci->port_nb;port_idx++){
			portid=lci->port_list[port_idx];
			queueid=lci->queue_list[port_idx];
			
			nb_mbuf=rte_eth_rx_burst(portid,queueid,rx_mbuf,MAX_BURST_RX_SIZE);
			if(!nb_mbuf)
				continue;
			
			for(pkt_idx=0;pkt_idx<nb_mbuf;pkt_idx++){
				rte_prefetch0(rte_pktmbuf_mtod(rx_mbuf[pkt_idx],void*));
				/*the following block MUST be in such order*/
				reset_user_conext(&context);
				dns_tunel_decapsulate(rx_mbuf[pkt_idx],&context);
				dns_l2_decap(rx_mbuf[pkt_idx],&context);
				dns_l3_decap(rx_mbuf[pkt_idx],&context);
				dns_l4_decap(rx_mbuf[pkt_idx],&context);
				dns_format_check(rx_mbuf[pkt_idx],&context);
				dns_rx_action(rx_mbuf[pkt_idx],&context);
				
			}
		}
	}
	return 0;
}

#define DEQUEUE_BURST_SIZE  32
#define TX_BURST_SIZE 48

/**
*the burst-xmit function, 
* but here we try to load all the packets  uniformally into queues of a destined ports if multiple xmit queues exist 
*/
int dns_burst_forward(int portid,int * queueid_list,int queue_nb,struct rte_mbuf ** mbufs,int mbuf_len)
{

	int start=0;
	int base;
	int mod;
	int real_tx_nb[MAX_QUEUE_NB];
	int idx;
	int ret;
	if(queue_nb==0){/*falsified packets port-destined where  this lcore do not xmit the port on any queues */
		
		for(idx=0;idx<mbuf_len;idx++)
			rte_pktmbuf_free(mbufs[idx]);
		return -1;
	}
	int idx_tmp;
	base=(int)mbuf_len/(int)queue_nb;
	for(idx=0;idx<queue_nb;idx++)
		real_tx_nb[idx]=base;
	
	mod=mbuf_len%queue_nb;
	for(idx=0;idx<mod;idx++)
		real_tx_nb[idx]++;

	for(idx=0,start=0;idx<queue_nb;idx++){
		if(real_tx_nb[idx]==0)
			break;
		//burst tx routine called
		ret=rte_eth_tx_burst(portid,queueid_list[idx],mbufs+start,real_tx_nb[idx]);
		
		for(idx_tmp=ret;idx_tmp<real_tx_nb[idx];idx_tmp++)//free packets that are not enqueued into dev's xmit ring
			rte_pktmbuf_free(*(mbufs+start+idx_tmp));

		start+=real_tx_nb[idx];
	}
	
	return 0;
}

int dns_tx_lcore_entry(__dbg void*arg)
{
	struct lcore_conf_item *lci=(struct lcore_conf_item*)arg;
	int tx_port_queue_arr[MAX_PORTS_NB][MAX_QUEUE_NB];
	int tx_port_queue_nb[MAX_PORTS_NB];
	int idx=0,idx_buff;
	int input_port,dst_port;
	int pkt_idx;
	int portid;
	int queueid;
	struct rte_mbuf *mbuf;
	/*collect the unique to ease indexing*/
	int uniq_ports[MAX_PORTS_NB];
	int uniq_ports_nb=0;

	for(idx=0;idx<lci->port_nb;idx++){
		idx_buff=0;
		for(;idx_buff<uniq_ports_nb;idx_buff++)
			if(uniq_ports[idx_buff]==lci->port_list[idx])
				break;
		if(idx_buff==uniq_ports_nb){
			uniq_ports[uniq_ports_nb]=lci->port_list[idx];
			uniq_ports_nb++;
		}
	}

	uint64_t prev_tsc=0, diff_tsc=0, cur_tsc=0;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	memset(tx_port_queue_arr,0x0,sizeof(tx_port_queue_arr));
	memset(tx_port_queue_nb,0x0,sizeof(tx_port_queue_nb));
	//collect the queue info for every ports
	for(idx=0;idx<lci->port_nb;idx++){
		portid=lci->port_list[idx];
		queueid=lci->queue_list[idx];
		tx_port_queue_arr[portid][tx_port_queue_nb[portid]]=queueid;
		tx_port_queue_nb[portid]++;
	}
	struct rte_mbuf *tx_ports_mbuf[MAX_PORTS_NB][TX_BURST_SIZE];
	int tx_ports_nb[MAX_PORTS_NB];
	memset(tx_ports_mbuf,0x0,sizeof(tx_ports_mbuf));
	memset(tx_ports_nb,0x0,sizeof(tx_ports_nb));
	
	struct rte_mbuf * tx_mbuf[DEQUEUE_BURST_SIZE];
	int tx_mbuf_nb;
	
	while(TRUE)
	{
		/*try to get  the quantity of mbufs the same  as DEQUEUE_BURST_SIZE */
		tx_mbuf_nb=rte_ring_sc_dequeue_burst(lci->ring,(void**)tx_mbuf,DEQUEUE_BURST_SIZE);
		for(pkt_idx=0;pkt_idx<tx_mbuf_nb;pkt_idx++){
			mbuf=tx_mbuf[pkt_idx];
			input_port=mbuf->pkt.in_port;
			dst_port =port_mapping[input_port];

			tx_ports_mbuf[dst_port][tx_ports_nb[dst_port]]=mbuf;
			tx_ports_nb[dst_port]++;
			/*if buffer overflows here,we flush the packets already buffered in Local Buffer */
			if(tx_ports_nb[dst_port]==TX_BURST_SIZE){//immediately flush tx ports buffer in TX lcores
				dns_burst_forward(dst_port,tx_port_queue_arr[dst_port],tx_port_queue_nb[dst_port],tx_ports_mbuf[dst_port],tx_ports_nb[dst_port]);
				tx_ports_nb[dst_port]=0;//reset buffer object counter
			}
		}
		cur_tsc=rte_rdtsc();
		diff_tsc=cur_tsc-prev_tsc;
		if(diff_tsc>drain_tsc){//drain tx ports buffer if the timer expires
			for(idx=0;idx<uniq_ports_nb;idx++){
				portid=uniq_ports[idx];
				if(!tx_ports_nb[portid])
					continue;
				dns_burst_forward(portid,tx_port_queue_arr[portid],tx_port_queue_nb[portid],tx_ports_mbuf[portid],tx_ports_nb[portid]);
				tx_ports_nb[portid]=0;
			}
			prev_tsc=cur_tsc;
		}
	}
	return 0;
}


/*
*dummy mempool initialzation function
*/
void dns_private_mempool_init(__dbg struct rte_mempool*mempool,__dbg void*arg)
{
	
}
void dns_private_obj_init(__dbg struct rte_mempool *mempool,__dbg void*arg,__dbg void*obj,__dbg unsigned int flag)
{
	memset(obj,0x0,sizeof(struct dns_hash_node));
	
}

int dns_sched_lcore_entry(__dbg void*arg)
{
	struct lcore_conf_item*lci=(struct lcore_conf_item*)arg;
	struct rte_mbuf * sched_mbuf[DEQUEUE_BURST_SIZE];
	int sched_mbuf_nb=0;
	__dbg int pkt_idx,idx;
	struct rte_mbuf *mbuf;
	struct mbuf_user_context context;
	__dbg int lcore_id=rte_lcore_id();
	__dbg int socket_id=rte_lcore_to_socket_id(lcore_id);
	#if 1
	char mempool_name[64];
	
	/*mempool setup*/
	
	sprintf(mempool_name,"sched_local_mem_%d",lcore_id);
	struct rte_mempool *mempool;
	mempool=rte_mempool_create(mempool_name,SCHED_MEMPOOL_NB,sizeof(struct dns_hash_node),32,sizeof(uint32_t),dns_private_mempool_init,NULL,dns_private_obj_init,NULL,socket_id,MEMPOOL_F_SP_PUT|MEMPOOL_F_SC_GET);
	if(!mempool){
		printf(">>>create mempool %s fails\n",mempool_name);
		return -1;
	}
	/*hash table setup*/
	 struct dns_hash_node* *hash_tbl=rte_zmalloc(NULL,SCHED_HASH_SIZE*(int)sizeof(struct dns_hash_node*),0);
	if(!hash_tbl){
		printf(">>>create hash table for lcore %d fails\n",lcore_id);
		return 0;
	}
	#endif
	while(TRUE)
	{
		sched_mbuf_nb=rte_ring_sc_dequeue_burst(lci->ring,(void**)sched_mbuf,DEQUEUE_BURST_SIZE);
		if(!sched_mbuf_nb)
			continue;
			for(pkt_idx=0;pkt_idx<sched_mbuf_nb;pkt_idx++){
				mbuf=sched_mbuf[pkt_idx];
				reset_user_conext(&context);
				dns_nat_extract_context(mbuf,&context);
				
				/*
				*here we preserve  some interfaces in case future extension is needed
				*/
				dns_hash_index(mempool,hash_tbl,mbuf,&context);
				dns_nat_translate_addr(mbuf,&context);
				dns_nat_action(mbuf,&context);
				
			}
	}

	return 0;
}


