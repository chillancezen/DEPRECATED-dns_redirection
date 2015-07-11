#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
	 
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_atomic.h>
#include "dns_config.h"

#include "rte_ether.h"
#include "rte_ip.h"
#include "rte_udp.h"
//#include "jhash.h"

#define TRUE 1
#define FALSE 0
#define BURST_TX_DRAIN_US 100
#define MAX_BURST_RX_SIZE 32 
#define MAX_QUEUE_NB 32
#define MAX_PORTS_NB 64
#define MAX_LCORE_NB 64
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

#define DEFAULT_SCHED_RING_SIZE 1024
#define DEFAULT_TX_RING_SIZE 1024

#define HTONS(a) ((((a)>>8)&0xff)|(((a)<<8)&0xff00))
#define HTONL(a)  ((((a)>>24)&0xff)|(((a)>>8)&0xff00)|(((a)<<8)&0xff0000)|(((a)<<24)&0xff000000))


#define __dbg  __attribute__((unused))

struct mbuf_conf_item{
	int id;
	int socket_id;
	int nb_mbuf;
	int mbuf_size;
	struct rte_mempool*mempool;
	int ref_cnt;
};
struct port_conf_item{
	int id;
	int is_enabled;
	struct rte_eth_dev_info port_info;
};
enum lcore_role{
	LCORE_ROLE_UNSPEC,
	LCORE_ROLE_RX,
	LCORE_ROLE_TX,
	LCORE_ROLE_SCHED,
	LCORE_ROLE_MAX_ITEM
};

struct lcore_conf_item{
	int   lcore_id;
	enum lcore_role lcore_role;
	int port_list[MAX_PORTS_NB];
	int queue_list[MAX_PORTS_NB];
	int port_nb;
	struct rte_ring * ring;
	int (*entry)(void*);
};
enum block_action
{
	block_action_unspec=0,
	block_action_forward,
	block_action_drop,
	block_action_redirect,
	block_action_next_block,
	
};
#define MAX_DOMAIN_NAME_LENGTH 256
#define IP_UDP_FIELD 0x11

struct dns_common_hdr{
	uint16_t id;
	union {
	uint16_t flag;
	struct {//this is how memory bytes maps
		uint8_t lefty_byte;
		uint8_t righty_byte;
	};
	};
	uint16_t nb_query;
	uint16_t nb_rr;
	uint16_t nb_authority;
	uint16_t nb_extra;
}__attribute__((packed));
#define MAX_DISPATCH_KEY 64
#define MAX_HASH_KEY_SIZE 32

struct dns_hash_node{
	uint64_t last_tsc;//used to keep track with these old items
	uint32_t signature;
	int hash_key_len;
	uint32_t original_ip;
	uint8_t original_mac[6];
	struct dns_hash_node* next;
	struct dns_hash_node* prev;
	uint8_t hash_key[MAX_HASH_KEY_SIZE];
};
enum dns_packet_type{
	dns_packet_type_unspec,
	dns_packet_type_query,
	dns_packet_type_response,
};
struct mbuf_user_context
{//in host's order
	int is_encap;
	int encap_len;
	struct ether_hdr * eh;
	struct ipv4_hdr *ipp;
	struct udp_hdr *udpp;
	struct dns_common_hdr *dnsp;
	enum dns_packet_type packet_type;
	
	uint16_t l2_upper_proto;
	uint8_t l3_upper_proto;
	void* payload;
	
	int dn_length;
	enum block_action next_action;

	/*dispatch key part*/
	int key_len;
	#if 1
	struct dns_hash_node *hash_real_node;
	struct dns_hash_node hash_node;
	uint32_t hash_index;
	#endif
	int dummy;//dummy flag,
	uint8_t dis_key[MAX_DISPATCH_KEY];
	char domain_name[MAX_DOMAIN_NAME_LENGTH];
};

struct packet_parameter{
	uint8_t dn_length;//total length:header length plus domain name length
	uint8_t ip_offset;
	uint8_t udp_offset;
	uint8_t payload_offset;
}__attribute__((packed));

#define USE_SERVER_LOAD_BALANCE 0

struct dns_server_item{//big endian 
	uint32_t ip_addr;
	uint8_t mac[6];
	uint8_t target_port;//0xff indicate the default port mapping
};
#define SCHED_MEMPOOL_NB  (1024*32)
#define SCHED_HASH_SIZE (1024*1024)
#define SCHED_HASH_MASK (SCHED_HASH_SIZE-1)
#define DNS_ENTRY_CLEAR_TIME 5  /*5s is resonable*/

struct rte_mempool* find_sutiable_mempool(struct mbuf_conf_item*arr,int isize,int socket_id);
int  reset_user_conext(struct mbuf_user_context*context);
int resolve_domain_name( const char *str,int ilen,char* name,int* name_len);;

int dns_rx_lcore_entry(void*arg);
int dns_burst_forward(int portid,int * queueid_list,int queue_nb,struct rte_mbuf ** mbufs,int mbuf_len);

int dns_tx_lcore_entry(void*arg);
int dns_sched_lcore_entry(void*arg);
int dns_tunel_decapsulate(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context *context);



int dns_l2_decap(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context*context);
int dns_l3_decap(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context*context);
int dns_l4_decap(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context*context);
int dns_format_check(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context* context);
int dns_rx_action(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context* context);

uint32_t calculate_dispatch_index(__dbg unsigned char * key,__dbg int ilength);
uint32_t jhash(void*  key, uint32_t length, uint32_t initval);

int dns_nat_extract_context(struct rte_mbuf*mbuf,struct mbuf_user_context*context);

void dns_private_mempool_init(__dbg struct rte_mempool*mempool,__dbg void*arg);
void dns_private_obj_init(__dbg struct rte_mempool *mempool,__dbg void*arg,__dbg void*obj,__dbg unsigned int flag);

int is_hash_nodes_equal(struct dns_hash_node*node1,struct dns_hash_node*node2);
uint32_t calculate_signature(uint8_t * key,int length);
uint32_t calculate_hash(uint8_t *key,int length);
int dns_nat_translate_addr(__dbg struct rte_mbuf*mbuf,__dbg struct mbuf_user_context*context);
int dns_hash_index(struct rte_mempool *mempool,struct dns_hash_node**hash_tbl,struct rte_mbuf*mbuf,struct mbuf_user_context*context);
int  dns_nat_action(struct rte_mbuf*mbuf,struct mbuf_user_context*context);

int dns_private_recollect_mempool_obj(struct rte_mempool *mempool,struct dns_hash_node **hash_tbl,int hash_idx,struct dns_hash_node* dhn);
struct dns_hash_node * dns_private_insert_mempool_obj(struct rte_mempool * mempool,struct dns_hash_node**  hash_tbl,int hash_idx,struct dns_hash_node*dhn);


int copy_hash_node(struct dns_hash_node* dst_node, const struct dns_hash_node*src_node);

uint16_t wrap_csum(uint16_t oldsum,uint16_t oldval,uint16_t newval);




