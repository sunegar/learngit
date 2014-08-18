
/*!
	\file   udr_xel_route.c
	\brief  
		Function list

		int udr_l3_tnl_destroy (int unit, int index);
		int udr_l3_tnl_intf_set (int unit, int index, uint8_t family);
		int udr_l3_tnl_param_family_set (int unit, int tnl_index, uint32_t family);
		int udr_l3_tnl_param_type_set (int unit, int tnl_index, uint32_t type);
		int udr_modid_to_slot_get (int unit, int modid, int remote, int *slot);
		int udr_route_6rd_braddr_set (int unit, uint32_t addr, int index);
		int udr_route_6rd_domain_addr_set (int unit, uint8_t * addr, int index);
		int udr_route_6rd_ip4prex_set (int unit, int prex_len, int index);
		int udr_route_6rd_ip6prex_set (int unit, int prex_len, int index);
		int udr_route_close (int unit);
		int udr_route_count_info_get (int unit, _route_info_t *info);
		int udr_route_get_cmic (int unit);
		int udr_route_get_defip_feature (int unit);
		int udr_route_get_system_mac (int unit, unsigned char *MacAddr);
		int udr_route_info_get (int unit, _udr_basic_info_t * info);
		int udr_route_init_post (int unit);
		int udr_route_init_pre (int unit);
		int udr_route_ipv4_ecmp_route_set (int unit, unsigned int ip_addr, unsigned int ip_mask, int in_port, uint8_t *pmac_addr, int vlan_id, uint8_t *pnext_hop_mac, int modid, int api_flag, int vrf_id, int action);
		int udr_route_ipv4_host_hit_get (int unit, unsigned int ip_addr, int vrf_id, int * hit);
		int udr_route_ipv4_host_hit_set (int unit, unsigned int ip_addr, int vrf_id);
		int udr_route_ipv4_host_set (int unit, unsigned int ip_addr, int in_port, uint8_t * pmac_addr, int vlan_id, uint8_t * pnext_hop_mac, int modid, int api_flag, int vrf_id, int action);
		int udr_route_ipv4_reverse_mcsu (int unit, UDR_IP_INFO_S * ip_info);
		int udr_route_ipv4_route_hit_get (int unit, unsigned int ip_addr, unsigned int ip_mask, int vrf_id, int * hit);
		int udr_route_ipv4_route_hit_set (int unit, unsigned int ip_addr, unsigned int ip_mask, int vrf_id);
		int udr_route_ipv4_route_set (int unit, unsigned int ip_addr, unsigned int ip_mask, int in_port, uint8_t *pmac_addr, int vlan_id, uint8_t *pnext_hop_mac, int modid, int api_flag, int vrf_id, int action);
		int udr_route_ipv6_ecmp_route_set (int unit, unsigned char* ipv6_addr, int ipv6_mask_len, int in_port, uint8_t* pmac_addr, int vlan_id, uint8_t* pnext_hop_mac, int modid, int api_flag, int vrf_id, int action);
		int udr_route_ipv6_host_hit_get (int unit, unsigned char * ip_addr, int vrf_id, int * hit);
		int udr_route_ipv6_host_hit_set (int unit, unsigned char * ip_addr, int vrf_id);
		int udr_route_ipv6_host_set (int unit, unsigned char* ipv6_addr, int in_port, uint8_t *pmac_addr, int vlan_id, uint8_t *pnext_hop_mac, int modid, int api_flag, int vrf_id, int action);
		int udr_route_ipv6_reverse_mcsu (int unit, UDR_IP_INFO_S * ip_info);
		int udr_route_ipv6_route_hit_get (int unit, unsigned char* ipv6_addr, int mask_length, int vrf_id, int* ipv6_hit);
		int udr_route_ipv6_route_hit_set (int unit, unsigned char* ipv6_addr, int mask_length, int vrf_id);
		int udr_route_ipv6_route_set (int unit, unsigned char* ipv6_addr, int ipv6_mask_len, int in_port, uint8_t* pmac_addr, int vlan_id, uint8_t* pnext_hop_mac, int modid, int api_flag, int vrf_id, int action);
		int udr_route_l3mtu_cpu_enable (int unit, int enable);
		int udr_route_module_handle (int unit, udr_route_data_t * entry, int action, int cmd);
		int udr_route_tnl_param_dst_set (int unit, int index, uint8_t *val);
		int udr_route_tnl_param_src_set (int unit, int index, uint8_t *val);
		int udr_route_urpf_en_set (int unit, int status);
		int udr_route_urpf_lpm_set (int unit, int port, int enable);
		int udr_route_urpf_mode_set (int unit, int port, int mode);
		int udr_route_vlan_mtu_set (int unit, int vlan, int mtu);
	\author Dispatch Maker
	\date   
*/

#include <udr_types.h>
#include <udr_common.h>
#include <common/xel/udr_xel_route.h>

#include "common/xel/pmcl.h"

#define errinit int r_rv = UDR_API_E_NONE, _err_line =-1;
#define assrt(c) if(!(c)){r_rv=UDR_API_E_INTERNAL;_err_line = __LINE__;goto err;}
#define gerr {_err_line = __LINE__;goto err;}
#define gerrv(r) {r_rv = (r);_err_line = __LINE__;goto err;}
#define gerrp(r, ...) {printf(__VA_ARGS__);r_rv = (r);_err_line = __LINE__;goto err;}
#define printhere() printf("HERE ! %s @ ( %s: %d)\n", __FUNCTION__, __FILE__, __LINE__)
#define errprnt {if(r_rv != UDR_API_E_NONE){if(_err_line != -1)printf("ERROR here (%s : line %d)! r_rv = %d\n", __FUNCTION__, _err_line, r_rv);else printf("ERROR unknown position! r_rv = %d\n", __FUNCTION__,  r_rv);}}

#if 0
#define udrstatic static
#else
#define udrstatic
#endif
/* route */
#define RT_DBG_ROUTE		0x00000001
#define RT_DBG_DASA		0x00000002
#define RT_DBG_NEXTHOP		0x00000004
#define RT_DBG_ECMP		0x00000008
#define RT_DBG_VP			0x00000010
#define RT_DBG_TNL			0x00000020
#define RT_DBG_REFTAB		0x00000100
#define RT_DBG_HW_WR		0x00010000
#define RT_DBG_HW_RD		0x00020000
#define RT_DBG_FRR          0x00040000
#define RT_DBG_DEFAULT (0)

#if 1
udrstatic uint32_t rt_dbg_flag = /*RT_DBG_DEFAULT*/0x20;
udrstatic int uspdebug_tnl=0;
#define rtdbgprint(lvl, ...) if((lvl) & rt_dbg_flag)printf(__VA_ARGS__)
#else
#define rtdbgprint(lvl, ...)
#endif

extern void * _xel_priv_ctl_hndl;

/*#undef PACKED
#define PACKED __attribute__((__packed__))*/

enum  tunnel_type
{
	 L3_NORMAL_FORWARD=0,
	 L3_MPLS_VPN =1,        
	 IP_TUNNEL=2   
};

struct table_dasa_resp_type
{
	uint16_t	valid : 1,
			tag_act : 2,
			rsv1 : 13;
	uint16_t	prio : 3,
			cfi  : 1,
			vid  : 12;
	uint8_t damac[6];
	uint8_t samac[6];
};

#if 0
struct ip_next_hop_resp 
{
	uint16_t	valid_bit:1,
			entry_type:3,
			mod_id:4,
			port_type:1,
			dest_id:7;
	uint16_t	l3_mac_index;
	uint16_t	l3_vpn_init_label_index_ipv4_tunnel_index;
};
#else
struct ip_next_hop_resp 
{
	uint16_t 	valid_bit:1,
			entry_type:3, /* 0:L3_NORMAL_FORWARD 1:L3_MPLS_VPN 2:IP_TUNNEL */
			rsv0:4,
			port_type:1,
			dest_id:7;
	uint16_t	l3_mac_index;
	uint16_t	l3_vpn_init_label_index_ipv4_tunnel_index;
	uint16_t	mod_id:7,
			cpu_flag:1,
			rsv1:8;
    uint8_t dst_ip[4];
};
#endif

struct ecmp_member_entry_type
{
	uint16_t    master_flag : 1,
                ecmp_next_hop_ref : 15;
};

struct ecmp_entry_type
{
	struct ecmp_member_entry_type entry[32];
};

struct mpls_label_type
{
	uint16_t 	label_high;
	uint16_t 	label_low : 4,
			exp : 3,
			bos : 1,
			ttl : 8;
};

struct table_vp_resp_type
{
	uint16_t 	valid : 1,
			out_type : 2,
			modid : 5,	
			port_type : 1,
			port_or_trunk_ID : 7;

	uint16_t 	dasa_index;

	uint16_t 	prio : 3,
			cfi  : 1,
			vid  : 12;

	uint16_t 	tag_act : 2,   
			ce_or_pe : 1,
			rsv2  : 13;

	struct mpls_label_type tunnel_label;
	struct mpls_label_type vc_label;
};


#define TNLTYP_FML6 4
enum tunnel_entry_type
{
	TNLTYP_IP6_IN_IP4_TUNNEL_PROCESS = 0, /*add ip4_header*/
	TNLTYP_IP4_GRE_HEADER_TUNNEL_PROCESS, /*add ip4_header*/
	TNLTYP_IP6_TO_IP4_TUNNEL_PROCESS, /*add ip4_header*/
	TNLTYP_ISATAP_TUNNEL_PROCESS,   /*add auto ip4_header*/
	TNLTYP_IP4_IN_IP6_TUNNEL_PROCESS = TNLTYP_FML6, /*add ip6_header*/
	TNLTYP_IP6_GRE_HEADER_TUNENL_PROCESS /*add ip6_header*/
};
#define TUNNEL_ENTRY_TYPE_USE_HDIP4(tp) (((tp) & TNLTYP_FML6) == 0)
#define TUNNEL_ENTRY_TYPE_USE_HDIP6(tp) ((tp) & TNLTYP_FML6)
#define TUNNEL_ENTRY_TYPE_SET_HDIP4(tp) ((tp) &= ~TNLTYP_FML6)
#define TUNNEL_ENTRY_TYPE_SET_HDIP6(tp) ((tp) |= TNLTYP_FML6)

#define TNL_TERM_4_ENGINE 1
#define TNL_TERM_4_TBL 2
#define TNL_TERM_4_SIZE 0x200
#define TNL_TERM_4_KEYBUF_SIZE 10
#define TNL_TERM_4_DATABUF_SIZE 4

struct  ip4_tunnel_decap_req_type
{
	uint32_t  src_ip;
	uint32_t  dst_ip;
};

struct ip4_tunnel_decap_resp_type 
{
	uint32_t match;
};

#define TNL_TERM_6_ENGINE 0
#define TNL_TERM_6_TBL 2
#define TNL_TERM_6_SIZE 0x200
#define TNL_TERM_6_KEYBUF_SIZE 40
#define TNL_TERM_6_DATABUF_SIZE 4

struct  ip6_tunnel_decap_req_type
{
	uint8_t  src_ip[16];
	uint8_t  dst_ip[16];
};

struct ip6_tunnel_decap_resp_type 
{
	uint32_t match;
};

#define PG_FRR_PORT_SCAN 14
#define PG_FRR_NH_SCAN   15
#define PG_FRR_PORT_SCAN_CNT 0x10000
#define PG_FRR_NH_SCAN_CNT   0x4000
struct hdr_frr_type
{
    uint16_t type;
    union
    {
       struct 
       {
           uint16_t frr_port;
           uint16_t  rsv;
       }pg_scan_frr_port;
       struct 
       {
          uint16_t frr_next_hop_ref;
          uint16_t  rsv;
       }pg_scan_ecmp_nh_ref;
    }info;
};
/******************************************************/

#define UDR_XEL_ROUTE_LOCK
#ifdef UDR_XEL_ROUTE_LOCK

udrstatic int _udr_xel_route_lock_init(void** plock)
{
	errinit;
	void* lock;
	assrt(plock);

	lock = semMCreate(SEM_Q_FIFO | SEM_DELETE_SAFE);
	if(lock == NULL)
		gerrv(UDR_API_E_INIT);
	*plock = lock;

err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_xel_route_lock_free(void* lock)
{
	errinit;
	int rslt;
	assrt(lock);

	rslt = semDelete(lock);
	if(rslt)
		gerrv(UDR_API_E_FAIL);

err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_xel_route_lock_in(void* lock)
{
	errinit;
	int rslt;
	assrt(lock);

	rslt = semTake(lock, WAIT_FOREVER);
	if(rslt)
		gerrv(UDR_API_E_FAIL);

err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_xel_route_lock_out(void* lock)
{
	errinit;
	int rslt;
	assrt(lock);

	rslt = semGive(lock);
	if(rslt)
		gerrv(UDR_API_E_FAIL);

err:
	errprnt;
	return r_rv;
}

#define LOCK_INIT(hndl) {r_rv = _udr_xel_route_lock_init(&(hndl)->lock);if(r_rv)gerr;}
#define LOCK_FREE(hndl) {r_rv = _udr_xel_route_lock_free((hndl)->lock);if(r_rv)gerr;}
#define LOCK_IN(hndl) {r_rv = _udr_xel_route_lock_in((hndl)->lock);if(r_rv)gerr;}
#define LOCK_OUT(hndl) {r_rv = _udr_xel_route_lock_out((hndl)->lock);if(r_rv)gerr;}
#define LOCK_XOUT(hndl) _udr_xel_route_lock_out((hndl)->lock)
#else
#define LOCK_INIT(hndl)
#define LOCK_FREE(hndl)
#define LOCK_IN(hndl)
#define LOCK_OUT(hndl)
#define LOCK_XOUT(hndl)
#endif

/******************************************************/

struct ref_sw_tab
{
	void* hwtab;
	void* hashtab;
	void* tokenpool;
	int len;
	int (*func_del)(void* hndl, int idx, void* data, int data_len);
#ifdef UDR_XEL_ROUTE_LOCK
	void* lock;
#endif
};

typedef struct ref_sw_tab* dasa_sw_tab_t;
typedef struct ref_sw_tab* nexthop_sw_tab_t;

struct ref_hw_info
{
	int eng_suid;
	int eng_rd_code;
	int eng_wr_code;
	int eng_width;
	uint32_t base;
	int step;
	int entry_width;
	int entry_num;
};

#define EAP0_UID 0x40
udrstatic int _reftab_write_hw(struct ref_hw_info* hw_hndl, int idx, void* data, int data_len)
{
	errinit;
	int i;
	int rslt;
	void* data_trav;
	uint32_t addr;
	void* priv_hndl;
	assrt(hw_hndl->entry_width <= hw_hndl->eng_width && data_len <= (hw_hndl->entry_width * hw_hndl->entry_num));

	rslt = pmcl_xel_default_hndl(&priv_hndl);
	if(rslt < 0)
		return rslt;
	addr = hw_hndl->base + hw_hndl->step * hw_hndl->entry_num * idx;
	data_trav = data;
	for(i=0; i<hw_hndl->entry_num; i++)
	{
		rtdbgprint(RT_DBG_HW_WR, "_reftab_write_hw %d idx=0x%x, addr = 0x%x\n", i, idx, addr);
		rslt = pmcl_xel_priv_xcm(priv_hndl, EAP0_UID, hw_hndl->eng_suid, addr, hw_hndl->eng_wr_code, 0, hw_hndl->eng_width, data_trav);
		if(rslt < 0)
			return rslt;
		addr += hw_hndl->step;
		data_trav = (void*)((int)data_trav + hw_hndl->entry_width);
	}

err:
	errprnt;
	return r_rv;
}

udrstatic int _reftab_read_hw(struct ref_hw_info* hw_hndl, int idx, void* data, int data_len)
{
	errinit;
	int i;
	int rslt;
	void* data_trav;
	uint32_t addr;
	void* priv_hndl;
	assrt(hw_hndl->entry_width <= hw_hndl->eng_width && data_len <= (hw_hndl->entry_width * hw_hndl->entry_num));

	rslt = pmcl_xel_default_hndl(&priv_hndl);
	if(rslt < 0)
		return rslt;
	addr = hw_hndl->base + hw_hndl->step * hw_hndl->entry_num * idx;
	data_trav = data;
	for(i=0; i<hw_hndl->entry_num; i++)
	{
		rtdbgprint(RT_DBG_HW_RD, "_reftab_read_hw %d idx=0x%x, addr = 0x%x\n", i, idx, addr);
		rslt = pmcl_xel_priv_xcm(priv_hndl, EAP0_UID, hw_hndl->eng_suid, addr, hw_hndl->eng_rd_code, 1, hw_hndl->eng_width, data_trav);
		if(rslt < 0)
			return rslt;
		addr += hw_hndl->step;
		data_trav = (void*)((int)data_trav + hw_hndl->entry_width);
	}

err:
	errprnt;
	return r_rv;
}

udrstatic int _reftab_add_hashtab_cbed(void* tokenpool, void* key, int key_len, void** pval)
{
	int rslt;
	int token;
	/*struct table_dasa_resp_type* dasa_entry = key;
	assrt(key_len == sizeof(struct table_dasa_resp_type));*/

	rslt = pmcl_comm_tokenpool_takenew(tokenpool, &token);
	if(rslt < 0)
		return rslt;

	*pval = (void*)token;
	return -PMCL_ERR_OK;
}

#define REFTAB_MAX_HW_LEN 128
/* 判断是否匹配 */
udrstatic int _reftab_match_hashtab_cbed(struct ref_sw_tab* ref_hndl, void* val, void* key, int key_len)
{
	int r_rv;
	int idx = (int)val;
	char buf[REFTAB_MAX_HW_LEN];
	if(key_len > REFTAB_MAX_HW_LEN)
		return -PMCL_ERR_ASSERT;
	if(key_len != ref_hndl->len)
		return -PMCL_ERR_ASSERT;

	r_rv = _reftab_read_hw(ref_hndl->hwtab, idx, buf, key_len);
	if(r_rv)
		return -PMCL_ERR_INNER;

	if(pmcl_memmatch(buf, key, key_len))
		return 1;
	else
		return 0;
}
/* 删除硬表的回调,ref_cnt清零 */
udrstatic int _reftab_del_tkp_cbed(struct ref_sw_tab* ref_hndl, int token)
{
	int r_rv, rlst;
	int del_val;
	char buf[REFTAB_MAX_HW_LEN];
	if(ref_hndl->len > REFTAB_MAX_HW_LEN)
		return -PMCL_ERR_ASSERT;

	r_rv = _reftab_read_hw(ref_hndl->hwtab, token, buf, ref_hndl->len);
	if(r_rv)
		return -PMCL_ERR_INNER;
    /*子表的ref_cnt减1*/
	if(ref_hndl->func_del)
	{
		r_rv = (ref_hndl->func_del)(ref_hndl, token, buf, ref_hndl->len);
		if(r_rv)
			return -PMCL_ERR_INNER;
	}

	rlst = pmcl_comm_hashtab_del(ref_hndl->hashtab, buf, ref_hndl->len, (void**)&del_val);
	if(r_rv)
		return -PMCL_ERR_INNER;
	if(del_val != token)
		return -PMCL_ERR_ASSERT;
	
	pmcl_memset(buf, 0, ref_hndl->len);
	r_rv = _reftab_write_hw(ref_hndl->hwtab, token, buf, ref_hndl->len);
	if(r_rv)
		return -PMCL_ERR_INNER;

	return -PMCL_ERR_OK;
}

/* ! REF CNT ALWAYS INCREASE WHEN CALLED ! */
udrstatic int _reftab_get_or_add(struct ref_sw_tab* reftab_hndl, void* entry, int* pidx)
{
	errinit;
	int rslt;
	int idx;

	LOCK_IN(reftab_hndl);
    /* 返回idx rslt- 1:add 0:get , reftab_hndl->tokenpool为前一个函数的参数 */
	rslt = pmcl_comm_hashtab_get_or_add(reftab_hndl->hashtab, entry, reftab_hndl->len, (void**)&idx, _reftab_add_hashtab_cbed, reftab_hndl->tokenpool);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);

	if(rslt == 1)
	{
		/* add new */
		r_rv = _reftab_write_hw(reftab_hndl->hwtab, idx, entry, reftab_hndl->len);
		if(r_rv)
			gerr;
	}
    /* 已经存在 */
	else
	{
		/* get ref */
		rslt = pmcl_comm_tokenpool_take(reftab_hndl->tokenpool, idx);
		if(rslt < 0)
			gerrv(UDR_API_E_INTERNAL);
		/* release all prev ref tab */
		if(reftab_hndl->func_del)
		{
			char buf[REFTAB_MAX_HW_LEN];
			r_rv = _reftab_read_hw(reftab_hndl->hwtab, idx, buf, reftab_hndl->len);
			if(r_rv)
				gerr;
            /* ##?? 为何此处有func_del */
			r_rv = (reftab_hndl->func_del)(reftab_hndl, idx, buf, reftab_hndl->len);
			if(r_rv)
				gerr;
		}
	}

	if(pidx)
        /* 保存下一跳信息索引 */
		*pidx = idx;

err:
	LOCK_XOUT(reftab_hndl);
	errprnt;
	return r_rv;
}

udrstatic int _reftab_reference_dir(struct ref_sw_tab* reftab_hndl, int idx)
{
	errinit;
	int rslt;

	LOCK_IN(reftab_hndl);

	rslt = pmcl_comm_tokenpool_take(reftab_hndl->tokenpool, idx);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);

err:
	LOCK_XOUT(reftab_hndl);
	errprnt;
	return r_rv;
}

udrstatic int _reftab_release_dir(struct ref_sw_tab* reftab_hndl, int idx)
{
	errinit;
	int rslt;

	LOCK_IN(reftab_hndl);

	rslt = pmcl_comm_tokenpool_give(reftab_hndl->tokenpool, idx);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);

err:
	LOCK_XOUT(reftab_hndl);
	errprnt;
	return r_rv;
}

#if 0
udrstatic int _reftab_release(struct ref_sw_tab* reftab_hndl, void* entry, int* pidx)
{
	errinit;
	int rslt;
	int idx;

	rslt = pmcl_comm_hashtab_get(reftab_hndl->hashtab, entry, reftab_hndl->len, (void**)&idx);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);

	r_rv = _reftab_release_dir(reftab_hndl, idx);
	if(r_rv)
		gerr;

	if(pidx)
		*pidx = idx;

err:
	errprnt;
	return r_rv;
}
#endif

/* 前两个参数为输入,后一个为输出 */
udrstatic int _reftab_refcnt(struct ref_sw_tab* reftab_hndl, int idx, int* prefcnt)
{
	errinit;
	int refcnt;

	refcnt = pmcl_comm_tokenpool_refcnt(reftab_hndl->tokenpool, idx);
	if(refcnt < 0)
		gerrv(UDR_API_E_INTERNAL);

	if(prefcnt)
		*prefcnt = refcnt;

err:
	errprnt;
	return r_rv;
}


#define REFTAB_HASH_WIDTH 16
#define REFTAB_HASH_BAKNUM 0x4000
udrstatic int _reftab_init(struct ref_sw_tab** preftab_hndl, int entry_len, int tab_size, void* hw_info, void* func_del)
{
	errinit;
	int rslt;
	int reverse_token;
	struct ref_sw_tab* reftab_hndl;
	if(preftab_hndl == NULL)
		gerrv(UDR_API_E_PARAM);
	
	reftab_hndl = pmcl_malloc(sizeof(struct ref_sw_tab));
	if(!reftab_hndl)
		gerrv(UDR_API_E_MEMORY);
	pmcl_memset(reftab_hndl, 0, sizeof(struct ref_sw_tab));
    /* hash地址空间大小以及备用hash地址空间的大小 */
	reftab_hndl->len = entry_len;
	rslt = pmcl_comm_hashtab_create(&reftab_hndl->hashtab, REFTAB_HASH_WIDTH, REFTAB_HASH_BAKNUM);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);
    /* hash发生冲突时的比较函数 */
	rslt = pmcl_comm_hashtab_reg_func(reftab_hndl->hashtab, NULL, _reftab_match_hashtab_cbed, reftab_hndl);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);
	rslt = pmcl_comm_tokenpool_create(&reftab_hndl->tokenpool, tab_size);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);
    /* 删除硬表的回调,ref_cnt清零  */
	rslt = pmcl_comm_tokenpool_reg_func(reftab_hndl->tokenpool, NULL, _reftab_del_tkp_cbed, reftab_hndl);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);
	/* reverse token 0 for invalid token */
	rslt = pmcl_comm_tokenpool_takenew(reftab_hndl->tokenpool, &reverse_token);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);
	assrt(reverse_token == 0);

	if(hw_info)
     /* 设置子表硬表 */
		reftab_hndl->hwtab = hw_info;
	if(func_del)
     /* 设置子表软表操作 */
		reftab_hndl->func_del = func_del;

	LOCK_INIT(reftab_hndl);

	*preftab_hndl = reftab_hndl;

err:
	errprnt;
	return r_rv;
}

udrstatic int _reftab_free(struct ref_sw_tab* reftab_hndl)
{
	errinit;
	int rslt;

	rslt = pmcl_comm_hashtab_free(reftab_hndl->hashtab);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);

	rslt = pmcl_comm_tokenpool_free(reftab_hndl->tokenpool);
	if(rslt < 0)
		gerrv(UDR_API_E_INTERNAL);

	LOCK_FREE(reftab_hndl);

	pmcl_free(reftab_hndl);

err:
	errprnt;
	return r_rv;
}

/******************************************************/

/* SE0 ~ SE4 */
#define SE_DDR_Read64 0x03
#define SE_DDR_Write64 0x04
#define SE_DDR_Read128 0x07
#define SE_DDR_Write128 0x09

/* SE5 */
#define SE_QDR_Read64 0x03
#define SE_QDR_Write64 0x05
#define SE_QDR_Read128 0x06
#define SE_QDR_Write128 0x0a

/* LAS1 */
#define LAS_DDR_Read64 0x03
#define LAS_DDR_Write64 0x05
#define LAS_DDR_Read128 0x06
#define LAS_DDR_Write128 0x0a

/* LAS0 LAS2 */
#define LAS_QDR_Read64 0x03
#define LAS_QDR_Write64 0x04
#define LAS_QDR_Read128 0x07
#define LAS_QDR_Write128 0x09

/* LAD0 ~ LAD1 */
#define LAD_PP_Read120 0x05
#define LAD_PP_Write120 0x20

#define NSE_SUID (0x4c)
#define LAS_SUID(i) (0x50 + (i))
#define LAD_SUID(i) (0x58 + (i))
#define SE_SUID(i) (0x60 + (i))

#if 0
#define DASA_HW_TAB_SIZE 0x1000
udrstatic struct ref_hw_info dasa_hw_info =
{
	.eng_suid = SE_SUID(3),
	.eng_rd_code = SE_DDR_Read128,
	.eng_wr_code = SE_DDR_Write128,
	.eng_width = 16,
	.base = 0x00000,
	.step = 2,
	.entry_width = 16,
	.entry_num = 1
};
#else
#define DASA_HW_TAB_SIZE 0x10000   // 64k
udrstatic struct ref_hw_info dasa_hw_info =
{
	.eng_suid = LAS_SUID(0),
	.eng_rd_code = LAS_QDR_Read128,
	.eng_wr_code = LAS_QDR_Write128,
	.eng_width = 16,
	.base = 0x00000,
	.step = 2,
	.entry_width = 16,
	.entry_num = 1
};
#endif

#define NH_HW_TAB_SIZE 0x8000  // 32k
udrstatic struct ref_hw_info nh_hw_info =
{
	.eng_suid = LAS_SUID(2),
	.eng_rd_code = LAS_QDR_Read128,
	.eng_wr_code = LAS_QDR_Write128,
	.eng_width = 16,
	.base = 0xb0000,
	.step = 2,
	.entry_width = 16,
	.entry_num = 1
};

#define ECMP_MEMBER_MAX 32
#define ECMP_NEXTHOP_FLAG 0x00800000
#define ECMP_HW_TAB_SIZE 0x800
udrstatic struct ref_hw_info ecmp_hw_info =
{
	.eng_suid = LAS_SUID(2),
	.eng_rd_code = LAS_QDR_Read64,
	.eng_wr_code = LAS_QDR_Write64,
	.eng_width = 8,
	.base = 0x00000,
	.step = 1,
	.entry_width = 8,
	.entry_num = 8
};

#define VP_HW_TAB_SIZE 0x8000  // 32k
udrstatic struct ref_hw_info vp_hw_info =
{
	.eng_suid = LAS_SUID(0),
	.eng_rd_code = LAS_QDR_Read128,
	.eng_wr_code = LAS_QDR_Write128,
	.eng_width = 16,
	.base = 0x20000,
	.step = 2,
	.entry_width = 16,
	.entry_num = 1
};

#define TNL_HW_TAB_SIZE 0x1000 // 4k
udrstatic struct ref_hw_info tnl_hw_info =
{
	.eng_suid = SE_SUID(2),
	.eng_rd_code = SE_DDR_Read64,
	.eng_wr_code = SE_DDR_Write64,
	.eng_width = 8,
	.base = 0x00a40,
	.step = 1,
	.entry_width = 8,
	.entry_num = 1
};

#define HDIP4_HW_TAB_SIZE 0x200 // 512
udrstatic struct ref_hw_info hdip4_hw_info =
{
	.eng_suid = SE_SUID(1),
	.eng_rd_code = SE_DDR_Read128,
	.eng_wr_code = SE_DDR_Write128,
	.eng_width = 16,
	.base = 0x00100,
	.step = 2,
	.entry_width = 16,
	.entry_num = 1
};

#define HDIP6_HW_TAB_SIZE 0x100  // 256
udrstatic struct ref_hw_info hdip6src_hw_info =
{
	.eng_suid = SE_SUID(4),
	.eng_rd_code = SE_DDR_Read128,
	.eng_wr_code = SE_DDR_Write128,
	.eng_width = 16,
	.base = 0x02000,
	.step = 2,
	.entry_width = 16,
	.entry_num = 1
};

udrstatic struct ref_hw_info hdip6dst_hw_info =
{
	.eng_suid = SE_SUID(2),
	.eng_rd_code = SE_DDR_Read128,
	.eng_wr_code = SE_DDR_Write128,
	.eng_width = 16,
	.base = 0x00840,
	.step = 2,
	.entry_width = 16,
	.entry_num = 1
};

/******************************************************/

/*udrstatic*/ struct
{
	struct ref_sw_tab* dasa_reftab;
	struct ref_sw_tab* nexthop_reftab;
	struct ref_sw_tab* ecmp_reftab;
	struct ref_sw_tab* vp_reftab;
	struct ref_sw_tab* tnl_reftab;
	struct ref_sw_tab* hdip4_reftab;
	struct ref_sw_tab* hdip6src_reftab;
	struct ref_sw_tab* hdip6dst_reftab;
	void* buftab;
#ifdef UDR_XEL_ROUTE_LOCK
	void* lock;
#endif
} _udr_xel_route_hndl = {0};

#define _REFTAB_GET(n) \
	if(pmcl_strmatch(name, #n))return _udr_xel_route_hndl.n##_reftab
udrstatic struct ref_sw_tab* _reftab_get(const char* name)
{
	_REFTAB_GET(dasa);
	_REFTAB_GET(nexthop);
	_REFTAB_GET(ecmp);
	_REFTAB_GET(vp);
	_REFTAB_GET(tnl);
	_REFTAB_GET(hdip4);
	_REFTAB_GET(hdip6src);
	_REFTAB_GET(hdip6dst);
	return NULL;
}

/* 添加下一跳信息,返回nh_ref索引指针pidx */
int udr_xel_route_reftab_get_or_add_dir(int unit, const char* name, void* data, int* pidx)
{
	errinit;
	int ref_idx;
	struct ref_sw_tab* reftab = _reftab_get(name);
	assrt(reftab);

	r_rv = _reftab_get_or_add(reftab, data, &ref_idx);
	if(r_rv)
		gerr;
	rtdbgprint(RT_DBG_REFTAB, "%s get or add dir: ref_idx=0x%x\n", name, ref_idx);

	if(pidx)
		*pidx = ref_idx;

err:
	errprnt;
	return r_rv;
}

int udr_xel_route_reftab_release_dir(int unit, const char* name, int idx)
{
	errinit;
	struct ref_sw_tab* reftab = _reftab_get(name);
	assrt(reftab);

	rtdbgprint(RT_DBG_REFTAB, "%s release direct: ref_idx=0x%x\n", name, idx);
	r_rv = _reftab_release_dir(reftab, idx);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}

/******************************************************/

#define _bitfield_set_save(f, v, n) \
	if((v) & (~((1<<(n))-1)))  \
	{ \
		printf("%s = %d more than %d bits.\n", #v, v, n); \
		gerrv(UDR_API_E_INTERNAL); \
	} \
	else \
	{ \
		(f) = (v); \
	}
udrstatic int _udr_convert_egr_to_dasa(udr_egress_entry_t* egr_entry, struct table_dasa_resp_type* dasa_entry)
{
	errinit;
	dasa_entry->valid = 1;
	if(egr_entry->vid == 0)
	{
		dasa_entry->tag_act = 0;
	}
	else
	{
		dasa_entry->tag_act = 1;
	}
	dasa_entry->prio = 0;
	dasa_entry->cfi = 0;
	_bitfield_set_save(dasa_entry->vid, egr_entry->vid, 12);
	pmcl_memcpy(dasa_entry->damac, egr_entry->dst_mac, 6);
	pmcl_memset(dasa_entry->samac, 0, 6);
err:
	errprnt;
	return r_rv;
}
int uspdebug_route=0;
udrstatic int _udr_convert_egr_to_nh(udr_egress_entry_t* egr_entry, struct ip_next_hop_resp* nh_entry, int dasa_ref, int tnl_ref)
{
	errinit;
       int product_type=0;
    
	nh_entry->valid_bit = 1;
    memcpy(nh_entry->dst_ip, egr_entry->next_hop_ip, 4);
	if(egr_entry->flags & UDR_ROUTE_FLAG_TUNNEL)
		nh_entry->entry_type = IP_TUNNEL;
	else
		nh_entry->entry_type = L3_NORMAL_FORWARD;
	
	if(egr_entry->flags & UDR_ROUTE_FLAG_CPU)
		nh_entry->cpu_flag = 1;
	else
		nh_entry->cpu_flag = 0;
#if 0
	_bitfield_set_save(nh_entry->mod_id, egr_entry->modid, 4);
#else
	{
		int _tmp_modid = egr_entry->modid;
		if(egr_entry->flags & UDR_ROUTE_FLAG_CPU)
		{
                    udr_xel_system_product_get(0, &product_type);
                    if(product_type==1)
                        r_rv = udr_xel_system_modid_get(0, &_tmp_modid, NULL);
                    else
			    r_rv = udr_xel_system_modid_get(0, NULL, &_tmp_modid);
                    if(uspdebug_route)
                        printf("%s: product_type=%d, _tmp_modid=%d\n\r",__FUNCTION__,product_type,_tmp_modid);
			if(r_rv)
				gerr;
		}
		else
		{
			r_rv = udr_xel_system_modid_trans2hw(0, _tmp_modid, &_tmp_modid);
			if(r_rv)
				gerr;
		}
                if(uspdebug_route)
                        printf("%s: flag=%d\n\r",__FUNCTION__,egr_entry->flags);
		_bitfield_set_save(nh_entry->mod_id, _tmp_modid, 7);
		
	}
#endif
	if(egr_entry->flags & UDR_ROUTE_FLAG_CPU)
	{
		nh_entry->port_type = 0;
		nh_entry->dest_id = 0;
	}
	else if(egr_entry->flags & UDR_ROUTE_FLAG_TRUNK)
	{
		nh_entry->port_type = 1;
		_bitfield_set_save(nh_entry->dest_id, egr_entry->port, 7);
	}
	else
	{
		nh_entry->port_type = 0;
		_bitfield_set_save(nh_entry->dest_id, egr_entry->port, 7);
	}
	_bitfield_set_save(nh_entry->l3_mac_index, dasa_ref, 16);
	_bitfield_set_save(nh_entry->l3_vpn_init_label_index_ipv4_tunnel_index, tnl_ref, 16);
err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_convert_egr_to_ecmp(int num, int* egr_grp, struct ecmp_entry_type* ecmp_entry)
{
	errinit;
	int i, j;
	int filled[ECMP_MEMBER_MAX] = {0};

	for(i=0; i<ECMP_MEMBER_MAX; i++)
	{
		if(i<num)
		{
			for(j=0; j<i; j++)
			{
				assrt(filled[j] != egr_grp[i % num]);
			}
			filled[i] = egr_grp[i % num];
		}
        /* 将ecmp的32个next_hop_ref填满 */
        ecmp_entry->entry[i].master_flag = 1;
		_bitfield_set_save(ecmp_entry->entry[i].ecmp_next_hop_ref, egr_grp[i % num], 15);
	}

err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_convert_ecmp_to_egr(struct ecmp_entry_type* ecmp_entry, int* pnum, int* egr_grp)
{
    /* 从一个ecmp中取出next_hop_ref信息和next_hop_ref的条目数 */
	errinit;
	int i;
	assrt(pnum);

	for(i=0; i<ECMP_MEMBER_MAX; i++)
	{
		int egr = ecmp_entry->entry[i].ecmp_next_hop_ref;
		if(i>0)
		{
			if(egr_grp[0] == egr)
				break;
		}
		egr_grp[i] = egr;
	}
	*pnum = i;

err:
	errprnt;
	return r_rv;
}


/******************************************************/

#define TNL_PARAM_PASS_NULL

#define BUFTAB_TNL 1

udrstatic int _udr_convert_tnltp(struct tnlbuf_sw_type* pswtp, int* ptnltp)
{
	errinit;
	enum tunnel_entry_type tnltp;
	assrt(pswtp->dirty.type);

	switch(pswtp->type)
	{
		case UDR_TUNNEL_6TO4:
			tnltp = TNLTYP_IP6_TO_IP4_TUNNEL_PROCESS;
			break;
		case UDR_TUNNEL_ISATAP:
			tnltp = TNLTYP_ISATAP_TUNNEL_PROCESS;
			break;
		case UDR_TUNNEL_GRE:
			assrt(pswtp->dirty.family);
			if(pswtp->family == UDR_TNL_FA4)
				tnltp = TNLTYP_IP4_GRE_HEADER_TUNNEL_PROCESS;
			else if(pswtp->family == UDR_TNL_FA6)
				tnltp = TNLTYP_IP6_GRE_HEADER_TUNENL_PROCESS;
			else
				gerrp(UDR_API_E_PARAM, "Unsupported tunnel family %d.\n", pswtp->family);
			break;
		case UDR_TUNNEL_IPINIP:
			assrt(pswtp->dirty.family);
			if(pswtp->family == UDR_TNL_FA4)
				tnltp = TNLTYP_IP6_IN_IP4_TUNNEL_PROCESS;
			else if(pswtp->family == UDR_TNL_FA6)
				tnltp = TNLTYP_IP4_IN_IP6_TUNNEL_PROCESS;
			else
				gerrp(UDR_API_E_PARAM, "Unsupported tunnel family %d.\n", pswtp->family);
			break;
		default:
			gerrp(UDR_API_E_PARAM, "Unsupported tunnel type %d.\n", pswtp->type);
	}
    if(uspdebug_tnl)
        printf("_udr_convert_tnltp: pswtp->type=%d, pswtp->family=%d,tnltp=%d\n", pswtp->type,pswtp->family , tnltp);
	if(ptnltp)
		*ptnltp = tnltp;
err:
	errprnt;
	return r_rv;
}


udrstatic int _udr_check_tnlbuf_valid(struct tnlbuf_info* tnlbuf, int silent)
{
	errinit;
	assrt(tnlbuf->dirty.type);
	assrt(tnlbuf->sw_type.dirty.type);
	switch(tnlbuf->sw_type.type)
	{
		case UDR_TUNNEL_6TO4:
			assrt(tnlbuf->dirty.sip4);
			assrt(tnlbuf->comm_info.ttl_dscp_config_bit == 0);
			break;
		case UDR_TUNNEL_ISATAP:
			assrt(tnlbuf->dirty.sip4);
			assrt(tnlbuf->comm_info.ttl_dscp_config_bit == 0);
			break;
		case UDR_TUNNEL_GRE:
			if(tnlbuf->comm_info.ttl_dscp_config_bit)
			{
				assrt(tnlbuf->dirty.ttl);
				assrt(tnlbuf->dirty.dscp);
			}
			assrt(tnlbuf->sw_type.dirty.family);
			if(tnlbuf->sw_type.family == UDR_TNL_FA4)
			{
//					assrt(tnlbuf->dirty.sip4);
//					assrt(tnlbuf->dirty.dip4);
			}
			else if(tnlbuf->sw_type.family == UDR_TNL_FA6)
			{
//				assrt(tnlbuf->dirty.sip6);
//				assrt(tnlbuf->dirty.dip6);
			}
			else
				gerrp(UDR_API_E_PARAM, "Unsupported tunnel family %d.\n", tnlbuf->sw_type.family);
			break;
		case UDR_TUNNEL_IPINIP:
			if(tnlbuf->comm_info.ttl_dscp_config_bit)
			{
				assrt(tnlbuf->dirty.ttl);
				assrt(tnlbuf->dirty.dscp);
			}
			assrt(tnlbuf->sw_type.dirty.family);
			if(tnlbuf->sw_type.family == UDR_TNL_FA4)
			{
//				assrt(tnlbuf->dirty.sip4);
//				assrt(tnlbuf->dirty.dip4);
			}
			else if(tnlbuf->sw_type.family == UDR_TNL_FA6)
			{
//				assrt(tnlbuf->dirty.sip6);
//				assrt(tnlbuf->dirty.dip6);
			}
			else
				gerrp(UDR_API_E_PARAM, "Unsupported tunnel family %d.\n", tnlbuf->sw_type.family);
			break;
		default:
			gerrp(UDR_API_E_PARAM, "Unsupported tunnel type %d.\n", tnlbuf->sw_type.type);
	}
err:
	if(!silent)errprnt;
	return r_rv;
}

udrstatic int _udr_tnlbuf_default(struct tnlbuf_info* tnlbuf)
{
	errinit;

	tnlbuf->status = TNLBUF_STATUS_NEW;
err:
	errprnt;
	return r_rv;
}

struct tnlbuf_info* _udr_tnlbuf_get(int unit, int idx)
{
	errinit;
	int rslt;
	void* rbuf = NULL;
	if(_udr_xel_route_hndl.buftab== NULL)
	{
		rslt = pmcl_comm_tab_create(&_udr_xel_route_hndl.buftab);
		if(rslt<0)
			gerrv(UDR_API_E_INTERNAL);
	}

	rslt = pmcl_comm_tab_get(_udr_xel_route_hndl.buftab, &rbuf, 2, BUFTAB_TNL, idx);
    /* 如果返回-1,表示不存在,重新创建 */
    if(rslt == -PMCL_ERR_NULL_RET)
	{
		rbuf = pmcl_malloc(sizeof(struct tnlbuf_info));
		if(!rbuf)
			gerrv(UDR_API_E_MEMORY);
		pmcl_memset(rbuf, 0, sizeof(struct tnlbuf_info));

		r_rv = _udr_tnlbuf_default(rbuf);
		if(r_rv)
			gerr;

		rslt = pmcl_comm_tab_set(_udr_xel_route_hndl.buftab, rbuf, 2, BUFTAB_TNL, idx);
		if(rslt < 0)
		{
			rbuf = NULL;
			gerrv(UDR_API_E_INTERNAL);
		}
	}
	else if(rslt < 0)
	{
		rbuf = NULL;
		gerrv(UDR_API_E_INTERNAL);
	}

err:
	errprnt;
	return rbuf;
}

udrstatic int _udr_tnlbuf_del(int unit, int idx)
{
	errinit;
	int rslt;
	void* rbuf = NULL;
	assrt(_udr_xel_route_hndl.buftab);

	rslt = pmcl_comm_tab_get(_udr_xel_route_hndl.buftab, &rbuf, 2, BUFTAB_TNL, idx);
	if(rslt == -PMCL_ERR_NULL_RET)
	{
		gerrv(UDR_API_E_NOT_FOUND);
	}
	else if(rslt < 0)
	{
		gerrv(UDR_API_E_INTERNAL);
	}
	else
	{
		assrt(rbuf);
		pmcl_free(rbuf);
		rslt = pmcl_comm_tab_del(_udr_xel_route_hndl.buftab, 2, BUFTAB_TNL, idx);
		assrt(rslt != -PMCL_ERR_NULL_RET);
		if(rslt < 0)
		{
			gerrv(UDR_API_E_INTERNAL);
		}
	}

err:
	errprnt;
	return r_rv;
}


udrstatic int _udr_tnlterm_hw_set_4(struct tnlbuf_info* tnlbuf, int idx, int dis)
{
	errinit;
	int rslt;
	char keybuf[TNL_TERM_4_KEYBUF_SIZE] = {0};
	char maskbuf[TNL_TERM_4_KEYBUF_SIZE] = {0};
	char databuf[TNL_TERM_4_DATABUF_SIZE] = {0};
	struct ip4_tunnel_decap_req_type* key = (struct ip4_tunnel_decap_req_type*)keybuf;
	struct ip4_tunnel_decap_req_type* mask = (struct ip4_tunnel_decap_req_type*)maskbuf;
	struct ip4_tunnel_decap_resp_type* data = (struct ip4_tunnel_decap_resp_type*)databuf;
	if(uspdebug_tnl)
    printf("_udr_tnlterm_hw_set_4 is called, dis =%d",dis);
	assrt(idx < TNL_TERM_4_SIZE);

	if(!dis)
	{
		if(tnlbuf->dirty.sip4)
		{
			key->dst_ip = tnlbuf->ipv4_info.sip;
			mask->dst_ip = 0xffffffff;
		}
		if(tnlbuf->dirty.dip4)
		{
			key->src_ip = tnlbuf->ipv4_info.dip;
			mask->src_ip = 0xffffffff;
		}
		data->match = 1;
	}
	
	rslt = pmcl_xel_write_tcam(
		TNL_TERM_4_ENGINE, TNL_TERM_4_TBL,
		idx, keybuf, maskbuf, databuf, dis);

err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_tnlterm_hw_set_6(struct tnlbuf_info* tnlbuf, int idx, int dis)
{
	errinit;
    if(uspdebug_tnl)
       printf("_udr_tnlterm_hw_set_6 is called, dis =%d",dis);
	int rslt;
	char keybuf[TNL_TERM_6_KEYBUF_SIZE] = {0};
	char maskbuf[TNL_TERM_6_KEYBUF_SIZE] = {0};
	char databuf[TNL_TERM_6_DATABUF_SIZE] = {0};
	struct ip6_tunnel_decap_req_type* key = (struct ip6_tunnel_decap_req_type*)keybuf;
	struct ip6_tunnel_decap_req_type* mask = (struct ip6_tunnel_decap_req_type*)maskbuf;
	struct ip6_tunnel_decap_resp_type* data = (struct ip6_tunnel_decap_resp_type*)databuf;
	
	assrt(idx < TNL_TERM_6_SIZE);
    /* 0为enable */
	if(!dis)
	{
		if(tnlbuf->dirty.sip6)
		{
			pmcl_memcpy(key->dst_ip, tnlbuf->ipv6_src_info.ip, 16);
			pmcl_memset(mask->dst_ip, 0xff, 16);
		}
		if(tnlbuf->dirty.dip6)
		{
			pmcl_memcpy(key->src_ip, tnlbuf->ipv6_dst_info.ip, 16);
			pmcl_memset(mask->src_ip, 0xff, 16);
		}
		data->match = 1;
	}
	
	rslt = pmcl_xel_write_tcam(
		TNL_TERM_6_ENGINE, TNL_TERM_6_TBL,
		idx, keybuf, maskbuf, databuf, dis);

err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_tnlterm_auto_set(int unit, int tnl_idx)
{
	errinit;
	struct tnlbuf_info* tnlbuf;
	int tnl_ref;

	tnlbuf = _udr_tnlbuf_get(unit, tnl_idx);
	if(!tnlbuf)
	{
		gerrv(UDR_API_E_INTERNAL);
	}

	assrt(tnlbuf->status >= TNLBUF_STATUS_SW_SET);
	r_rv = _udr_check_tnlbuf_valid(tnlbuf, 1);
	if(r_rv == UDR_API_E_INTERNAL)
	{
		gerrv(UDR_API_E_NONE); /* something needed is not set, pass */
	}
	else if(r_rv)
		gerr;

	if(TUNNEL_ENTRY_TYPE_USE_HDIP6(tnlbuf->comm_info.entry_type))
	{
		r_rv = _udr_tnlterm_hw_set_6(tnlbuf, tnl_idx, 0);
		if(r_rv)
			gerr;
	}
	else
	{
		r_rv = _udr_tnlterm_hw_set_4(tnlbuf, tnl_idx, 0);
		if(r_rv)
			gerr;
	}
	tnlbuf->status = TNLBUF_STATUS_TERM_SET;

err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_tnlterm_del(int unit, int tnl_idx)
{
	errinit;
	struct tnlbuf_info* tnlbuf;
	int tnl_ref;
    if(uspdebug_tnl)
        printf("_udr_tnlterm_del:the del tnl_idx is %d\n",tnl_idx);

	tnlbuf = _udr_tnlbuf_get(unit, tnl_idx);
    if(uspdebug_tnl)
    printf("_udr_tnlterm_del:the del tnlbuf is %d\n",tnlbuf);
	if(!tnlbuf)
	{
		gerrv(UDR_API_E_INTERNAL);
	}
//	    if(uspdebug_tnl)
//	    printf("_udr_tnlterm_del:the del tnlbuf->status is %d\n",tnlbuf->status);
//		if(tnlbuf->status < TNLBUF_STATUS_TERM_SET)
//			gerrv(UDR_API_E_NONE);

	r_rv = _udr_check_tnlbuf_valid(tnlbuf, 0);
    if(uspdebug_tnl)
    printf("_udr_tnlterm_del: _udr_check_tnlbuf_valid return is %d\n",r_rv);
	if(r_rv)
		gerr;

    if(uspdebug_tnl)
    printf("_udr_tnlterm_del: tnlbuf->comm_info.entry_type is %d\n",tnlbuf->comm_info.entry_type);
	if(TUNNEL_ENTRY_TYPE_USE_HDIP6(tnlbuf->comm_info.entry_type))
	{
		r_rv = _udr_tnlterm_hw_set_6(tnlbuf, tnl_idx, 1);
		if(r_rv)
			gerr;
	}
	else
	{
		r_rv = _udr_tnlterm_hw_set_4(tnlbuf, tnl_idx, 1);
		if(r_rv)
			gerr;
	}
	tnlbuf->status = TNLBUF_STATUS_SW_SET;
	
err:
	errprnt;
	return r_rv;
}

/******************************************************/


int udr_xel_route_tnl_get_or_add(int unit, int tnl_idx, int dasa_idx,int* ptnl)
{
	errinit;
	struct tnlbuf_info* tnlbuf;
	int tnl_ref;

	tnlbuf = _udr_tnlbuf_get(unit, tnl_idx);
	if(!tnlbuf)
	{
		gerrv(UDR_API_E_INTERNAL);
	}

	assrt(tnlbuf->status >= TNLBUF_STATUS_TERM_SET);
	r_rv = _udr_check_tnlbuf_valid(tnlbuf, 0);
	if(r_rv)
		gerr;

	if(TUNNEL_ENTRY_TYPE_USE_HDIP6(tnlbuf->comm_info.entry_type))
	{
		int h6s, h6d;

		rtdbgprint(RT_DBG_TNL, "head ipv6 dst add or get: ip=%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x\n",
			tnlbuf->ipv6_dst_info.ip[0], tnlbuf->ipv6_dst_info.ip[1], tnlbuf->ipv6_dst_info.ip[2], tnlbuf->ipv6_dst_info.ip[3],
			tnlbuf->ipv6_dst_info.ip[4], tnlbuf->ipv6_dst_info.ip[5], tnlbuf->ipv6_dst_info.ip[6], tnlbuf->ipv6_dst_info.ip[7],
			tnlbuf->ipv6_dst_info.ip[8], tnlbuf->ipv6_dst_info.ip[9], tnlbuf->ipv6_dst_info.ip[10], tnlbuf->ipv6_dst_info.ip[11],
			tnlbuf->ipv6_dst_info.ip[12], tnlbuf->ipv6_dst_info.ip[13], tnlbuf->ipv6_dst_info.ip[14], tnlbuf->ipv6_dst_info.ip[15]
			);
		r_rv = udr_xel_route_reftab_get_or_add_dir(unit, "hdip6dst", &tnlbuf->ipv6_dst_info, &h6d);
		if(r_rv)
			gerr;
		tnlbuf->comm_info.ip6_dst_ip_index = h6d;
		
		rtdbgprint(RT_DBG_TNL, "head ipv6 src add or get: ip=%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x\n",
			tnlbuf->ipv6_src_info.ip[0], tnlbuf->ipv6_src_info.ip[1], tnlbuf->ipv6_src_info.ip[2], tnlbuf->ipv6_src_info.ip[3],
			tnlbuf->ipv6_src_info.ip[4], tnlbuf->ipv6_src_info.ip[5], tnlbuf->ipv6_src_info.ip[6], tnlbuf->ipv6_src_info.ip[7],
			tnlbuf->ipv6_src_info.ip[8], tnlbuf->ipv6_src_info.ip[9], tnlbuf->ipv6_src_info.ip[10], tnlbuf->ipv6_src_info.ip[11],
			tnlbuf->ipv6_src_info.ip[12], tnlbuf->ipv6_src_info.ip[13], tnlbuf->ipv6_src_info.ip[14], tnlbuf->ipv6_src_info.ip[15]
			);
		r_rv = udr_xel_route_reftab_get_or_add_dir(unit, "hdip6src", &tnlbuf->ipv6_src_info, &h6s);
		if(r_rv)
			gerr;
		tnlbuf->comm_info.ip6_src_ip_index = h6s;

		/*tnlbuf->comm_info.ip4_struct_index= 0;*/
	}
	else
	{
		int h4;

		rtdbgprint(RT_DBG_TNL, "head ipv4 add or get: dip=0x%x, sip=0x%x\n",
			tnlbuf->ipv4_info.dip, tnlbuf->ipv4_info.sip
			);
		r_rv = udr_xel_route_reftab_get_or_add_dir(unit, "hdip4", &tnlbuf->ipv4_info, &h4);
		if(r_rv)
			gerr;
		tnlbuf->comm_info.ip4_struct_index= h4;

		/*tnlbuf->comm_info.ip6_dst_ip_index = 0;
		tnlbuf->comm_info.ip6_src_ip_index = 0;*/
	}

	rtdbgprint(RT_DBG_TNL, "tunnel add or get: entry_type=0x%x, ttl_auto=%d, ttl=%d, dscp=0x%x, h4ref=0x%x, h6dref=0x%x, h6sref=0x%x\n",
		tnlbuf->comm_info.entry_type, tnlbuf->comm_info.ttl_dscp_config_bit, tnlbuf->comm_info.ttl, tnlbuf->comm_info.dscp,
		tnlbuf->comm_info.ip4_struct_index, tnlbuf->comm_info.ip6_dst_ip_index, tnlbuf->comm_info.ip6_src_ip_index
		);
	r_rv = udr_xel_route_reftab_get_or_add_dir(unit, "tnl", &tnlbuf->comm_info, &tnl_ref);
	if(r_rv)
		gerr;
    tnlbuf->dasa_ref = dasa_idx;
	tnlbuf->status = TNLBUF_STATUS_HW_SET;

	if(ptnl)
		*ptnl = tnl_ref;
	
err:
	errprnt;
	return r_rv;
}

int udr_xel_route_dasa_get_or_add(int unit, udr_egress_entry_t* egr_entry, int* pdasa)
{
	errinit;
	int dasa_ref;
	struct table_dasa_resp_type dasa_entry = {0};
	assrt(_udr_xel_route_hndl.dasa_reftab);

	r_rv = _udr_convert_egr_to_dasa(egr_entry, &dasa_entry);
	if(r_rv)
		gerr;

	rtdbgprint(RT_DBG_DASA, "dasa add or get: tag_act=%d, vid=%d, da=%02x:%02x:%02x:%02x:%02x:%02x, sa=%02x:%02x:%02x:%02x:%02x:%02x\n", dasa_entry.tag_act, dasa_entry.vid,
		dasa_entry.damac[0], dasa_entry.damac[1], dasa_entry.damac[2], dasa_entry.damac[3], dasa_entry.damac[4], dasa_entry.damac[5],
		dasa_entry.samac[0], dasa_entry.samac[1], dasa_entry.samac[2], dasa_entry.samac[3], dasa_entry.samac[4], dasa_entry.samac[5]);
	r_rv = udr_xel_route_reftab_get_or_add_dir(unit, "dasa", &dasa_entry, &dasa_ref);
	if(r_rv)
		gerr;

	if(pdasa)
		*pdasa = dasa_ref;

err:
	errprnt;
	return r_rv;
}

int udr_xel_route_nexthop_with_tnl_get_or_add(int unit, int tnl_idx, udr_egress_entry_t* egr_entry, int* pnexthop)
{
	errinit;
	int dasa_ref, tnl_ref, nh_ref;
	struct ip_next_hop_resp nh_entry = {0};
	assrt(_udr_xel_route_hndl.dasa_reftab && _udr_xel_route_hndl.nexthop_reftab);

	r_rv = udr_xel_route_dasa_get_or_add(unit, egr_entry, &dasa_ref);
	if(r_rv)
		gerr;
    
	r_rv = udr_xel_route_tnl_get_or_add(unit, tnl_idx, dasa_ref, &tnl_ref);
	if(r_rv)
		gerr;

	r_rv = _udr_convert_egr_to_nh(egr_entry, &nh_entry, dasa_ref, tnl_ref);
	if(r_rv)
		gerr;

	rtdbgprint(RT_DBG_NEXTHOP, "nexthop add or get: entry_type=%d, port_type=%d, cpu_flag=%d, mod_id=%d, dest_id=%d, l3_mac_index=0x%x\n", nh_entry.entry_type, nh_entry.port_type, nh_entry.cpu_flag, nh_entry.mod_id, nh_entry.dest_id, nh_entry.l3_mac_index);
	r_rv = udr_xel_route_reftab_get_or_add_dir(unit, "nexthop", &nh_entry, &nh_ref);
	if(r_rv)
		gerr;

	if(pnexthop)
		*pnexthop = nh_ref;

err:
	errprnt;
	return r_rv;
}

/* 添加下一跳,pnexthop添加的下一跳索引的指针 */
int udr_xel_route_nexthop_get_or_add(int unit, udr_egress_entry_t* egr_entry, int* pnexthop)
{
	errinit;
	int dasa_ref, nh_ref;
	struct ip_next_hop_resp nh_entry = {0};
	assrt(_udr_xel_route_hndl.dasa_reftab && _udr_xel_route_hndl.nexthop_reftab);
    /* 获取dasa的索引号 egr_ertry为输入  dasa_ref为输出 */
	r_rv = udr_xel_route_dasa_get_or_add(unit, egr_entry, &dasa_ref);
	if(r_rv)
		gerr;
    /* 将udr_egress_entry_t:egr_entry转化为ip_next_hop_resp:nh_entry结构体 */
	r_rv = _udr_convert_egr_to_nh(egr_entry, &nh_entry, dasa_ref, 0);
	if(r_rv)
		gerr;
    /* 添加下一跳信息,返回nh_ref索引 */
	rtdbgprint(RT_DBG_NEXTHOP, "nexthop add or get: entry_type=%d, port_type=%d, cpu_flag=%d, mod_id=%d, dest_id=%d, l3_mac_index=0x%x\n", nh_entry.entry_type, nh_entry.port_type, nh_entry.cpu_flag, nh_entry.mod_id, nh_entry.dest_id, nh_entry.l3_mac_index);
	r_rv = udr_xel_route_reftab_get_or_add_dir(unit, "nexthop", &nh_entry, &nh_ref);
	if(r_rv)
		gerr;

	if(pnexthop)
		*pnexthop = nh_ref;

err:
	errprnt;
	return r_rv;
}

int udr_xel_route_ecmp_get_or_add(int unit, int egr_num, udr_egress_entry_t* egr_entry, int* pecmp)
{
	errinit;
	int i;
	int ecmp_ref;
	int egr_num_add = 0;
	struct ecmp_entry_type ecmp_entry = {0};
	int nexthop_grp[ECMP_MEMBER_MAX] = {0};
    int ecmp_frr_mode = 0; // 0:ecmp 1:frr
    int nexthop_master_flag[ECMP_MEMBER_MAX] = {0};
	assrt(egr_num>0 && egr_num<=ECMP_MEMBER_MAX);
    /* flag位有一个为1,则为frr模式 */
    if((egr_entry[0].flags & UDR_ROUTE_FLAG_FRRMAIN) || (egr_entry[0].flags & UDR_ROUTE_FLAG_FRRBACKUP))
    {
        ecmp_frr_mode = 1;
        rtdbgprint(RT_DBG_ECMP,"the frr mode captured!\n");
    }
	for(i=0; i<egr_num; i++)
	{
		if(egr_entry[i].op != ECMP_NH_DEL)
		{
			r_rv = udr_xel_route_nexthop_get_or_add(unit, &egr_entry[i], &nexthop_grp[egr_num_add]);
			if(r_rv)
				gerr;
            if(1 == ecmp_frr_mode)
            {
                nexthop_master_flag[egr_num_add] = (egr_entry[i].flags & UDR_ROUTE_FLAG_FRRMAIN)? 1 : 0;
            }
            egr_num_add ++;
		}
	}
	assrt(egr_num_add > 0);
    rtdbgprint(RT_DBG_ECMP,"ecmp_member_num: %d.\n", egr_num_add);
	if(egr_num_add > 1)
	{
		r_rv = _udr_convert_egr_to_ecmp(egr_num_add, nexthop_grp, &ecmp_entry);
		if(r_rv)
			gerr;
        /* frr模式时,重置master_flag标记位 */
        if(1 == ecmp_frr_mode)
        {   if(1==uspdebug_route)
            printf("frr mode detected! \n");
            for(i=0; i<ECMP_MEMBER_MAX; i++)
            {
                ecmp_entry.entry[i].master_flag = nexthop_master_flag[i%egr_num_add];
            }
        }         

		rtdbgprint(RT_DBG_ECMP, "ecmp add or get: egr_num_add=%d\n[0x%x", egr_num_add, nexthop_grp[0]);
		for(i=1; i<egr_num_add; i++)
		{
			rtdbgprint(RT_DBG_ECMP, ", 0x%x", nexthop_grp[i]);
		}
		rtdbgprint(RT_DBG_ECMP, "]\n");
		r_rv = udr_xel_route_reftab_get_or_add_dir(unit, "ecmp", &ecmp_entry, &ecmp_ref);
		if(r_rv)
			gerr;

		if(pecmp)
			*pecmp = ecmp_ref | ECMP_NEXTHOP_FLAG;
	}
	else
	{
		assrt(egr_num_add == 1);
		if(pecmp)
			*pecmp = nexthop_grp[0];
	}

err:
	errprnt;
	return r_rv;
}

#if 0
int udr_xel_route_nexthop_release(int unit, udr_egress_entry_t* egr_entry)
{
	errinit;
	int dasa_ref, nh_ref;
	struct ip_next_hop_resp nh_entry = {0};
	struct table_dasa_resp_type dasa_entry = {0};
	assrt(_udr_xel_route_hndl.dasa_reftab && _udr_xel_route_hndl.nexthop_reftab);

	r_rv = _udr_convert_egr_to_dasa(egr_entry, &dasa_entry);
	if(r_rv)
		gerr;

	rtdbgprint(RT_DBG_DASA, "dasa release: tag_act=%d, vid=%d, da=%02x:%02x:%02x:%02x:%02x:%02x, sa=%02x:%02x:%02x:%02x:%02x:%02x\n", dasa_entry.tag_act, dasa_entry.vid,
		dasa_entry.damac[0], dasa_entry.damac[1], dasa_entry.damac[2], dasa_entry.damac[3], dasa_entry.damac[4], dasa_entry.damac[5],
		dasa_entry.samac[0], dasa_entry.samac[1], dasa_entry.samac[2], dasa_entry.samac[3], dasa_entry.samac[4], dasa_entry.samac[5]);
	r_rv = _reftab_release(_udr_xel_route_hndl.dasa_reftab, &dasa_entry, &dasa_ref);
	if(r_rv)
		gerr;
	rtdbgprint(RT_DBG_DASA, "dasa_ref=0x%x\n", dasa_ref);

	r_rv = _udr_convert_egr_to_nh(egr_entry, &nh_entry, dasa_ref);
	if(r_rv)
		gerr;
	
	rtdbgprint(RT_DBG_NEXTHOP, "nexthop release: entry_type=%d, port_type=%d, mod_id=%d, dest_id=%d, l3_mac_index=0x%x\n", nh_entry.entry_type, nh_entry.port_type, nh_entry.mod_id, nh_entry.dest_id, nh_entry.l3_mac_index);
	r_rv = _reftab_release(_udr_xel_route_hndl.nexthop_reftab, &nh_entry, &nh_ref);
	if(r_rv)
		gerr;
	rtdbgprint(RT_DBG_DASA, "nh_ref=0x%x\n", nh_ref);

err:
	errprnt;
	return r_rv;
}

int udr_xel_route_dasa_release_dir(int unit, int dasa)
{
	errinit;
	assrt(_udr_xel_route_hndl.dasa_reftab);

	rtdbgprint(RT_DBG_DASA, "dasa release direct: dasa_ref=0x%x\n", dasa);
	r_rv = _reftab_release_dir(_udr_xel_route_hndl.dasa_reftab, dasa);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}

int udr_xel_route_nexthop_release_dir(int unit, int nexthop)
{
	errinit;
	struct ip_next_hop_resp nh_entry = {0};
	assrt(_udr_xel_route_hndl.nexthop_reftab);

	rtdbgprint(RT_DBG_NEXTHOP, "nexthop release direct: nexthop_ref=0x%x\n", nexthop);
	r_rv = _reftab_release_dir(_udr_xel_route_hndl.nexthop_reftab, nexthop);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}

int udr_xel_route_ecmp_release_dir(int unit, int ecmp)
{
	errinit;
	struct ecmp_entry_type ecmp_entry = {0};
	assrt(_udr_xel_route_hndl.ecmp_reftab);

	rtdbgprint(RT_DBG_ECMP, "ecmp release direct: ecmp_ref=0x%x\n", ecmp);
	r_rv = _reftab_release_dir(_udr_xel_route_hndl.ecmp_reftab, ecmp);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}
#endif
/* 下一跳的子表:dasa, vp, tnl+dasa */
udrstatic int _udr_xel_route_nexthop_ondel(void* hndl, int idx, void* data, int data_len)
{
	errinit;
	struct ip_next_hop_resp* nh_entry = data;
	assrt(data_len == sizeof(struct ip_next_hop_resp));

	if(nh_entry->entry_type == L3_NORMAL_FORWARD)
	{
		int dasa_ref;
//		assrt(nh_entry->l3_mac_index);
		assrt(nh_entry->l3_vpn_init_label_index_ipv4_tunnel_index == 0);
		dasa_ref = nh_entry->l3_mac_index;
		rtdbgprint(RT_DBG_NEXTHOP, "Forward Nexthop on delete: nexthop_ref=0x%x, dasa_ref=0x%x\n", idx, dasa_ref);
		r_rv = udr_xel_route_reftab_release_dir(0, "dasa", dasa_ref);
		if(r_rv)
			gerr;
	}
	else if(nh_entry->entry_type == L3_MPLS_VPN)
	{
		int vpn_ref;
		assrt(nh_entry->l3_mac_index == 0);
//		assrt(nh_entry->l3_vpn_init_label_index_ipv4_tunnel_index);
		vpn_ref = nh_entry->l3_vpn_init_label_index_ipv4_tunnel_index;
		rtdbgprint(RT_DBG_NEXTHOP, "VPN Nexthop on delete: nexthop_ref=0x%x, vpn_ref=0x%x\n", idx, vpn_ref);
		r_rv = udr_xel_route_reftab_release_dir(0, "vp", vpn_ref);
		if(r_rv)
			gerr;
	}
	else if(nh_entry->entry_type == IP_TUNNEL)
	{
		int dasa_ref, tnl_ref;
		assrt(nh_entry->l3_mac_index);
		assrt(nh_entry->l3_vpn_init_label_index_ipv4_tunnel_index);
		dasa_ref = nh_entry->l3_mac_index;
		tnl_ref = nh_entry->l3_vpn_init_label_index_ipv4_tunnel_index;
		rtdbgprint(RT_DBG_NEXTHOP, "Tunnel Nexthop on delete: nexthop_ref=0x%x, dasa_ref=0x%x, tnl_ref=0x%x\n", idx, dasa_ref, tnl_ref);
		r_rv = udr_xel_route_reftab_release_dir(0, "dasa", dasa_ref);
		if(r_rv)
			gerr;
		r_rv = udr_xel_route_reftab_release_dir(0, "tnl", tnl_ref);
		if(r_rv)
			gerr;
	}
	else
	{
		gerrp(UDR_API_E_INTERNAL, "Unknown egress entry_type %d.\n", nh_entry->entry_type);
	}
	
err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_xel_route_ecmp_ondel(void* hndl, int idx, void* data, int data_len)
{
	errinit;
	int i;
	int egr_num;
	int egr_grp[ECMP_MEMBER_MAX] = {0};
	struct ecmp_entry_type* ecmp_entry = data;
	assrt(data_len == sizeof(struct ecmp_entry_type));

	r_rv = _udr_convert_ecmp_to_egr(ecmp_entry, &egr_num, egr_grp);
	if(r_rv)
		gerr;

	assrt(egr_num>0);
	rtdbgprint(RT_DBG_ECMP, "ecmp on delete: ecmp_ref=0x%x egr_num=0x%x\n[0x%x", idx, egr_num, egr_grp[0]);
	for(i=1; i<egr_num; i++)
	{
		rtdbgprint(RT_DBG_ECMP, ", 0x%x", egr_grp[i]);
	}
	rtdbgprint(RT_DBG_ECMP, "]\n");

	for(i=0; i<egr_num; i++)
	{
		r_rv = udr_xel_route_reftab_release_dir(0, "nexthop", egr_grp[i]);
		if(r_rv)
			gerr;
	}
	
err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_xel_route_vp_ondel(void* hndl, int idx, void* data, int data_len)
{
	errinit;
	struct table_vp_resp_type* vp_entry = data;
	assrt(data_len == sizeof(struct table_vp_resp_type));
	/*assrt(vp_entry->dasa_index);*/

	if(vp_entry->dasa_index)
	{
		int dasa_ref;
		dasa_ref = vp_entry->dasa_index;
		rtdbgprint(RT_DBG_VP, "VPN on delete: vpn_ref=0x%x, dasa_ref=0x%x\n", idx, dasa_ref);
		r_rv = udr_xel_route_reftab_release_dir(0, "dasa", dasa_ref);
		if(r_rv)
			gerr;
	}
	else
	{
		assrt(vp_entry->out_type == 1); /* only this type for C can without DASA */
		rtdbgprint(RT_DBG_VP, "VPN without DASA on delete: vpn_ref=0x%x", idx);
	}
	
err:
	errprnt;
	return r_rv;
}

udrstatic int _udr_xel_route_tnl_ondel(void* hndl, int idx, void* data, int data_len)
{
	errinit;
	struct ip4_or_ip6_header_index_resp_type* tnl_entry = data;
	assrt(data_len == sizeof(struct ip4_or_ip6_header_index_resp_type));

	if(TUNNEL_ENTRY_TYPE_USE_HDIP6(tnl_entry->entry_type))
	{
		int hdip6src_ref, hdip6dst_ref;
		assrt(tnl_entry->ip6_src_ip_index);
		assrt(tnl_entry->ip6_dst_ip_index);
		hdip6src_ref = tnl_entry->ip6_src_ip_index;
		hdip6dst_ref = tnl_entry->ip6_dst_ip_index;
		rtdbgprint(RT_DBG_TNL, "IP6 Tunnel on delete: tnl_ref=0x%x, hdip6src_ref=0x%x, hdip6dst_ref=0x%x\n", idx, hdip6src_ref, hdip6dst_ref);
		r_rv = udr_xel_route_reftab_release_dir(0, "hdip6src", hdip6src_ref);
		if(r_rv)
			gerr;
		r_rv = udr_xel_route_reftab_release_dir(0, "hdip6dst", hdip6dst_ref);
		if(r_rv)
			gerr;
	}
	else
	{
		int hdip4_ref;
		assrt(tnl_entry->ip4_struct_index);
		hdip4_ref = tnl_entry->ip4_struct_index;
		rtdbgprint(RT_DBG_TNL, "IP4 Tunnel on delete: tnl_ref=0x%x, hdip4_ref=0x%x\n", idx, hdip4_ref);
		r_rv = udr_xel_route_reftab_release_dir(0, "hdip4", hdip4_ref);
		if(r_rv)
			gerr;
	}
	
err:
	errprnt;
	return r_rv;
}
/* egress released when ip del or add overwrite */
udrstatic int _udr_xel_route_ip_add_released_cbed(void* arg, int nexthop)
{
	int r_rv, rslt;
	
	if(nexthop & ECMP_NEXTHOP_FLAG)
	{
		/* ECMP */
		rtdbgprint(RT_DBG_ROUTE, "egress released when ip del or add overwrite: ecmp nexthop=0x%x(0x%x)\n", (nexthop&(~ECMP_NEXTHOP_FLAG)), nexthop);
		r_rv = udr_xel_route_reftab_release_dir(0, "ecmp", (nexthop&(~ECMP_NEXTHOP_FLAG)));
		if(r_rv)
			return -PMCL_ERR_INNER;
		
	}
	else
	{
		rtdbgprint(RT_DBG_ROUTE, "egress released when ip del or add overwrite: nexthop=0x%x\n", nexthop);
		r_rv = udr_xel_route_reftab_release_dir(0, "nexthop", nexthop);
		if(r_rv)
			return -PMCL_ERR_INNER;
	}
	
	return -PMCL_ERR_OK;
	
}

int udr_xel_route_route_set(udr_route_entry_t *route_entry, int nexthop)
{
	errinit;
	int rslt;
	int mask_len = 0;

	LOCK_IN(&_udr_xel_route_hndl);

	if(route_entry->family == UDR_TNL_FA4)
	{
		/* IPv4 set */
		while( (((route_entry->ipv4_mask)>>mask_len) & 1) == 0 && mask_len < 32)mask_len++;
		mask_len = 32 - mask_len;
		
		rtdbgprint(RT_DBG_ROUTE, "ipv4 route add: vrid=0x%x, ipv4_addr=0x%x, len=%d, nexthop=0x%x\n", route_entry->vrId, route_entry->ipv4_addr, mask_len, nexthop);
		rslt = pmcl_xel_add_ipv4_hook(route_entry->vrId, route_entry->ipv4_addr, mask_len, nexthop, _udr_xel_route_ip_add_released_cbed, NULL);
		if(rslt < 0)
			gerrv(UDR_API_E_INTERNAL);
	}
	else if(route_entry->family == UDR_TNL_FA6)
	{
		/* IPv6 set */
		rtdbgprint(RT_DBG_ROUTE,
			"ipv6 route add: ipv6_addr=0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x, len=%d, nexthop=0x%x\n",
			route_entry->ipv6_addr[0], route_entry->ipv6_addr[1], route_entry->ipv6_addr[2], route_entry->ipv6_addr[3], 
			route_entry->ipv6_addr[4], route_entry->ipv6_addr[5], route_entry->ipv6_addr[6], route_entry->ipv6_addr[7], 
			route_entry->ipv6_addr[8], route_entry->ipv6_addr[9], route_entry->ipv6_addr[10], route_entry->ipv6_addr[11], 
			route_entry->ipv6_addr[12], route_entry->ipv6_addr[13], route_entry->ipv6_addr[14], route_entry->ipv6_addr[15], 
			route_entry->ipv6_mask_len, nexthop);
		rslt = pmcl_xel_add_ipv6_hook(route_entry->ipv6_addr, route_entry->ipv6_mask_len, nexthop, _udr_xel_route_ip_add_released_cbed, NULL);
		if(rslt < 0)
			gerrv(UDR_API_E_INTERNAL);
	}
	else
	{
		gerrp(UDR_API_E_PARAM, "route family should be UDR_TNL_FA4 or UDR_TNL_FA6.\n");
	}

err:
	LOCK_XOUT(&_udr_xel_route_hndl);
	errprnt;
	return r_rv;
}

int udr_xel_route_route_get(udr_route_entry_t *route_entry, int* pnexthop)
{
	errinit;
	int nexthop;
	int mask_len = 0;

	LOCK_IN(&_udr_xel_route_hndl);

	if(route_entry->family == UDR_TNL_FA4)
	{
		/* IPv4 get */
		while( (((route_entry->ipv4_mask)>>mask_len) & 1) == 0 && mask_len < 32)mask_len++;
		mask_len = 32 - mask_len;
		assrt(mask_len>0);
		
		nexthop = pmcl_xel_show_ipv4(route_entry->vrId, route_entry->ipv4_addr, mask_len);
		if(nexthop <= 0)
			gerrv(UDR_API_E_INTERNAL);
		rtdbgprint(RT_DBG_ROUTE, "ipv4 route get: vrid=0x%x, ipv4_addr=0x%x, len=%d, nexthop=0x%x\n", route_entry->vrId, route_entry->ipv4_addr, mask_len, nexthop);
	}
	else if(route_entry->family == UDR_TNL_FA6)
	{
		/* IPv6 get */
		nexthop = pmcl_xel_show_ipv6(route_entry->ipv6_addr, route_entry->ipv6_mask_len);
		if(nexthop <= 0)
			gerrv(UDR_API_E_INTERNAL);
		rtdbgprint(RT_DBG_ROUTE,
			"ipv6 route get: ipv6_addr=0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x, len=%d, nexthop=0x%x\n",
			route_entry->ipv6_addr[0], route_entry->ipv6_addr[1], route_entry->ipv6_addr[2], route_entry->ipv6_addr[3], 
			route_entry->ipv6_addr[4], route_entry->ipv6_addr[5], route_entry->ipv6_addr[6], route_entry->ipv6_addr[7], 
			route_entry->ipv6_addr[8], route_entry->ipv6_addr[9], route_entry->ipv6_addr[10], route_entry->ipv6_addr[11], 
			route_entry->ipv6_addr[12], route_entry->ipv6_addr[13], route_entry->ipv6_addr[14], route_entry->ipv6_addr[15], 
			route_entry->ipv6_mask_len, nexthop);
	}
	else
	{
		gerrp(UDR_API_E_PARAM, "route family should be UDR_TNL_FA4 or UDR_TNL_FA6.\n");
	}

	if(pnexthop)
		*pnexthop = nexthop;

err:
	LOCK_XOUT(&_udr_xel_route_hndl);
	errprnt;
	return r_rv;
}

int udr_xel_route_ext_route_reference(udr_route_entry_t *route_entry, int* pnexthop)
{
	errinit;
	int nexthop;
	int mask_len = 0;

	r_rv = udr_xel_route_route_get(route_entry, &nexthop);
	if(r_rv)
		gerr;

	LOCK_IN(&_udr_xel_route_hndl);

	if(nexthop & ECMP_NEXTHOP_FLAG)
	{
		/* ECMP */
		int ecmp = (nexthop & (~ECMP_NEXTHOP_FLAG));
		r_rv = _reftab_reference_dir(_udr_xel_route_hndl.ecmp_reftab, ecmp);
		if(r_rv)
			gerr;
	}
	else
	{
		assrt(nexthop > 0);
		r_rv = _reftab_reference_dir(_udr_xel_route_hndl.nexthop_reftab, nexthop);
		if(r_rv)
			gerr;
	}

	if(pnexthop)
		*pnexthop = nexthop;

err:
	LOCK_XOUT(&_udr_xel_route_hndl);
	errprnt;
	return r_rv;
}

int udr_xel_route_ext_route_release(int nexthop)
{
	errinit;
	int rslt;
	int mask_len = 0;

	LOCK_IN(&_udr_xel_route_hndl);

	if(nexthop & ECMP_NEXTHOP_FLAG)
	{
		/* ECMP */
		int ecmp = (nexthop & (~ECMP_NEXTHOP_FLAG));
		r_rv = _reftab_release_dir(_udr_xel_route_hndl.ecmp_reftab, ecmp);
		if(r_rv)
			gerr;
	}
	else
	{
		assrt(nexthop > 0);
		r_rv = _reftab_release_dir(_udr_xel_route_hndl.nexthop_reftab, nexthop);
		if(r_rv)
			gerr;
	}

err:
	LOCK_XOUT(&_udr_xel_route_hndl);
	errprnt;
	return r_rv;
}

int udr_xel_route_ip_add(int unit , udr_route_data_t  * entry)
{
	errinit;
	int nexthop = 0;
	udr_route_entry_t *route_entry = entry->l3_entry;
	udr_egress_entry_t *egress_entry = entry->egress;
	int egress_num = entry->egress_num;
	/*assrt(route_entry->ipv4_mask != 0);*/
    if(uspdebug_route)
    _xel_route_show_route_data(0, entry);
	if(route_entry->flags == UDR_ROUTE_FLAG_ARP) 
	{
		/* pass here */
	}
	else if(route_entry->flags == UDR_ROUTE_FLAG_CPU)
	{
		/* pass here */
	}
	else if(route_entry->flags == UDR_ROUTE_FLAG_ECMP)
	{
		/* pass here */
	}
	else if(route_entry->flags == UDR_ROUTE_FLAG_TUNNEL)
	{
		/* pass here */
	}
	else if(route_entry->flags)
	{
		gerrp(UDR_API_E_DISABLED, "flag %d is not implemented.\n", route_entry->flags);
	}
#if 0
	if(route_entry->family == UDR_TNL_FA6)
		gerrp(UDR_API_E_DISABLED, "IPv6 is not implemented.\n");
	if(route_entry->vrId != 0)
		gerrp(UDR_API_E_DISABLED, "VRF is not implemented.\n");
#endif

    /* ecmp */
	if(route_entry->flags == UDR_ROUTE_FLAG_ECMP)
	{
		assrt(egress_num>1);
		r_rv = udr_xel_route_ecmp_get_or_add(unit, egress_num, egress_entry, &nexthop);
		if(r_rv)
			gerr;
	}
    /* tunnel */
	else if(route_entry->flags == UDR_ROUTE_FLAG_TUNNEL)
	{
		/*assrt(route_entry->tunnel_idx);*/
		r_rv = udr_xel_route_nexthop_with_tnl_get_or_add(unit, route_entry->tunnel_idx, egress_entry, &nexthop);
		if(r_rv)
			gerr;
	}
    /* 普通路由 */
	else
	{
		r_rv = udr_xel_route_nexthop_get_or_add(unit, egress_entry, &nexthop);
		if(r_rv)
			gerr;
	}
    /* 返回下一跳索引供set使用 */
	r_rv = udr_xel_route_route_set(route_entry, nexthop);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}

int udr_xel_route_ip_del(int unit , udr_route_data_t  * entry)
{
	errinit;
	int rslt;
	int mask_len = 0;
	udr_route_entry_t *route_entry = entry->l3_entry;
	udr_egress_entry_t *egress_entry = entry->egress;
	int egress_num = entry->egress_num;

	LOCK_IN(&_udr_xel_route_hndl);

	if(route_entry->flags == UDR_ROUTE_FLAG_ARP) 
	{
		/*printf("ARP Flag, do nothing special.\n");*/
	}
	else if(route_entry->flags == UDR_ROUTE_FLAG_CPU)
	{
		/* pass here */
	}
	else if(route_entry->flags == UDR_ROUTE_FLAG_ECMP)
	{
		/* pass here */
	}
	else if(route_entry->flags == UDR_ROUTE_FLAG_TUNNEL)
	{
		/* pass here */
	}
	else if(route_entry->flags)
	{
		gerrp(UDR_API_E_DISABLED, "flag %d is not implemented.\n", route_entry->flags);
	}
#if 0
	if(route_entry->family == UDR_TNL_FA6)
		gerrp(UDR_API_E_DISABLED, "IPv6 is not implemented.\n");
	if(route_entry->vrId != 0)
		gerrp(UDR_API_E_DISABLED, "VRF is not implemented.\n");
#endif

#if 0
	r_rv = udr_xel_route_nexthop_release(unit, egress_entry);
	if(r_rv)
		gerr;
#endif

	if(route_entry->family == UDR_TNL_FA4)
	{
		assrt(route_entry->ipv4_mask != 0);
		while( (((route_entry->ipv4_mask)>>mask_len) & 1) == 0)mask_len++;
		mask_len = 32 - mask_len;
		rtdbgprint(RT_DBG_ROUTE, "ipv4 route del: vrid=0x%x, ipv4_addr=0x%x, len=%d\n", route_entry->vrId, route_entry->ipv4_addr, mask_len);
		rslt = pmcl_xel_del_ipv4(route_entry->vrId, route_entry->ipv4_addr, mask_len);
		if(rslt < -1)
			gerrv(UDR_API_E_INTERNAL);
	}
	else if(route_entry->family == UDR_TNL_FA6)
	{
		assrt(route_entry->ipv6_mask_len > 0);
		rtdbgprint(RT_DBG_ROUTE,
			"ipv6 route del: ipv6_addr=0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x, len=%d\n",
			route_entry->ipv6_addr[0], route_entry->ipv6_addr[1], route_entry->ipv6_addr[2], route_entry->ipv6_addr[3], 
			route_entry->ipv6_addr[4], route_entry->ipv6_addr[5], route_entry->ipv6_addr[6], route_entry->ipv6_addr[7], 
			route_entry->ipv6_addr[8], route_entry->ipv6_addr[9], route_entry->ipv6_addr[10], route_entry->ipv6_addr[11], 
			route_entry->ipv6_addr[12], route_entry->ipv6_addr[13], route_entry->ipv6_addr[14], route_entry->ipv6_addr[15], 
			route_entry->ipv6_mask_len);
		rslt = pmcl_xel_del_ipv6(route_entry->ipv6_addr, route_entry->ipv6_mask_len);
		if(rslt < -1)
			gerrv(UDR_API_E_INTERNAL);
	}
	else
	{
		gerrp(UDR_API_E_PARAM, "route family should be UDR_TNL_FA4 or UDR_TNL_FA6.\n");
	}

err:
	LOCK_XOUT(&_udr_xel_route_hndl);
	errprnt;
	return r_rv;
}

#if 1

int _xel_route_show_dasa(int dasa_ref)
{
	errinit;
	struct table_dasa_resp_type dasa_entry = {0};
	int refcnt;

	r_rv = _reftab_read_hw(_udr_xel_route_hndl.dasa_reftab->hwtab, dasa_ref, &dasa_entry, sizeof(struct table_dasa_resp_type));
	if(r_rv)
		gerr;

	r_rv = _reftab_refcnt(_udr_xel_route_hndl.dasa_reftab, dasa_ref, &refcnt);
	if(r_rv)
		gerr;
	
	printf("========================\n");
	printf("dasa 0x%x show: refcnt=%d\ntag_act=%d, vid=%d\nda=%02x:%02x:%02x:%02x:%02x:%02x\nsa=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dasa_ref, refcnt, dasa_entry.tag_act, dasa_entry.vid,
		dasa_entry.damac[0], dasa_entry.damac[1], dasa_entry.damac[2], dasa_entry.damac[3], dasa_entry.damac[4], dasa_entry.damac[5],
		dasa_entry.samac[0], dasa_entry.samac[1], dasa_entry.samac[2], dasa_entry.samac[3], dasa_entry.samac[4], dasa_entry.samac[5]);
	printf("========================\n");
	
err:
	errprnt;
	return r_rv;
}

int _xel_route_show_hdip6(int hdip6dst_ref, int hdip6src_ref)
{
	errinit;
	struct table_ipv6_header_resp_type hdip6_entry = {0};
	int refcnt;

	r_rv = _reftab_read_hw(_udr_xel_route_hndl.hdip6dst_reftab->hwtab, hdip6dst_ref, &hdip6_entry, sizeof(struct table_ipv6_header_resp_type));
	if(r_rv)
		gerr;

	r_rv = _reftab_refcnt(_udr_xel_route_hndl.hdip6dst_reftab, hdip6dst_ref, &refcnt);
	if(r_rv)
		gerr;
	
	printf("========================\n");
	printf("head ipv6 dst 0x%x show: refcnt=%d\nip=%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x\n",
		hdip6dst_ref, refcnt,
		hdip6_entry.ip[0], hdip6_entry.ip[1], hdip6_entry.ip[2], hdip6_entry.ip[3],
		hdip6_entry.ip[4], hdip6_entry.ip[5], hdip6_entry.ip[6], hdip6_entry.ip[7],
		hdip6_entry.ip[8], hdip6_entry.ip[9], hdip6_entry.ip[10], hdip6_entry.ip[11],
		hdip6_entry.ip[12], hdip6_entry.ip[13], hdip6_entry.ip[14], hdip6_entry.ip[15]);

	r_rv = _reftab_read_hw(_udr_xel_route_hndl.hdip6src_reftab->hwtab, hdip6src_ref, &hdip6_entry, sizeof(struct table_ipv6_header_resp_type));
	if(r_rv)
		gerr;

	r_rv = _reftab_refcnt(_udr_xel_route_hndl.hdip6src_reftab, hdip6src_ref, &refcnt);
	if(r_rv)
		gerr;
	
	printf("head ipv6 src 0x%x show: refcnt=%d\nip=%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x\n",
		hdip6src_ref, refcnt,
		hdip6_entry.ip[0], hdip6_entry.ip[1], hdip6_entry.ip[2], hdip6_entry.ip[3],
		hdip6_entry.ip[4], hdip6_entry.ip[5], hdip6_entry.ip[6], hdip6_entry.ip[7],
		hdip6_entry.ip[8], hdip6_entry.ip[9], hdip6_entry.ip[10], hdip6_entry.ip[11],
		hdip6_entry.ip[12], hdip6_entry.ip[13], hdip6_entry.ip[14], hdip6_entry.ip[15]);
	printf("========================\n");
	
err:
	errprnt;
	return r_rv;
}

int _xel_route_show_hdip4(int hdip4_ref)
{
	errinit;
	struct table_ipv4_header_resp_type hdip4_entry = {0};
	int refcnt;

	r_rv = _reftab_read_hw(_udr_xel_route_hndl.hdip4_reftab->hwtab, hdip4_ref, &hdip4_entry, sizeof(struct table_ipv4_header_resp_type));
	if(r_rv)
		gerr;

	r_rv = _reftab_refcnt(_udr_xel_route_hndl.hdip4_reftab, hdip4_ref, &refcnt);
	if(r_rv)
		gerr;
	
	printf("========================\n");
	printf("head ipv4 0x%x show: refcnt=%d\ndip=0x%08x\nsip=0x%08x\n",
		hdip4_ref, refcnt, hdip4_entry.dip, hdip4_entry.sip);
	printf("========================\n");
	
err:
	errprnt;
	return r_rv;
}

int _xel_route_show_tnl(int tnl_ref)
{
	errinit;
	struct ip4_or_ip6_header_index_resp_type tnl_entry = {0};
	int refcnt;

	r_rv = _reftab_read_hw(_udr_xel_route_hndl.tnl_reftab->hwtab, tnl_ref, &tnl_entry, sizeof(struct ip4_or_ip6_header_index_resp_type));
	if(r_rv)
		gerr;

	r_rv = _reftab_refcnt(_udr_xel_route_hndl.tnl_reftab, tnl_ref, &refcnt);
	if(r_rv)
		gerr;
	
	printf("========================\n");
	printf("tunnel 0x%x show: refcnt=%d\nentry_type=0x%x\n",
		tnl_ref, refcnt, tnl_entry.entry_type);
	if(tnl_entry.ttl_dscp_config_bit)
	{
		printf("ttl=%d, dscp=0x%x\n", tnl_entry.ttl, tnl_entry.dscp);
	}
	printf("========================\n");

	if(TUNNEL_ENTRY_TYPE_USE_HDIP6(tnl_entry.entry_type))
	{
		int hdip6dst_ref, hdip6src_ref;
		assrt(tnl_entry.ip6_dst_ip_index);
		assrt(tnl_entry.ip6_src_ip_index);
		hdip6dst_ref = tnl_entry.ip6_dst_ip_index;
		hdip6src_ref = tnl_entry.ip6_src_ip_index;
		r_rv = _xel_route_show_hdip6(hdip6dst_ref, hdip6src_ref);
		if(r_rv)
			gerr;
	}
	else
	{
		int hdip4_ref;
		assrt(tnl_entry.ip4_struct_index);
		hdip4_ref = tnl_entry.ip4_struct_index;
		r_rv = _xel_route_show_hdip4(hdip4_ref);
		if(r_rv)
			gerr;
	}
	
err:
	errprnt;
	return r_rv;
}

int _xel_route_show_nexthop(int nh_ref)
{
	errinit;
	struct ip_next_hop_resp nh_entry = {0};
	int refcnt;

	r_rv = _reftab_read_hw(_udr_xel_route_hndl.nexthop_reftab->hwtab, nh_ref, &nh_entry, sizeof(struct ip_next_hop_resp));
	if(r_rv)
		gerr;

	r_rv = _reftab_refcnt(_udr_xel_route_hndl.nexthop_reftab, nh_ref, &refcnt);
	if(r_rv)
		gerr;

	printf("========================\n");
	printf("nexthop 0x%x show: refcnt=%d\nentry_type=%d, port_type=%d, cpu_flag=%d\nmod_id=%d, dest_id=%d\nl3_mac_index=0x%x\ndst_ip=%d.%d.%d.%d\n",
		nh_ref, refcnt, nh_entry.entry_type, nh_entry.port_type, nh_entry.cpu_flag, nh_entry.mod_id, nh_entry.dest_id, nh_entry.l3_mac_index,
		nh_entry.dst_ip[0], nh_entry.dst_ip[1], nh_entry.dst_ip[2], nh_entry.dst_ip[3]);
	printf("========================\n");

	if(nh_entry.entry_type == L3_NORMAL_FORWARD)
	{
		int dasa_ref;
		dasa_ref = nh_entry.l3_mac_index;
		r_rv = _xel_route_show_dasa(dasa_ref);
		if(r_rv)
			gerr;
	}
	else if(nh_entry.entry_type == IP_TUNNEL)
	{
		int dasa_ref, tnl_ref;
		dasa_ref = nh_entry.l3_mac_index;
		r_rv = _xel_route_show_dasa(dasa_ref);
		if(r_rv)
			gerr;
		tnl_ref = nh_entry.l3_vpn_init_label_index_ipv4_tunnel_index;
		r_rv = _xel_route_show_tnl(tnl_ref);
		if(r_rv)
			gerr;
	}
	else
	{
		gerrp(UDR_API_E_INTERNAL, "Unsupported egress entry_type %d.\n", nh_entry.entry_type);
	}
	
err:
	errprnt;
	return r_rv;
}

int _xel_route_show_ecmp(int nh_ref)
{
	errinit;
	int i;
	int ecmp_ref = (nh_ref & (~ECMP_NEXTHOP_FLAG));
	struct ecmp_entry_type ecmp_entry = {0};
	int nh_num;
	int nh_grp[ECMP_MEMBER_MAX] = {0};
	int refcnt;
	assrt(nh_ref & ECMP_NEXTHOP_FLAG);

	r_rv = _reftab_read_hw(_udr_xel_route_hndl.ecmp_reftab->hwtab, ecmp_ref, &ecmp_entry, sizeof(struct ecmp_entry_type));
	if(r_rv)
		gerr;
    /* 判断ecmp被引用的计数 */
	r_rv = _reftab_refcnt(_udr_xel_route_hndl.ecmp_reftab, ecmp_ref, &refcnt);
	if(r_rv)
		gerr;

	r_rv = _udr_convert_ecmp_to_egr(&ecmp_entry, &nh_num, nh_grp);
	if(r_rv)
		gerr;

	printf("*******************************\n");
	printf("ecmp nexthop 0x%x(0x%x) show: nh_num=%d, refcnt=%d\n",
		ecmp_ref, nh_ref, nh_num, refcnt);
	
	for(i=0; i<nh_num; i++)
	{
		r_rv = _xel_route_show_nexthop(nh_grp[i]);
		if(r_rv)
			gerr;
	}
	printf("*******************************\n");

err:
	errprnt;
	return r_rv;
}


int _xel_route_ipv4_show(int vrf, uint32_t ip_addr, int ip_len)
{
	errinit;
	int nh_ref;

	nh_ref = pmcl_xel_show_ipv4(vrf, ip_addr, ip_len);
	if(nh_ref & ECMP_NEXTHOP_FLAG)
	{
		/* ECMP */
		r_rv = _xel_route_show_ecmp(nh_ref);
		if(r_rv)
			gerr;
	}
	else if(nh_ref == 0)
	{
		assrt(ip_len == 0);
		goto fin;
	}
	else
	{
		r_rv = _xel_route_show_nexthop(nh_ref);
		if(r_rv)
			gerr;
	}
	
fin:
err:
	errprnt;
	return r_rv;
}

int _xel_route_ipv6_show(int vrf, uint8_t* ip_addr_buf, int ip_len)
{
	errinit;
	int nh_ref;

	nh_ref = pmcl_xel_show_ipv6(ip_addr_buf, ip_len);
	if(nh_ref & ECMP_NEXTHOP_FLAG)
	{
		/* ECMP */
		r_rv = _xel_route_show_ecmp(nh_ref);
		if(r_rv)
			gerr;
	}
	else if(nh_ref == 0)
	{
		assrt(ip_len == 0);
		goto fin;
	}
	else
	{
		r_rv = _xel_route_show_nexthop(nh_ref);
		if(r_rv)
			gerr;
	}
	
fin:
err:
	errprnt;
	return r_rv;
}

int _xel_route_show_route_data(int unit, udr_route_data_t *pdata)
{
    errinit;
    int idx = 0;
    udr_route_entry_t* route_entry = pdata->l3_entry;
    int mask_len = 0;
    udr_egress_entry_t * egress_entry = pdata->egress;
    rtdbgprint(RT_DBG_ROUTE, "the route flag : 0x%x\n", route_entry->flags);
	if(route_entry->family == UDR_TNL_FA4)
	{
		/* IPv4 get */
		while( (((route_entry->ipv4_mask)>>mask_len) & 1) == 0 && mask_len < 32)
          mask_len++;
		mask_len = 32 - mask_len;
		assrt(mask_len>0);
		rtdbgprint(RT_DBG_ROUTE, "ipv4 route show: vrid=0x%x, ipv4_addr=0x%x, len=%d\n", route_entry->vrId, route_entry->ipv4_addr, mask_len);
	}
	else if(route_entry->family == UDR_TNL_FA6)
	{
		/* IPv6 get */
		rtdbgprint(RT_DBG_ROUTE,
			"ipv6 route show: ipv6_addr=0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x, len=%d\n",
			route_entry->ipv6_addr[0], route_entry->ipv6_addr[1], route_entry->ipv6_addr[2], route_entry->ipv6_addr[3], 
			route_entry->ipv6_addr[4], route_entry->ipv6_addr[5], route_entry->ipv6_addr[6], route_entry->ipv6_addr[7], 
			route_entry->ipv6_addr[8], route_entry->ipv6_addr[9], route_entry->ipv6_addr[10], route_entry->ipv6_addr[11], 
			route_entry->ipv6_addr[12], route_entry->ipv6_addr[13], route_entry->ipv6_addr[14], route_entry->ipv6_addr[15], 
			route_entry->ipv6_mask_len);
	}
	else
	{
		gerrp(UDR_API_E_PARAM, "route family should be UDR_TNL_FA4 or UDR_TNL_FA6.\n");
	}

    for(idx=0; idx < pdata->egress_num; idx++)
    {
        rtdbgprint(RT_DBG_ROUTE,"egress[%d]-->flags: 0x%x, modid: %d, port: %d, vid: %d, op: %d, dst_mac: %3x:%3x:%3x:%3x:%3x:%3x\n",
                   idx, egress_entry->flags, egress_entry->modid, egress_entry->port, egress_entry->vid, egress_entry->op,
                   egress_entry->dst_mac[0], egress_entry->dst_mac[1], egress_entry->dst_mac[2], egress_entry->dst_mac[3],
                   egress_entry->dst_mac[4], egress_entry->dst_mac[5]);
        egress_entry ++;
    }
err:
	errprnt;
	return r_rv;
}

#endif

typedef int (*udr_route_module )(int unit , udr_route_data_t  * entry);

udr_route_module xel_route_module[][ROUTE_SET_MAX] =
{
	{udr_xel_route_ip_del, udr_xel_route_ip_add},
	{udr_xel_route_ip_del ,udr_xel_route_ip_add},
	{udr_xel_route_ip_add ,udr_xel_route_ip_add}
};


/****************** private / public ********************/


/*!
	\brief 
	
	\param[in] unit - 
	\param[in] index - 
	\return 

	\note
		
*/

int udr_xel_l3_tnl_destroy(int unit, int index)
{
	errinit;
	r_rv = _udr_tnlterm_del(unit, index);
	if(r_rv)
		gerr;
	r_rv = _udr_tnlbuf_del(unit, index);
	if(r_rv)
		gerr;
err:
	errprnt;
	return r_rv;
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] index - 
	\param[in] family - 
	\return 

	\note
		
*/

int udr_xel_l3_tnl_intf_set(int unit, int index, uint8_t family)
{
	/*##__PORTMAKER__##udr_xel_l3_tnl_intf_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_l3_tnl_intf_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] tnl_index - 
	\param[in] family - 
	\return 

	\note
		
*/

int udr_xel_l3_tnl_param_family_set(int unit, int tnl_index, uint32_t family)
{
	errinit;
	struct tnlbuf_info* tnlbuf;
	char keybuf_6[TNL_TERM_6_KEYBUF_SIZE] = {0};
	char maskbuf_6[TNL_TERM_6_KEYBUF_SIZE] = {0};
	char databuf_6[TNL_TERM_6_DATABUF_SIZE] = {0};
    char keybuf_4[TNL_TERM_4_KEYBUF_SIZE] = {0};
	char maskbuf_4[TNL_TERM_4_KEYBUF_SIZE] = {0};
	char databuf_4[TNL_TERM_4_DATABUF_SIZE] = {0};
#ifdef TNL_PARAM_PASS_NULL
	if(family == 0)
		gerrv(UDR_API_E_NONE);
#endif /* TNL_PARAM_PASS_NULL */

	tnlbuf = _udr_tnlbuf_get(unit, tnl_index);
	if(!tnlbuf)
	{
		gerrv(UDR_API_E_INTERNAL);
	}
	/*assrt(tnlbuf->status < TNLBUF_STATUS_HW_SET);*/
    if(tnlbuf->sw_type.family != family)
    {
        /* 地址簇变化 */
    	if(TUNNEL_ENTRY_TYPE_USE_HDIP6(tnlbuf->comm_info.entry_type))
    	{
    	    r_rv = pmcl_xel_write_tcam(TNL_TERM_6_ENGINE, TNL_TERM_6_TBL,
    		                       tnl_index, keybuf_6, maskbuf_6, databuf_6, 1);
    		if(r_rv)
    			gerr;
    	}
    	else
    	{
    	    r_rv = pmcl_xel_write_tcam(TNL_TERM_4_ENGINE, TNL_TERM_4_TBL,
    		                       tnl_index, keybuf_4, maskbuf_4, databuf_4, 1);
    		if(r_rv)
    			gerr;
    	}
    }
    
	tnlbuf->sw_type.family = family;
	tnlbuf->sw_type.dirty.family = 1;
	if(tnlbuf->sw_type.dirty.type)
	{
		int tnltp;
		r_rv = _udr_convert_tnltp(&tnlbuf->sw_type, &tnltp);
		if(r_rv)
			gerr;
		_bitfield_set_save(tnlbuf->comm_info.entry_type, tnltp, 3);
		tnlbuf->dirty.type = 1;
	}
	tnlbuf->status = TNLBUF_STATUS_SW_SET;

	r_rv = _udr_tnlterm_auto_set(unit, tnl_index);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] tnl_index - 
	\param[in] type - 
	\return 

	\note
		
*/

int udr_xel_l3_tnl_param_type_set(int unit, int tnl_index, uint32_t type)
{
	errinit;
	struct tnlbuf_info* tnlbuf;
	char keybuf_6[TNL_TERM_6_KEYBUF_SIZE] = {0};
	char maskbuf_6[TNL_TERM_6_KEYBUF_SIZE] = {0};
	char databuf_6[TNL_TERM_6_DATABUF_SIZE] = {0};
    char keybuf_4[TNL_TERM_4_KEYBUF_SIZE] = {0};
	char maskbuf_4[TNL_TERM_4_KEYBUF_SIZE] = {0};
	char databuf_4[TNL_TERM_4_DATABUF_SIZE] = {0};

#ifdef TNL_PARAM_PASS_NULL
	if(type == 0)
		gerrv(UDR_API_E_NONE);
#endif /* TNL_PARAM_PASS_NULL */

	tnlbuf = _udr_tnlbuf_get(unit, tnl_index);
	if(!tnlbuf)
	{
		gerrv(UDR_API_E_INTERNAL);
	}
	/*assrt(tnlbuf->status < TNLBUF_STATUS_HW_SET);*/
    /* 类型变化(gre->ipinip) */

    if(tnlbuf->sw_type.type != type)
    {
        /* 地址簇变化 */
    	if(TUNNEL_ENTRY_TYPE_USE_HDIP6(tnlbuf->comm_info.entry_type))
    	{
    	    r_rv = pmcl_xel_write_tcam(TNL_TERM_6_ENGINE, TNL_TERM_6_TBL,
    		                       tnl_index, keybuf_6, maskbuf_6, databuf_6, 1);
    		if(r_rv)
    			gerr;
    	}
    	else
    	{
    	    r_rv = pmcl_xel_write_tcam(TNL_TERM_4_ENGINE, TNL_TERM_4_TBL,
    		                       tnl_index, keybuf_4, maskbuf_4, databuf_4, 1);
    		if(r_rv)
    			gerr;
    	}
    }


    
	tnlbuf->sw_type.type = type;
	tnlbuf->sw_type.dirty.type = 1;
	if(tnlbuf->sw_type.dirty.family)
	{
		int tnltp;
		r_rv = _udr_convert_tnltp(&tnlbuf->sw_type, &tnltp);
		if(r_rv)
			gerr;
		_bitfield_set_save(tnlbuf->comm_info.entry_type, tnltp, 3);
		tnlbuf->dirty.type = 1;
	}
	tnlbuf->status = TNLBUF_STATUS_SW_SET;

	r_rv = _udr_tnlterm_auto_set(unit, tnl_index);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] modid - 
	\param[in] remote - 
	\param[in] slot - 
	\return 

	\note
		
*/

int udr_xel_modid_to_slot_get(int unit, int modid, int remote, int *slot)
{
	/*##__PORTMAKER__##udr_xel_modid_to_slot_get##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_modid_to_slot_get is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] addr - 
	\param[in] index - 
	\return 

	\note
		
*/

int udr_xel_route_6rd_braddr_set(int unit, uint32_t addr, int index)
{
	/*##__PORTMAKER__##udr_xel_route_6rd_braddr_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_6rd_braddr_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] addr - 
	\param[in] index - 
	\return 

	\note
		
*/

int udr_xel_route_6rd_domain_addr_set(int unit, uint8_t * addr, int index)
{
	/*##__PORTMAKER__##udr_xel_route_6rd_domain_addr_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_6rd_domain_addr_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] prex_len - 
	\param[in] index - 
	\return 

	\note
		
*/

int udr_xel_route_6rd_ip4prex_set(int unit, int prex_len, int index)
{
	/*##__PORTMAKER__##udr_xel_route_6rd_ip4prex_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_6rd_ip4prex_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] prex_len - 
	\param[in] index - 
	\return 

	\note
		
*/

int udr_xel_route_6rd_ip6prex_set(int unit, int prex_len, int index)
{
	/*##__PORTMAKER__##udr_xel_route_6rd_ip6prex_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_6rd_ip6prex_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\return 

	\note
		
*/

int udr_xel_route_close(int unit)
{
	errinit;

	r_rv = _reftab_free(_udr_xel_route_hndl.dasa_reftab);
	if(r_rv)
		gerr;
	r_rv = _reftab_free(_udr_xel_route_hndl.nexthop_reftab);
	if(r_rv)
		gerr;
	r_rv = _reftab_free(_udr_xel_route_hndl.ecmp_reftab);
	if(r_rv)
		gerr;
	r_rv = _reftab_free(_udr_xel_route_hndl.vp_reftab);
	if(r_rv)
		gerr;
	r_rv = _reftab_free(_udr_xel_route_hndl.tnl_reftab);
	if(r_rv)
		gerr;
	r_rv = _reftab_free(_udr_xel_route_hndl.hdip4_reftab);
	if(r_rv)
		gerr;
	r_rv = _reftab_free(_udr_xel_route_hndl.hdip6src_reftab);
	if(r_rv)
		gerr;
	r_rv = _reftab_free(_udr_xel_route_hndl.hdip6dst_reftab);
	if(r_rv)
		gerr;
	LOCK_FREE(&_udr_xel_route_hndl);
	
err:
	errprnt;
	return r_rv;
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] info - 
	\return 

	\note
		
*/

int udr_xel_route_count_info_get(int unit, _route_info_t *info)
{
	/*##__PORTMAKER__##udr_xel_route_count_info_get##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_count_info_get is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\return 

	\note
		
*/

int udr_xel_route_get_cmic(int unit)
{
	/*##__PORTMAKER__##udr_xel_route_get_cmic##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_get_cmic is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\return 

	\note
		
*/

int udr_xel_route_get_defip_feature(int unit)
{
	/*##__PORTMAKER__##udr_xel_route_get_defip_feature##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_get_defip_feature is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] MacAddr - 
	\return 

	\note
		
*/

int udr_xel_route_get_system_mac(int unit, unsigned char *MacAddr)
{
	/*##__PORTMAKER__##udr_xel_route_get_system_mac##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_get_system_mac is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] info - 
	\return 

	\note
		
*/

int udr_xel_route_info_get(int unit, _udr_basic_info_t * info)
{
	/*##__PORTMAKER__##udr_xel_route_info_get##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_info_get is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\return 

	\note
		
*/

int udr_xel_route_init_post(int unit)
{
    int ret;
	errinit;

	printf("udr_xel_route_init_post is called\n\r");
    /* 均为hash表,最后一个参数为func_del */
	r_rv = _reftab_init(&_udr_xel_route_hndl.dasa_reftab, sizeof(struct table_dasa_resp_type), DASA_HW_TAB_SIZE, &dasa_hw_info, NULL);
	if(r_rv)
		gerr;
	r_rv = _reftab_init(&_udr_xel_route_hndl.nexthop_reftab, sizeof(struct ip_next_hop_resp), NH_HW_TAB_SIZE, &nh_hw_info, _udr_xel_route_nexthop_ondel);
	if(r_rv)
		gerr;
	r_rv = _reftab_init(&_udr_xel_route_hndl.ecmp_reftab, sizeof(struct ecmp_entry_type), ECMP_HW_TAB_SIZE, &ecmp_hw_info, _udr_xel_route_ecmp_ondel);
	if(r_rv)
		gerr;
	r_rv = _reftab_init(&_udr_xel_route_hndl.vp_reftab, sizeof(struct table_vp_resp_type), VP_HW_TAB_SIZE, &vp_hw_info, _udr_xel_route_vp_ondel);
	if(r_rv)
		gerr;
    /* tnl = tunnel */
	r_rv = _reftab_init(&_udr_xel_route_hndl.tnl_reftab, sizeof(struct ip4_or_ip6_header_index_resp_type), TNL_HW_TAB_SIZE, &tnl_hw_info, _udr_xel_route_tnl_ondel);
	if(r_rv)
		gerr;
	r_rv = _reftab_init(&_udr_xel_route_hndl.hdip4_reftab, sizeof(struct table_ipv4_header_resp_type), HDIP4_HW_TAB_SIZE, &hdip4_hw_info, NULL);
	if(r_rv)
		gerr;
	r_rv = _reftab_init(&_udr_xel_route_hndl.hdip6src_reftab, sizeof(struct table_ipv6_header_resp_type), HDIP6_HW_TAB_SIZE, &hdip6src_hw_info, NULL);
	if(r_rv)
		gerr;
	r_rv = _reftab_init(&_udr_xel_route_hndl.hdip6dst_reftab, sizeof(struct table_ipv6_header_resp_type), HDIP6_HW_TAB_SIZE, &hdip6dst_hw_info, NULL);
	if(r_rv)
		gerr;
	LOCK_INIT(&_udr_xel_route_hndl);
#if 0
 	if(ret = udr_xel_pkt_recv_register_reason(0, udr_xel_route_frr_cpu_handle, 10))
 	{
        r_rv = ret;
        printf("\n the frr handle register failed!\n");
        goto err;
 	}
#endif
    
	printf("udr_xel_route_init_post is end\n\r");
err:
	errprnt;
	return r_rv;
}

/*!
	\brief 
	
	\param[in] unit - 
	\return 

	\note
		
*/

int udr_xel_route_init_pre(int unit)
{
	/*##__PORTMAKER__##udr_xel_route_init_pre##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_init_pre is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] ip_mask - 
	\param[in] in_port - 
	\param[in] pmac_addr - 
	\param[in] vlan_id - 
	\param[in] pnext_hop_mac - 
	\param[in] modid - 
	\param[in] api_flag - 
	\param[in] vrf_id - 
	\param[in] action - 
	\return 

	\note
		
*/

int udr_xel_route_ipv4_ecmp_route_set(int unit, unsigned int ip_addr, unsigned int ip_mask, int in_port, uint8_t *pmac_addr, int vlan_id, uint8_t *pnext_hop_mac, int modid, int api_flag, int vrf_id, int action)
{
	/*##__PORTMAKER__##udr_xel_route_ipv4_ecmp_route_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv4_ecmp_route_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] vrf_id - 
	\param[in] hit - 
	\return 

	\note
		
*/

int udr_xel_route_ipv4_host_hit_get(int unit, unsigned int ip_addr, int vrf_id, int * hit)
{
	/*##__PORTMAKER__##udr_xel_route_ipv4_host_hit_get##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv4_host_hit_get is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] vrf_id - 
	\return 

	\note
		
*/

int udr_xel_route_ipv4_host_hit_set(int unit, unsigned int ip_addr, int vrf_id)
{
	/*##__PORTMAKER__##udr_xel_route_ipv4_host_hit_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv4_host_hit_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] in_port - 
	\param[in] pmac_addr - 
	\param[in] vlan_id - 
	\param[in] pnext_hop_mac - 
	\param[in] modid - 
	\param[in] api_flag - 
	\param[in] vrf_id - 
	\param[in] action - 
	\return 

	\note
		
*/

int udr_xel_route_ipv4_host_set(int unit, unsigned int ip_addr, int in_port, uint8_t * pmac_addr, int vlan_id, uint8_t * pnext_hop_mac, int modid, int api_flag, int vrf_id, int action)
{
	/*##__PORTMAKER__##udr_xel_route_ipv4_host_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv4_host_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_info - 
	\return 

	\note
		
*/

int udr_xel_route_ipv4_reverse_mcsu(int unit, UDR_IP_INFO_S * ip_info)
{
	/*##__PORTMAKER__##udr_xel_route_ipv4_reverse_mcsu##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv4_reverse_mcsu is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] ip_mask - 
	\param[in] vrf_id - 
	\param[in] hit - 
	\return 

	\note
		
*/

int udr_xel_route_ipv4_route_hit_get(int unit, unsigned int ip_addr, unsigned int ip_mask, int vrf_id, int * hit)
{
	/*##__PORTMAKER__##udr_xel_route_ipv4_route_hit_get##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv4_route_hit_get is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] ip_mask - 
	\param[in] vrf_id - 
	\return 

	\note
		
*/

int udr_xel_route_ipv4_route_hit_set(int unit, unsigned int ip_addr, unsigned int ip_mask, int vrf_id)
{
	/*##__PORTMAKER__##udr_xel_route_ipv4_route_hit_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv4_route_hit_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] ip_mask - 
	\param[in] in_port - 
	\param[in] pmac_addr - 
	\param[in] vlan_id - 
	\param[in] pnext_hop_mac - 
	\param[in] modid - 
	\param[in] api_flag - 
	\param[in] vrf_id - 
	\param[in] action - 
	\return 

	\note
		
*/

int udr_xel_route_ipv4_route_set(int unit, unsigned int ip_addr, unsigned int ip_mask, int in_port, uint8_t *pmac_addr, int vlan_id, uint8_t *pnext_hop_mac, int modid, int api_flag, int vrf_id, int action)
{
	/*##__PORTMAKER__##udr_xel_route_ipv4_route_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv4_route_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ipv6_addr - 
	\param[in] ipv6_mask_len - 
	\param[in] in_port - 
	\param[in] pmac_addr - 
	\param[in] vlan_id - 
	\param[in] pnext_hop_mac - 
	\param[in] modid - 
	\param[in] api_flag - 
	\param[in] vrf_id - 
	\param[in] action - 
	\return 

	\note
		
*/

int udr_xel_route_ipv6_ecmp_route_set(int unit, unsigned char* ipv6_addr, int ipv6_mask_len, int in_port, uint8_t* pmac_addr, int vlan_id, uint8_t* pnext_hop_mac, int modid, int api_flag, int vrf_id, int action)
{
	/*##__PORTMAKER__##udr_xel_route_ipv6_ecmp_route_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv6_ecmp_route_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] vrf_id - 
	\param[in] hit - 
	\return 

	\note
		
*/

int udr_xel_route_ipv6_host_hit_get(int unit, unsigned char * ip_addr, int vrf_id, int * hit)
{
	/*##__PORTMAKER__##udr_xel_route_ipv6_host_hit_get##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv6_host_hit_get is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_addr - 
	\param[in] vrf_id - 
	\return 

	\note
		
*/

int udr_xel_route_ipv6_host_hit_set(int unit, unsigned char * ip_addr, int vrf_id)
{
	/*##__PORTMAKER__##udr_xel_route_ipv6_host_hit_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv6_host_hit_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ipv6_addr - 
	\param[in] in_port - 
	\param[in] pmac_addr - 
	\param[in] vlan_id - 
	\param[in] pnext_hop_mac - 
	\param[in] modid - 
	\param[in] api_flag - 
	\param[in] vrf_id - 
	\param[in] action - 
	\return 

	\note
		
*/

int udr_xel_route_ipv6_host_set(int unit, unsigned char* ipv6_addr, int in_port, uint8_t *pmac_addr, int vlan_id, uint8_t *pnext_hop_mac, int modid, int api_flag, int vrf_id, int action)
{
	/*##__PORTMAKER__##udr_xel_route_ipv6_host_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv6_host_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ip_info - 
	\return 

	\note
		
*/

int udr_xel_route_ipv6_reverse_mcsu(int unit, UDR_IP_INFO_S * ip_info)
{
	/*##__PORTMAKER__##udr_xel_route_ipv6_reverse_mcsu##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv6_reverse_mcsu is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ipv6_addr - 
	\param[in] mask_length - 
	\param[in] vrf_id - 
	\param[in] ipv6_hit - 
	\return 

	\note
		
*/

int udr_xel_route_ipv6_route_hit_get(int unit, unsigned char* ipv6_addr, int mask_length, int vrf_id, int* ipv6_hit)
{
	/*##__PORTMAKER__##udr_xel_route_ipv6_route_hit_get##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv6_route_hit_get is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ipv6_addr - 
	\param[in] mask_length - 
	\param[in] vrf_id - 
	\return 

	\note
		
*/

int udr_xel_route_ipv6_route_hit_set(int unit, unsigned char* ipv6_addr, int mask_length, int vrf_id)
{
	/*##__PORTMAKER__##udr_xel_route_ipv6_route_hit_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv6_route_hit_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] ipv6_addr - 
	\param[in] ipv6_mask_len - 
	\param[in] in_port - 
	\param[in] pmac_addr - 
	\param[in] vlan_id - 
	\param[in] pnext_hop_mac - 
	\param[in] modid - 
	\param[in] api_flag - 
	\param[in] vrf_id - 
	\param[in] action - 
	\return 

	\note
		
*/

int udr_xel_route_ipv6_route_set(int unit, unsigned char* ipv6_addr, int ipv6_mask_len, int in_port, uint8_t* pmac_addr, int vlan_id, uint8_t* pnext_hop_mac, int modid, int api_flag, int vrf_id, int action)
{
	/*##__PORTMAKER__##udr_xel_route_ipv6_route_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_ipv6_route_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] enable - 
	\return 

	\note
		
*/

int udr_xel_route_l3mtu_cpu_enable(int unit, int enable)
{
	/*##__PORTMAKER__##udr_xel_route_l3mtu_cpu_enable##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_l3mtu_cpu_enable is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] entry - 
	\param[in] action - 
	\param[in] cmd - 
	\return 

	\note
		
*/

int udr_xel_route_module_handle(int unit, udr_route_data_t * entry, int action, int cmd)
{
	if(xel_route_module[cmd][action])
		return xel_route_module[cmd][action](unit,entry);
	else
		return UDR_API_E_DISABLED;
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] index - 
	\param[in] val - 
	\return 

	\note
		
*/

int udr_xel_route_tnl_param_dst_set(int unit, int index, uint8_t *val)
{
	errinit;
	struct tnlbuf_info* tnlbuf;

	tnlbuf = _udr_tnlbuf_get(unit, index);
	if(!tnlbuf)
	{
		gerrv(UDR_API_E_INTERNAL);
	}
	/*assrt(tnlbuf->status < TNLBUF_STATUS_HW_SET);*/

	assrt(tnlbuf->sw_type.dirty.family);
	if(tnlbuf->sw_type.family == UDR_TNL_FA4)
	{
		int ipaddr = (val[0]<<24) + (val[1]<<16) + (val[2]<<8) + val[3];
#ifdef TNL_PARAM_PASS_NULL
		if(ipaddr == 0)
			gerrv(UDR_API_E_NONE);
#endif /* TNL_PARAM_PASS_NULL */
		tnlbuf->ipv4_info.dip = ipaddr;
		tnlbuf->dirty.dip4 = 1;
	}
	else if(tnlbuf->sw_type.family == UDR_TNL_FA6)
	{
		int i;
#ifdef TNL_PARAM_PASS_NULL
		for(i=0; i<16; i++)
		{
			if(val[i] != 0)
				break;
		}
		if(i>=16)
			gerrv(UDR_API_E_NONE);
#endif /* TNL_PARAM_PASS_NULL */
		for(i=0; i<16; i++)
		{
			tnlbuf->ipv6_dst_info.ip[i] = val[i];
		}
		tnlbuf->dirty.dip6 = 1;
	}
	else
		gerrp(UDR_API_E_PARAM, "Unsupported tunnel family %d.\n", tnlbuf->sw_type.family);

	tnlbuf->status = TNLBUF_STATUS_SW_SET;

	r_rv = _udr_tnlterm_auto_set(unit, index);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] index - 
	\param[in] val - 
	\return 

	\note
		
*/

int udr_xel_route_tnl_param_src_set(int unit, int index, uint8_t *val)
{
	errinit;
	struct tnlbuf_info* tnlbuf;

	tnlbuf = _udr_tnlbuf_get(unit, index);
	if(!tnlbuf)
	{
		gerrv(UDR_API_E_INTERNAL);
	}
	/*assrt(tnlbuf->status < TNLBUF_STATUS_HW_SET);*/

	assrt(tnlbuf->sw_type.dirty.family);
	if(tnlbuf->sw_type.family == UDR_TNL_FA4)
	{
		int ipaddr = (val[0]<<24) + (val[1]<<16) + (val[2]<<8) + val[3];
#ifdef TNL_PARAM_PASS_NULL
		if(ipaddr == 0)
			gerr;
#endif /* TNL_PARAM_PASS_NULL */
		tnlbuf->ipv4_info.sip = ipaddr;
		tnlbuf->dirty.sip4 = 1;
	}
	else if(tnlbuf->sw_type.family == UDR_TNL_FA6)
	{
		int i;
#ifdef TNL_PARAM_PASS_NULL
		for(i=0; i<16; i++)
		{
			if(val[i] != 0)
				break;
		}
		if(i>=16)
			gerr;
#endif /* TNL_PARAM_PASS_NULL */
		for(i=0; i<16; i++)
		{
			tnlbuf->ipv6_src_info.ip[i] = val[i];
		}
		tnlbuf->dirty.sip6 = 1;
	}
	else
		gerrp(UDR_API_E_PARAM, "Unsupported tunnel family %d.\n", tnlbuf->sw_type.family);

	tnlbuf->status = TNLBUF_STATUS_SW_SET;

	r_rv = _udr_tnlterm_auto_set(unit, index);
	if(r_rv)
		gerr;

err:
	errprnt;
	return r_rv;
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] status - 
	\return 

	\note
		
*/

int udr_xel_route_urpf_en_set(int unit, int status)
{
	/*##__PORTMAKER__##udr_xel_route_urpf_en_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_urpf_en_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] port - 
	\param[in] enable - 
	\return 

	\note
		
*/

int udr_xel_route_urpf_lpm_set(int unit, int port, int enable)
{
	/*##__PORTMAKER__##udr_xel_route_urpf_lpm_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_urpf_lpm_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

/*!
	\brief 
	
	\param[in] unit - 
	\param[in] port - 
	\param[in] mode - 
	\return 

	\note
		
*/

int udr_xel_route_urpf_mode_set(int unit, int port, int mode)
{
	/*##__PORTMAKER__##udr_xel_route_urpf_mode_set##route.pd##*/
	int	r_rv = UDR_API_E_NONE;
	/*printf("udr_xel_route_urpf_mode_set is called.\n");*/

	return r_rv;
	/*##__PORTMAKER_END__##*/
}

int udr_xel_route_vlan_mtu_set(int unit, int vlan, int mtu)
{
	return UDR_API_E_NONE;
}

int udr_xel_route_sw_counter_init(int unit)
{
   	memset(&route_sw_collector,0,sizeof(udr_route_sw_counter_s));
	return OK;
}

int udr_xel_route_del_all(int unit)
{
	int rv=UDR_API_E_NONE;

	return rv;
}

#define PG_FRR_PORT_SCAN 14
#define PG_FRR_NH_SCAN   15
#define PG_FRR_PORT_SCAN_CNT 0x10000
#define PG_FRR_NH_SCAN_CNT   0x4000
#define gBaseDelayTime 100000
int gMaxDelayTime = 5;
int udr_xel_route_frr_irq(int unit, int port)
 {
    int ret=0;
    int _p_errno=0;
    void *pg_hdl; 
    int i =0;
    int delayCount = gMaxDelayTime * gBaseDelayTime;
    struct hdr_frr_type pg_scan_frr_port;
    rtdbgprint(RT_DBG_FRR, "the frr irq captured!, port = %d \n",port);
    pmcl_memset(&pg_scan_frr_port, 0, sizeof(struct hdr_frr_type) );
    pg_scan_frr_port.type = PG_FRR_PORT_SCAN;
    pg_scan_frr_port.info.pg_scan_frr_port.frr_port = port & 0xffff;

    for (i = 0; i < delayCount; i++)
    {
        /* just delay some time */
    }
    ret = pmcl_xel_priv_hndls_get(_xel_priv_ctl_hndl, "pkg_hndl", &pg_hdl);
    if(ret < UDR_API_E_NONE)
    {
    	printf("\r\n hndl get failed!");
        _p_errno = - UDR_API_E_INTERNAL;
        goto err;
    }

	ret = pmcl_xel_pkg_send(pg_hdl, PG_FRR_PORT_SCAN_CNT, sizeof(struct hdr_frr_type), &pg_scan_frr_port);
	if(ret < UDR_API_E_NONE)
	{
		printf("\r\n xel pkg send failed! ");
        _p_errno = - UDR_API_E_INTERNAL;
        goto err;
    }

	
    return UDR_API_E_NONE;
									

err:
  	return _p_errno;
}


int udr_xel_route_frr_cpu_handle(void* data, int len, int type)
 {
    int ret=0;
    int _p_errno=0;
    void *pg_hdl;
    int next_hop_ref = 0;
    struct hdr_frr_type pg_scan_frr_nh;

    if(type != 10)
	{
		/* error */
		return UDR_API_E_INTERNAL;
	}
    next_hop_ref = *(uint16_t*)data;
    rtdbgprint(RT_DBG_FRR, "the frr cpu handle begins! next_hop_ref = %d \n", next_hop_ref);
    pmcl_memset(&pg_scan_frr_nh, 0, sizeof(struct hdr_frr_type) );
	pg_scan_frr_nh.type = PG_FRR_NH_SCAN;
    pg_scan_frr_nh.info.pg_scan_ecmp_nh_ref.frr_next_hop_ref = next_hop_ref & 0xffff;

    ret = pmcl_xel_priv_hndls_get(_xel_priv_ctl_hndl, "pkg_hndl", &pg_hdl);
    if(ret < UDR_API_E_NONE)
    {
    	printf("\r\n hndl get failed!");
        _p_errno = - UDR_API_E_INTERNAL;
        goto err;
    }

	ret = pmcl_xel_pkg_send(pg_hdl, PG_FRR_NH_SCAN_CNT, sizeof(struct hdr_frr_type), &pg_scan_frr_nh);
	if(ret < UDR_API_E_NONE)
	{
		printf("\r\n xel pkg send failed! ");
        _p_errno = - UDR_API_E_INTERNAL;
        goto err;
    }

	
    return UDR_API_E_NONE;
									

err:
  	return _p_errno;
    
 }

int route_test_ipv4(int flag, uint32_t dip, uint32_t ip_mask, uint8_t* dmac, int port)
{
	udr_route_data_t  entry;
	udr_route_entry_t route_entry;
	udr_egress_entry_t egress_entry;
	int ret = 0;
	int unit = 0;

	memset(&entry,0,sizeof(udr_route_data_t));
	memset(&route_entry,0,sizeof(udr_route_entry_t));
	memset(&egress_entry,0,sizeof(udr_egress_entry_t));

	memcpy(egress_entry.dst_mac,dmac,6);
	egress_entry.modid = 0;
	egress_entry.port = port;   //dest_id
	egress_entry.vid = 3;
	egress_entry.op = 1;
    egress_entry.next_hop_ip[0]=192;
    egress_entry.next_hop_ip[1]=168;
    egress_entry.next_hop_ip[2]=1;
    egress_entry.next_hop_ip[3]=10;
	
	route_entry.egress_unit = unit;
	route_entry.intf_num = 1;

	route_entry.ipv4_addr = dip;
	route_entry.ipv4_mask = ip_mask;
	route_entry.vrId = 0;
	route_entry.family = UDR_TNL_FA4;

	entry.egress = &egress_entry;
	entry.l3_entry = &route_entry;
	entry.egress_num = 1;
	if(uspdebug_route)
	{
		printf("\n\r vrf =%d,ipaddr=0x%0x,ipmask=0x%0x,src_mac=0x%02x:%02x:%02x:%02x:%02x:%02x",entry.l3_entry->vrId,
			entry.l3_entry->ipv4_addr,entry.l3_entry->ipv4_mask,entry.l3_entry->src_mac[0],entry.l3_entry->src_mac[1],entry.l3_entry->src_mac[2],
			entry.l3_entry->src_mac[3],entry.l3_entry->src_mac[4],entry.l3_entry->src_mac[5]);
		printf("\n\r port=%d,vlan=%d,dst mac=0x%02x:%02x:%02x:%02x:%02x:%02x\n",entry.egress->port,entry.egress->vid,entry.egress->dst_mac[0],
			entry.egress->dst_mac[1],entry.egress->dst_mac[2],entry.egress->dst_mac[3],entry.egress->dst_mac[4],entry.egress->dst_mac[5]);

		
	}
	if(flag)
	{
		ret = udr_xel_route_ip_add(unit,&entry);
		if(ret<0)
		{
			return ret;
		} 
	}
	else
	{
		ret = udr_xel_route_ip_del(unit,&entry);
		if(ret < 0)
		{
			return ret;
		}
	}
	return ret;
}

int route_test_ecmp(int flag, uint32_t dip, uint32_t ip_mask, uint8_t hop_num, uint8_t *dmac, int *port)
{
	udr_route_data_t  entry;
	udr_route_entry_t route_entry;
	udr_egress_entry_t egress_entry[hop_num];
	int ret = 0;
	int unit = 0;
    int i;
	memset(&entry,0,sizeof(udr_route_data_t));
	memset(&route_entry,0,sizeof(udr_route_entry_t));
	memset(&egress_entry,0,sizeof(udr_egress_entry_t)*hop_num);
    for(i=0; i < hop_num; i++)
    {    
    	memcpy(egress_entry[i].dst_mac,dmac+6*i,6);
    	egress_entry[i].modid = 0;
    	egress_entry[i].port = port[i];   //dest_id
    	egress_entry[i].vid = 3;
    	egress_entry[i].op = 1;
	}
    egress_entry[0].flags = 0x20;
    egress_entry[1].flags = 0x40;
	route_entry.egress_unit = unit;
	route_entry.intf_num = 1;

	route_entry.ipv4_addr = dip;
	route_entry.ipv4_mask = ip_mask;
	route_entry.vrId = 0;
	route_entry.family = UDR_TNL_FA4;
    route_entry.flags = UDR_ROUTE_FLAG_ECMP;
	entry.egress = &egress_entry;
	entry.l3_entry = &route_entry;
	entry.egress_num = hop_num;
    _xel_route_show_route_data(0,&entry);
	if(uspdebug_route)
	{
		printf("\n\r vrf =%d,ipaddr=0x%0x,ipmask=0x%0x,src_mac=0x%02x:%02x:%02x:%02x:%02x:%02x",entry.l3_entry->vrId,
			entry.l3_entry->ipv4_addr,entry.l3_entry->ipv4_mask,entry.l3_entry->src_mac[0],entry.l3_entry->src_mac[1],entry.l3_entry->src_mac[2],
			entry.l3_entry->src_mac[3],entry.l3_entry->src_mac[4],entry.l3_entry->src_mac[5]);
        for(i=0;i<hop_num;i++)
		printf("\n\r port=%d,vlan=%d,dst mac=0x%02x:%02x:%02x:%02x:%02x:%02x\n",entry.egress[i].port,entry.egress[i].vid,entry.egress[i].dst_mac[0],
			entry.egress[i].dst_mac[1],entry.egress[i].dst_mac[2],entry.egress[i].dst_mac[3],entry.egress[i].dst_mac[4],entry.egress[i].dst_mac[5]);

		
	}
	if(flag)
	{
		ret = udr_xel_route_ip_add(unit,&entry);
		if(ret<0)
		{
			return ret;
		} 
	}
	else
	{
		ret = udr_xel_route_ip_del(unit,&entry);
		if(ret < 0)
		{
			return ret;
		}
	}
	return ret;
}
/* end of udr_xel_route.c*/
