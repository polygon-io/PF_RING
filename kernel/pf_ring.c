/* ***************************************************************
 *
 * (C) 2004-21 - ntop.org
 *
 * This code includes contributions courtesy of
 * - Amit D. Chaudhary <amit_ml@rajgad.com>
 * - Andrew Gallatin <gallatyn@myri.com>
 * - Brad Doctor <brad@stillsecure.com>
 * - Felipe Huici <felipe.huici@nw.neclab.eu>
 * - Francesco Fusco <fusco@ntop.org> (IP defrag)
 * - Helmut Manck <helmut.manck@secunet.com>
 * - Hitoshi Irino <irino@sfc.wide.ad.jp> (IPv6 support)
 * - Jakov Haron <jyh@cabel.net>
 * - Jeff Randall <jrandall@nexvu.com>
 * - Kevin Wormington <kworm@sofnet.com>
 * - Mahdi Dashtbozorgi <rdfm2000@gmail.com>
 * - Marketakis Yannis <marketak@ics.forth.gr>
 * - Matthew J. Roth <mroth@imminc.com>
 * - Michael Stiller <ms@2scale.net> (VM memory support)
 * - Noam Dev <noamdev@gmail.com>
 * - Siva Kollipara <siva@cs.arizona.edu>
 * - Vincent Carrier <vicarrier@wanadoo.fr>
 * - Eugene Bogush <b_eugene@ukr.net>
 * - Samir Chang <coobyhb@gmail.com>
 * - Ury Stankevich <urykhy@gmail.com>
 * - Raja Mukerji <raja@mukerji.com>
 * - Davide Viti <zinosat@tiscali.it>
 * - Will Metcalf <william.metcalf@gmail.com>
 * - Godbach <nylzhaowei@gmail.com>
 * - Nicola Bonelli <bonelli@antifork.org>
 * - Jan Alsenz
 * - valxdater@seznam.cz
 * - Vito Piserchia <vpiserchia@metatype.it>
 * - Guo Chen <johncg1983@gmail.com>
 * - Dan Kruchinin <dkruchinin@acm.org>
 * - Andreas Tsopelas <tsopelas@kth.se>
 * - Alex Aronson <alexa@silicom.co.il>
 * - Piotr Romanus <promanus@crossbeamsys.com>
 * - Lior Okman <lior.okman@insightix.com>
 * - Fedor Sakharov <fedor.sakharov@gmail.com>
 * - Daniel Christopher <Chris.Daniel@visualnetworksystems.com>
 * - Martin Holste <mcholste@gmail.com>
 * - Eric Leblond <eric@regit.org>
 * - Momina Khan <momina.azam@gmail.com>
 * - XTao <xutao881001@gmail.com>
 * - James Juran <james.juran@mandiant.com>
 * - Paulo Angelo Alves Resende <pa@pauloangelo.com>
 * - Amir Kaduri (Kadoorie) <akaduri75@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <linux/version.h>

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32))
#error **********************************************************************
#error * PF_RING works on kernel 2.6.32 or newer. Please update your kernel *
#error **********************************************************************
#endif

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>
#include <linux/icmp.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/proc_fs.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/io.h>		/* needed for virt_to_phys() */
#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/pci.h>
#include <asm/shmparam.h>

#ifndef UTS_RELEASE
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
#include <linux/utsrelease.h>
#else
#include <generated/utsrelease.h>
#endif
#endif

#ifdef UTS_UBUNTU_RELEASE_ABI
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(3,0,0))
#undef UTS_UBUNTU_RELEASE_ABI
#else
#define UBUNTU_VERSION_CODE (LINUX_VERSION_CODE & ~0xFF)
#endif
#endif

#define I82599_HW_FILTERING_SUPPORT

#include "linux/pf_ring.h"

#ifndef GIT_REV
#define GIT_REV "unknown"
#endif

#if(LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0))
#define PDE_DATA(a) PDE(a)->data
#endif

#if(LINUX_VERSION_CODE <= KERNEL_VERSION(4,16,0))
#ifndef NETDEV_PRE_UP
#define NETDEV_PRE_UP  0x000D
#endif
#endif

/* ************************************************* */

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0))

/* From linux 5.4.34 */

struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}

struct timeval ns_to_timeval(const s64 nsec)
{
	struct timespec ts = ns_to_timespec(nsec);
	struct timeval tv;

	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = (suseconds_t) ts.tv_nsec / 1000;

	return tv;
}

#endif

/* ************************************************* */

static inline void printk_addr(u_int8_t ip_version, ip_addr *addr, u_int16_t port)
{
  if(!addr) {
    printk("NULL addr");
    return;
  }
  if(ip_version==4) {
    printk("IP=%d.%d.%d.%d:%u ",
        ((addr->v4 >> 24) & 0xff),
        ((addr->v4 >> 16) & 0xff),
        ((addr->v4 >> 8) & 0xff),
        ((addr->v4 >> 0) & 0xff),
        port);
  } else if(ip_version==6) {
    printk("IP=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%u ",
        addr->v6.s6_addr[0],addr->v6.s6_addr[1], addr->v6.s6_addr[2],addr->v6.s6_addr[3],
        addr->v6.s6_addr[4],addr->v6.s6_addr[5], addr->v6.s6_addr[6],addr->v6.s6_addr[7],
        addr->v6.s6_addr[8],addr->v6.s6_addr[9], addr->v6.s6_addr[10],addr->v6.s6_addr[11],
        addr->v6.s6_addr[12],addr->v6.s6_addr[13], addr->v6.s6_addr[14],addr->v6.s6_addr[15],
        port);
  } else {
    printk("IP=? (v=%d) ", ip_version);
  }
  return;
}

/* ************************************************* */

#define debug_on(debug_level) (unlikely(enable_debug >= debug_level))
#define debug_printk(debug_level, fmt, ...) { if(debug_on(debug_level)) \
  printk("[PF_RING][DEBUG] %s:%d " fmt,  __FUNCTION__, __LINE__, ## __VA_ARGS__); }

#define debug_printk_rule_session(rule) \
  printk("vlan=%u proto=%d ", (rule)->vlan_id, (rule)->proto); \
  printk_addr((rule)->ip_version,&(rule)->host_peer_a, (rule)->port_peer_a); \
  printk_addr((rule)->ip_version,&(rule)->host_peer_b, (rule)->port_peer_b); \

#define debug_printk_rules_comparison(debug_level, rule_a, rule_b) { \
  if(debug_on(debug_level)) { \
    printk("[PF_RING][DEBUG] %s:%d Comparing ", __FUNCTION__, __LINE__); \
    debug_printk_rule_session(rule_a); \
    debug_printk_rule_session(rule_b); \
    printk("\n"); \
  } \
}

#define debug_printk_rule_info(debug_level, rule, fmt, ...) { \
  if(debug_on(debug_level)) { \
    printk("[PF_RING][DEBUG] %s:%d ", __FUNCTION__, __LINE__); \
    debug_printk_rule_session(rule); \
    printk(fmt, ## __VA_ARGS__); \
  } \
}

/* ************************************************* */

#define TH_FIN_MULTIPLIER	0x01
#define TH_SYN_MULTIPLIER	0x02
#define TH_RST_MULTIPLIER	0x04
#define TH_PUSH_MULTIPLIER	0x08
#define TH_ACK_MULTIPLIER	0x10
#define TH_URG_MULTIPLIER	0x20

/* ************************************************* */

#define PROC_INFO               "info"
#define PROC_DEV                "dev"
#define PROC_STATS              "stats"
#define PROC_RULES              "rules"

/* ************************************************* */

const static ip_addr ip_zero = { IN6ADDR_ANY_INIT };

static u_int8_t pfring_enabled = 1;

#if(LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0))
static int pf_ring_net_id;
#else
static unsigned int pf_ring_net_id;
#endif

/* Dummy 'any' device */
static pf_ring_device any_device_element, none_device_element;

/* List of all ring sockets. */
static lockless_list ring_table;
static atomic_t ring_table_size;

/*
  List where we store pointers that we need to remove in
   a delayed fashion when we're done with all operations
*/
static lockless_list delayed_memory_table;

/* Protocol hook */
static struct packet_type prot_hook;

/* List of virtual filtering devices */
static struct list_head virtual_filtering_devices_list;
static DEFINE_MUTEX(virtual_filtering_lock);

/* List of all clusters */
static lockless_list ring_cluster_list;
static DEFINE_RWLOCK(ring_cluster_lock);

/* List of all devices on which PF_RING has been registered */
static struct list_head ring_aware_device_list; /* List of pf_ring_device */

/*
   Fragment handling for clusters

   As in a cluster packet fragments cannot be hashed, we have a cache where we can keep
   the association between the IP packet identifier and the balanced application.
*/
static u_int32_t num_cluster_fragments = 0;
static u_int32_t num_cluster_discarded_fragments = 0;
static unsigned long next_fragment_purge_jiffies = 0;
static struct list_head cluster_fragment_hash[NUM_FRAGMENTS_HASH_SLOTS];
static DEFINE_SPINLOCK(cluster_fragments_lock);

/* List of all ZC devices */
static struct list_head zc_devices_list;
static u_int zc_devices_list_size = 0;

/* List of generic cluster referees */
static struct list_head cluster_referee_list;
static DEFINE_MUTEX(cluster_referee_lock);

/* Dummy buffer used for loopback_test */
u_int32_t loobpack_test_buffer_len = 4*1024*1024;
u_char *loobpack_test_buffer = NULL;

/* Fake MAC address, to be passed to functions that don't use it but have it
   in their signatures */
u_int8_t zeromac[ETH_ALEN] = {'\0','\0','\0','\0','\0','\0'};

/* ********************************** */

static void ring_proc_add(struct pf_ring_socket *pfr);
static void ring_proc_remove(struct pf_ring_socket *pfr);
static void ring_proc_init(pf_ring_net *netns);
static void ring_proc_term(pf_ring_net *netns);

static int reflect_packet(struct sk_buff *skb,
			  struct pf_ring_socket *pfr,
			  struct net_device *reflector_dev,
			  int displ, rule_action_behaviour behaviour,
			  u_int8_t do_clone_skb);

static void purge_idle_fragment_cache(void);

/* ********************************** */

static DEFINE_MUTEX(ring_mgmt_lock);

/* ********************************** */

/*
  Caveat
  [http://lists.metaprl.org/pipermail/cs134-labs/2002-October/000025.html]

  GFP_ATOMIC means roughly "make the allocation operation atomic".  This
  means that the kernel will try to find the memory using a pile of free
  memory set aside for urgent allocation.  If that pile doesn't have
  enough free pages, the operation will fail.  This flag is useful for
  allocation within interrupt handlers.

  GFP_KERNEL will try a little harder to find memory.  There's a
  possibility that the call to kmalloc() will sleep while the kernel is
  trying to find memory (thus making it unsuitable for interrupt
  handlers).  It's much more rare for an allocation with GFP_KERNEL to
  fail than with GFP_ATOMIC.

  In all cases, kmalloc() should only be used allocating small amounts of
  memory (a few kb).  vmalloc() is better for larger amounts.

  Also note that in lab 1 and lab 2, it would have been arguably better to
  use GFP_KERNEL instead of GFP_ATOMIC.  GFP_ATOMIC should be saved for
  those instances in which a sleep would be totally unacceptable.
*/
/* ********************************** */

/* Forward */
static struct proto_ops ring_ops;
static struct proto ring_proto;

static int remove_from_cluster(struct sock *sock, struct pf_ring_socket *pfr);
static int pfring_select_zc_dev(struct pf_ring_socket *pfr, zc_dev_mapping *mapping);
static int pfring_get_zc_dev(struct pf_ring_socket *pfr);
static int pfring_release_zc_dev(struct pf_ring_socket *pfr);

static int  get_fragment_app_id(u_int32_t ipv4_src_host, u_int32_t ipv4_dst_host, u_int16_t fragment_id, u_int8_t more_fragments);
static void add_fragment_app_id(u_int32_t ipv4_src_host, u_int32_t ipv4_dst_host, u_int16_t fragment_id, u_int8_t app_id);

/* Extern */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
extern int ip_defrag(struct sk_buff *skb, u32 user);
#else
extern int ip_defrag(struct net *net, struct sk_buff *skb, u32 user);
#endif

/* ********************************** */

/* Defaults */
static unsigned int min_num_slots = DEFAULT_NUM_SLOTS;
static unsigned int perfect_rules_hash_size = DEFAULT_RING_HASH_SIZE;
static unsigned int enable_tx_capture = 1;
static unsigned int enable_frag_coherence = 1;
static unsigned int enable_ip_defrag = 0;
static unsigned int quick_mode = 0;
static unsigned int force_ring_lock = 0;
static unsigned int enable_debug = 0;
static unsigned int transparent_mode = 0;
static atomic_t ring_id_serial = ATOMIC_INIT(0);

#if defined(RHEL_RELEASE_CODE)
#if(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(4,8))
#define REDHAT_PATCHED_KERNEL
#endif
#endif

module_param(min_num_slots, uint, 0644);
module_param(perfect_rules_hash_size, uint, 0644);
module_param(enable_tx_capture, uint, 0644);
module_param(enable_frag_coherence, uint, 0644);
module_param(enable_ip_defrag, uint, 0644);
module_param(quick_mode, uint, 0644);
module_param(force_ring_lock, uint, 0644);
module_param(enable_debug, uint, 0644);
module_param(transparent_mode, uint, 0644);

MODULE_PARM_DESC(min_num_slots, "Min number of ring slots");
MODULE_PARM_DESC(perfect_rules_hash_size, "Perfect rules hash size");
MODULE_PARM_DESC(enable_tx_capture, "Set to 1 to capture outgoing packets");
MODULE_PARM_DESC(enable_frag_coherence, "Set to 1 to handle fragments (flow coherence) in clusters");
MODULE_PARM_DESC(enable_ip_defrag,
		 "Set to 1 to enable IP defragmentation"
		 "(only rx traffic is defragmentead)");
MODULE_PARM_DESC(quick_mode,
		 "Set to 1 to run at full speed but with up"
		 "to one socket per interface");
MODULE_PARM_DESC(force_ring_lock, "Set to 1 to force ring locking (automatically enable with rss)");
MODULE_PARM_DESC(enable_debug, "Set to 1 to enable PF_RING debug tracing into the syslog, 2 for more verbosity");
MODULE_PARM_DESC(transparent_mode,
		 "(deprecated)");

/* ********************************** */

#define MIN_QUEUED_PKTS      64
#define MAX_QUEUE_LOOPS      64

#define ring_sk(__sk) ((struct ring_sock *) __sk)->pf_ring_sk

#define _rdtsc() ({ uint64_t x; asm volatile("rdtsc" : "=A" (x)); x; })

/* ***************** Legacy code ************************ */

u_int get_num_rx_queues(struct net_device *dev)
{
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)) && defined(CONFIG_RPS)
  /* FIXX now sure why we are taking the min here, it may depend on the way old kernels
   * managed rss queues, setting real_num_tx_queues, not sure if it's still needed */
  return min_val(dev->real_num_rx_queues, dev->real_num_tx_queues);
#elif(defined(RHEL_MAJOR) && (RHEL_MAJOR == 6)) && defined(CONFIG_RPS)
  if(netdev_extended(dev) != NULL)
    return netdev_extended(dev)->real_num_rx_queues;
  else
    return 1;
#else
  return dev->real_num_tx_queues;
#endif
}

/* ************************************************** */

u_int lock_rss_queues(struct net_device *dev)
{
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)) && defined(CONFIG_RPS)
  return (dev->real_num_rx_queues > 1) || (dev->real_num_tx_queues > 1);
#elif(defined(RHEL_MAJOR) && (RHEL_MAJOR == 6)) && defined(CONFIG_RPS)
  if(netdev_extended(dev) != NULL)
    return (netdev_extended(dev)->real_num_rx_queues > 1);
  else
    return 1; /* unknown */
#else
  return (dev->real_num_tx_queues > 1);
#endif
}

/* ************************************************** */

#if defined(REDHAT_PATCHED_KERNEL)
/* Always the same RH crap */

#if((RHEL_MAJOR == 5) && (RHEL_MINOR <= 8 /* 5 */))
void msleep(unsigned int msecs)
{
  unsigned long timeout = msecs_to_jiffies(msecs) + 1;

  while (timeout)
    timeout = schedule_timeout_uninterruptible(timeout);
}
#endif
#endif

/* ************************************************** */

static inline int32_t ifindex_to_pf_index(pf_ring_net *netns,
                                          int32_t ifindex) {
  ifindex_map_item *ifindex_map = netns->ifindex_map;
  int i;

  if (ifindex < MAX_NUM_DEV_IDX &&
      ifindex_map[ifindex].set &&
      ifindex_map[ifindex].direct_mapping)
    return ifindex;

  for (i = 0; i < MAX_NUM_DEV_IDX; i++)
    if (ifindex_map[i].set &&
        ifindex_map[i].ifindex == ifindex)
      return i;

  return -1;
}

/* ************************************************** */

static inline int32_t pf_index_to_ifindex(pf_ring_net *netns,
                                          int32_t pf_index) {
  ifindex_map_item *ifindex_map = netns->ifindex_map;
  if (ifindex_map[pf_index].set)
    return ifindex_map[pf_index].ifindex;

  return -1;
}

/* ************************************************** */

static int32_t map_ifindex(pf_ring_net *netns, int32_t ifindex) {
  ifindex_map_item *ifindex_map = netns->ifindex_map;
  int32_t i = ifindex_to_pf_index(netns, ifindex);

  if (i >= 0)
    return i;

  if (ifindex < MAX_NUM_DEV_IDX &&
      !ifindex_map[ifindex].set) {
    ifindex_map[ifindex].ifindex = ifindex;
    ifindex_map[ifindex].direct_mapping = 1;
    ifindex_map[ifindex].set = 1;
    return ifindex;
  }

  for (i = 0; i < MAX_NUM_DEV_IDX; i++)
    if (!ifindex_map[i].set) {
      ifindex_map[i].ifindex = ifindex;
      ifindex_map[i].direct_mapping = 0;
      ifindex_map[i].set = 1;
      return i;
    }

  return -1;
}

/* ************************************************** */

static void unmap_ifindex(pf_ring_net *netns, int32_t ifindex) {
  ifindex_map_item *ifindex_map = netns->ifindex_map;
  int32_t i = ifindex_to_pf_index(netns, ifindex);
  if (i >= 0) {
    ifindex_map[i].ifindex = 0;
    ifindex_map[i].direct_mapping = 0;
    ifindex_map[i].set = 0;
  }
}

/* ************************************************** */

void init_lockless_list(lockless_list *l)
{
  memset(l, 0, sizeof(lockless_list));
  spin_lock_init(&l->list_lock);
}

/* ************************************************** */

/* Return the index where the element has been add or -1 in case of no room left */
int lockless_list_add(lockless_list *l, void *elem)
{
  int i;

  debug_printk(2, "BEGIN [total=%u]\n", l->num_elements);

  if(l->num_elements >= MAX_NUM_LIST_ELEMENTS) {
    printk("[PF_RING] Exceeded the maximum number of list items\n");
    return(-1); /* Too many */
  }

  /* I could avoid mutexes but ... */
  spin_lock_bh(&l->list_lock);

  for(i=0; i<MAX_NUM_LIST_ELEMENTS; i++) {
    void *old_slot_value;

    /* Set l->list_elements[i]=elem if l->list_elements[i]=NULL */
    old_slot_value = cmpxchg(&l->list_elements[i], NULL, elem);

    if(old_slot_value == NULL)
      break; /* We succeeded */
  }

  if(l->top_element_id < i)
    l->top_element_id = i;

  l->num_elements++;

  if(debug_on(2)) {
    debug_printk(2, "END [total=%u][id=%u][top_element_id=%u]\n",
	         l->num_elements, i, l->top_element_id);

    for(i=0; i<MAX_NUM_LIST_ELEMENTS; i++) {
      if(l->list_elements[i])
	debug_printk(2, "[slot %u is full]\n",i);
    }
  }

  spin_unlock_bh(&l->list_lock);

  return(i);
}

/* ************************************************** */

/* http://community.topcoder.com/tc?module=Static&d1=tutorials&d2=bitManipulation */

/*
  Return the index where the element has been add or -1 in case the element to
  be removed was not found

  NOTE: NO MEMORY IS FREED
*/
int lockless_list_remove(lockless_list *l, void *elem)
{
  int i, old_full_slot = -1;

  debug_printk(2, "BEGIN [total=%u]\n", l->num_elements);

  if(l->num_elements == 0) return(-1); /* Not found */

  spin_lock_bh(&l->list_lock);

  for(i=0; i<MAX_NUM_LIST_ELEMENTS; i++) {
    if(l->list_elements[i] == elem) {
      (void)xchg(&l->list_elements[i], NULL);

      while((l->top_element_id > 0) && (l->list_elements[l->top_element_id] == NULL))
	l->top_element_id--;

      l->num_elements--, old_full_slot = i;
      break;
    }
  }

  if(debug_on(2)) {
    debug_printk(2, "END [total=%u][top_element_id=%u]\n", l->num_elements, l->top_element_id);

    for(i=0; i<MAX_NUM_LIST_ELEMENTS; i++) {
      if(l->list_elements[i])
	debug_printk(2, "[slot %u is full]\n", i);
    }
  }

  spin_unlock_bh(&l->list_lock);
  wmb();

  return(old_full_slot);
}

/* ************************************************** */

void *lockless_list_get_next(lockless_list *l, u_int32_t *last_idx)
{
  while(*last_idx <= l->top_element_id) {
    void *elem;

    elem = l->list_elements[*last_idx];
    (*last_idx)++;

    if(elem != NULL)
      return(elem);
  }

  return(NULL);
}

/* ************************************************** */

void * lockless_list_get_first(lockless_list *l, u_int32_t *last_idx)
{
  *last_idx = 0;
  return(lockless_list_get_next(l, last_idx));
}

/* ************************************************** */

void lockless_list_empty(lockless_list *l, u_int8_t free_memory)
{
  int i;

  if(free_memory) {
    spin_lock_bh(&l->list_lock);

    for(i=0; i<MAX_NUM_LIST_ELEMENTS; i++) {
      if(l->list_elements[i] != NULL) {
	kfree(l->list_elements[i]);
	l->list_elements[i] = NULL;
      }
    }

    l->num_elements = 0;
    spin_unlock_bh(&l->list_lock);
    wmb();
  }
}

/* ************************************************** */

void term_lockless_list(lockless_list *l, u_int8_t free_memory)
{
  lockless_list_empty(l, free_memory);
}

/* ********************************** */

pf_ring_net *netns_lookup(struct net *net) {
  pf_ring_net *pf_net = net_generic(net, pf_ring_net_id);

  if (pf_net == NULL)
    printk("[PF_RING] Namespace lookup failure\n");

  return pf_net;
}

/* ********************************** */

static inline int device_net_eq(pf_ring_device *dev_ptr, struct net *net) {
  return (dev_ptr == &any_device_element || dev_ptr == &none_device_element ||
          net_eq(dev_net(dev_ptr->dev), net));
}

/* ********************************** */

pf_ring_net *netns_add(struct net *net) {
  pf_ring_net *netns = net_generic(net, pf_ring_net_id);

  netns->net = net;
  ring_proc_init(netns);

  /* any_device */
  map_ifindex(netns, ANY_IFINDEX);
  /* none_device */
  map_ifindex(netns, NONE_IFINDEX);

  return netns;
}

/* ********************************** */

static int netns_remove(struct net *net)
{
  pf_ring_net *netns = net_generic(net, pf_ring_net_id);
  ring_proc_term(netns);
  return 0;
}

/* ********************************** */

static inline u_char *get_slot(struct pf_ring_socket *pfr, u_int64_t off)
{
  return(&(pfr->ring_slots[off]));
}

/* ********************************** */

static inline u_int64_t get_next_slot_offset(struct pf_ring_socket *pfr, u_int64_t off)
{
  struct pfring_pkthdr *hdr;
  u_int32_t real_slot_size;

  hdr = (struct pfring_pkthdr *) get_slot(pfr, off);

  real_slot_size = pfr->slot_header_len + hdr->caplen;

  /* padding at the end of the packet (magic number added on insert) */
  real_slot_size += sizeof(u_int16_t); /* RING_MAGIC_VALUE */

  /* Align slot size to 64 bit */
  real_slot_size = ALIGN(real_slot_size, sizeof(u_int64_t));

  if((off + real_slot_size + pfr->slots_info->slot_len) > (pfr->slots_info->tot_mem - sizeof(FlowSlotInfo)))
    return 0;

  return (off + real_slot_size);
}

/* ********************************** */

static inline u_int64_t num_queued_pkts(struct pf_ring_socket *pfr)
{
  u_int64_t tot_insert, tot_read;

  if(pfr->ring_slots == NULL)
    return 0;

  tot_insert = pfr->slots_info->tot_insert;
  tot_read = pfr->slots_info->tot_read;

  if (tot_read > tot_insert) /* safety check */
    return 0;

  return tot_insert - tot_read;
}

/* ************************************* */

static inline u_int64_t num_kernel_queued_pkts(struct pf_ring_socket *pfr)
{
  if(pfr->ring_slots != NULL) {
    return pfr->slots_info->tot_insert - pfr->slots_info->kernel_tot_read;
  } else
    return(0);
}

/* ************************************* */

static inline u_int64_t get_num_ring_free_slots(struct pf_ring_socket * pfr)
{
  u_int64_t nqpkts = num_queued_pkts(pfr);

  if(nqpkts < (pfr->slots_info->min_num_slots))
    return(pfr->slots_info->min_num_slots - nqpkts);
  else
    return(0);
}

/* ********************************** */

/*
  Consume packets that have been read by userland but not
  yet by kernel
*/
static void consume_pending_pkts(struct pf_ring_socket *pfr, u_int8_t synchronized)
{
  while (pfr->slots_info->kernel_remove_off != pfr->slots_info->remove_off &&
        /* one slot back (pfring_mod_send_last_rx_packet is called after pfring_recv has updated remove_off) */
        (synchronized || pfr->slots_info->remove_off != get_next_slot_offset(pfr, pfr->slots_info->kernel_remove_off))) {
    struct pfring_pkthdr *hdr = (struct pfring_pkthdr *) &pfr->ring_slots[pfr->slots_info->kernel_remove_off];

    debug_printk(2, "Original offset [kernel_remove_off=%llu][remove_off=%llu][skb=%p]\n",
	     pfr->slots_info->kernel_remove_off,
	     pfr->slots_info->remove_off,
	     hdr->extended_hdr.tx.reserved);

    if(hdr->extended_hdr.tx.reserved != NULL) {
      /* Can't forward the packet on the same interface it has been received */
      if(hdr->extended_hdr.tx.bounce_interface == pfr->ring_dev->dev->ifindex) {
	hdr->extended_hdr.tx.bounce_interface = UNKNOWN_INTERFACE;
      }

      if(hdr->extended_hdr.tx.bounce_interface != UNKNOWN_INTERFACE) {
	/* Let's check if the last used device is still the prefered one */
	if(pfr->tx.last_tx_dev_idx != hdr->extended_hdr.tx.bounce_interface) {
	  if(pfr->tx.last_tx_dev != NULL) {
	    dev_put(pfr->tx.last_tx_dev); /* Release device */
	  }

	  /* Reset all */
	  pfr->tx.last_tx_dev = NULL, pfr->tx.last_tx_dev_idx = UNKNOWN_INTERFACE;

	  pfr->tx.last_tx_dev = dev_get_by_index(sock_net(pfr->sk), hdr->extended_hdr.tx.bounce_interface);

	  if(pfr->tx.last_tx_dev != NULL) {
	    /* We have found the device */
	    pfr->tx.last_tx_dev_idx = hdr->extended_hdr.tx.bounce_interface;
	  }
	}

	if(pfr->tx.last_tx_dev) {
	  debug_printk(2, "Bouncing packet to interface %d/%s\n",
		       hdr->extended_hdr.tx.bounce_interface,
		       pfr->tx.last_tx_dev->name);

	  reflect_packet(hdr->extended_hdr.tx.reserved, pfr,
			 pfr->tx.last_tx_dev, 0 /* displ */,
			 forward_packet_and_stop_rule_evaluation,
			 0 /* don't clone skb */);
	} else {
	  kfree_skb(hdr->extended_hdr.tx.reserved); /* Free memory */
	}
      } else {
	debug_printk(2, "Freeing cloned (unforwarded) packet\n");

	kfree_skb(hdr->extended_hdr.tx.reserved); /* Free memory */
      }
    }

    hdr->extended_hdr.tx.reserved = NULL;
    hdr->extended_hdr.tx.bounce_interface = UNKNOWN_INTERFACE;

    pfr->slots_info->kernel_remove_off = get_next_slot_offset(pfr, pfr->slots_info->kernel_remove_off);
    pfr->slots_info->kernel_tot_read++;

    debug_printk(2, "New offset [kernel_remove_off=%llu][remove_off=%llu]\n",
		 pfr->slots_info->kernel_remove_off,
		 pfr->slots_info->remove_off);
  }
}

/* ********************************** */

static inline int check_free_ring_slot(struct pf_ring_socket *pfr)
{
  u_int64_t remove_off;

  if(pfr->tx.enable_tx_with_bounce && pfr->header_len == long_pkt_header) /* fast-tx enabled */
    remove_off = pfr->slots_info->kernel_remove_off;
  else
    remove_off = pfr->slots_info->remove_off;

  if(pfr->slots_info->insert_off == remove_off) {
    u_int64_t queued_pkts;

    /* Both insert and remove offset are set on the same slot.
     * We need to find out whether the memory is full or empty */

    if(pfr->tx.enable_tx_with_bounce && pfr->header_len == long_pkt_header)
      queued_pkts = num_kernel_queued_pkts(pfr);
    else
      queued_pkts = num_queued_pkts(pfr);

    if(queued_pkts >= pfr->slots_info->min_num_slots)
      return(0); /* Memory is full */

  } else if(pfr->slots_info->insert_off < remove_off) {

    /* We have to check whether we have enough space to accommodate a new packet */

    /* Checking space for 1. new packet and 2. packet under processing */
    if((remove_off - pfr->slots_info->insert_off) < (2 * pfr->slots_info->slot_len))
      return(0);

  } else { /* pfr->slots_info->insert_off > remove_off */

    /* We have enough room for the incoming packet as after we insert a packet, the insert_off
     *  offset is wrapped to the beginning in case the space remaining is less than slot_len
     *  (i.e. the memory needed to accommodate a packet) */

    /* Checking space for 1. new packet, 2. packet under processing and 3. emty room when available space at insert time is less than slot_len */
    if((pfr->slots_info->tot_mem - sizeof(FlowSlotInfo) - pfr->slots_info->insert_off) < (3 * pfr->slots_info->slot_len) && remove_off == 0)
      return(0);
  }

  return(1);
}

/* ********************************** */

#define IP_DEFRAG_RING 1234

/* Returns new sk_buff, or NULL  */
static struct sk_buff *ring_gather_frags(struct sk_buff *skb)
{
#if(LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
  int status = ip_defrag(skb, IP_DEFRAG_RING);
#else
  int status = ip_defrag(dev_net(skb->dev), skb, IP_DEFRAG_RING);
#endif

  if(status)
    skb = NULL;
  else
    ip_send_check(ip_hdr(skb));

  return(skb);
}

/* ********************************** */

static void ring_sock_destruct(struct sock *sk)
{
  struct pf_ring_socket *pfr;

  skb_queue_purge(&sk->sk_receive_queue);

  if(!sock_flag(sk, SOCK_DEAD)) {
    debug_printk(2, "Attempt to release alive ring socket: %p\n", sk);
    return;
  }

  pfr = ring_sk(sk);

  if(pfr)
    kfree(pfr);
}

/* ********************************** */

pf_ring_device *pf_ring_device_ifindex_lookup(struct net *net, int ifindex) {
  struct list_head *ptr, *tmp_ptr;

  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    pf_ring_device *dev_ptr = list_entry(ptr, pf_ring_device, device_list);
    if(device_net_eq(dev_ptr, net) && dev_ptr->dev->ifindex == ifindex)
      return dev_ptr;
  }

  return NULL;
}

/* ********************************** */

pf_ring_device *pf_ring_device_name_lookup(struct net *net /* namespace */, char *name) {
  struct list_head *ptr, *tmp_ptr;
  int l = strlen(name);

  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    pf_ring_device *dev_ptr = list_entry(ptr, pf_ring_device, device_list);
    if(((strcmp(dev_ptr->device_name, name) == 0)
	/*
	  The problem is that pfring_mod_bind() needs to specify the interface
	  name using struct sockaddr that is defined as

	  struct sockaddr { ushort sa_family; char sa_data[14]; };

	  so the total interface name lenght is 13 chars (plus \0 trailer).
	  The check below is to trap this case.
	 */
	|| ((l >= 13) && (strncmp(dev_ptr->device_name, name, 13) == 0)))
       && device_net_eq(dev_ptr, net))
      return dev_ptr;
  }

  return NULL;
}

/* ************************************* */

static zc_dev_list *pf_ring_zc_dev_name_lookup(char *device_name, int32_t channel_id) {
  struct list_head *ptr, *tmp_ptr;
  zc_dev_list *entry;

  /* lookinf for ZC dev */
  list_for_each_safe(ptr, tmp_ptr, &zc_devices_list) {
    entry = list_entry(ptr, zc_dev_list, list);

    //printk("[PF_RING] %s:%d Checking %s channel %u\n", __FUNCTION__, __LINE__,
    //  entry->zc_dev.dev->name, entry->zc_dev.channel_id);

    if(strcmp(entry->zc_dev.dev->name, device_name) == 0
       && entry->zc_dev.channel_id == channel_id)
      return entry;
  }

  return NULL; 
}

/* ************************************* */

static zc_dev_list *pf_ring_zc_dev_net_device_lookup(struct net_device *dev, int32_t channel_id) {
  struct list_head *ptr, *tmp_ptr;
  zc_dev_list *entry;

  /* lookinf for ZC dev */
  list_for_each_safe(ptr, tmp_ptr, &zc_devices_list) {
    entry = list_entry(ptr, zc_dev_list, list);

    if(entry->zc_dev.dev == dev
       && entry->zc_dev.channel_id == channel_id)
      return entry;
  }

  return NULL; 
}

/* ********************************** */

static int ring_proc_get_info(struct seq_file *m, void *data_not_used);
static int ring_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, ring_proc_get_info, PDE_DATA(inode));
}

#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
static const struct file_operations ring_proc_fops = {
  .owner = THIS_MODULE,
  .open = ring_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};
#else
static const struct proc_ops ring_proc_fops = {
  .proc_open = ring_proc_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};
#endif

/* ********************************** */

static void ring_proc_add(struct pf_ring_socket *pfr)
{
  pf_ring_net *netns;

  netns = netns_lookup(sock_net(pfr->sk));

  if(netns != NULL &&
      netns->proc_dir != NULL &&
      pfr->sock_proc_name[0] == '\0') {
    snprintf(pfr->sock_proc_name, sizeof(pfr->sock_proc_name),
	     "%d-%s.%d", pfr->ring_pid, pfr->ring_dev->dev->name, pfr->ring_id);

    proc_create_data(pfr->sock_proc_name, 0, netns->proc_dir, &ring_proc_fops, pfr);

    debug_printk(2, "Added /proc/net/pf_ring/%s\n", pfr->sock_proc_name);
  }
}

/* ********************************** */

static void ring_proc_remove(struct pf_ring_socket *pfr)
{
  pf_ring_net *netns;

  netns = netns_lookup(sock_net(pfr->sk));

  if(netns != NULL &&
      netns->proc_dir != NULL &&
      pfr->sock_proc_name[0] != '\0') {
    debug_printk(2, "Removing /proc/net/pf_ring/%s\n", pfr->sock_proc_name);

    remove_proc_entry(pfr->sock_proc_name, netns->proc_dir);

    debug_printk(2, "Removed /proc/net/pf_ring/%s\n", pfr->sock_proc_name);

    pfr->sock_proc_name[0] = '\0';

    if(pfr->sock_proc_stats_name[0] != '\0') {
      debug_printk(2, "Removing /proc/net/pf_ring/stats/%s\n", pfr->sock_proc_stats_name);

      remove_proc_entry(pfr->sock_proc_stats_name, netns->proc_stats_dir);

      debug_printk(2, "Removed /proc/net/pf_ring/stats/%s\n", pfr->sock_proc_stats_name);

      pfr->sock_proc_stats_name[0] = '\0';

    }
  }
}

/* ********************************** */

static int ring_proc_dev_get_info(struct seq_file *m, void *data_not_used)
{
  if(m->private != NULL) {
    pf_ring_device *dev_ptr = (pf_ring_device*)m->private;
    struct net_device *dev = dev_ptr->dev;
    char dev_buf[16] = { 0 }, *dev_family = "???";

    if(dev_ptr->is_zc_device) {
      switch(dev_ptr->zc_dev_model) {
      case intel_e1000:
	dev_family = "Intel e1000";
        break;
      case intel_e1000e:
	dev_family = "Intel e1000e";
        break;
      case intel_igb:
	dev_family = "Intel igb";
	break;
      case intel_igb_82580:
	dev_family = "Intel igb 82580/i350 HW TS";
	break;
      case intel_ixgbe:
	dev_family = "Intel ixgbe";
	break;
      case intel_ixgbe_82598:
	dev_family = "Intel ixgbe 82598";
	break;
      case intel_ixgbe_82599:
	dev_family = "Intel ixgbe 82599";
	break;
      case intel_ixgbe_82599_ts:
	dev_family = "Silicom ixgbe 82599 HW TS";
	break;
      case intel_ixgbe_x550:
	dev_family = "Intel ixgbe X550";
	break;
      case intel_ixgbe_vf:
	dev_family = "Intel ixgbe VF";
	break;
      case intel_i40e:
        dev_family = "Intel i40e";
        break;
      case intel_fm10k:
        dev_family = "Intel fm10k";
        break;
      case intel_ice:
        dev_family = "Intel ice";
        break;
      }
    } else {
      switch(dev_ptr->device_type) {
      case standard_nic_family: dev_family = "Standard NIC"; break;
      case intel_82599_family:  dev_family = "Intel 82599"; break;
      }
    }

    seq_printf(m, "Name:         %s\n", dev->name);
    seq_printf(m, "Index:        %d\n", dev->ifindex);
    seq_printf(m, "Address:      %02X:%02X:%02X:%02X:%02X:%02X\n",
	       dev->perm_addr[0], dev->perm_addr[1], dev->perm_addr[2],
	       dev->perm_addr[3], dev->perm_addr[4], dev->perm_addr[5]);

    seq_printf(m, "Polling Mode: %s\n", dev_ptr->is_zc_device ? "NAPI/ZC" : "NAPI");

    seq_printf(m, "Promisc:      %s\n", (dev->flags & IFF_PROMISC) ? "Enabled" : "Disabled");

    switch(dev->type) {
    case ARPHRD_ETHER    /*   1 */: strcpy(dev_buf, "Ethernet"); break;
    case ARPHRD_LOOPBACK /* 772 */: strcpy(dev_buf, "Loopback"); break;
    default: sprintf(dev_buf, "%d", dev->type); break;
    }

    seq_printf(m, "Type:         %s\n", dev_buf);
    seq_printf(m, "Family:       %s\n", dev_family);

    if(!dev_ptr->is_zc_device) {
      pf_ring_net *netns = netns_lookup(dev_net(dev));
      int dev_index = ifindex_to_pf_index(netns, dev->ifindex);
      if(dev_index >= 0)
	seq_printf(m, "# Bound Sockets:  %d\n",
		   netns->num_rings_per_device[dev_index]);
    }

    seq_printf(m, "TX Queues:    %d\n", dev->real_num_tx_queues);
    seq_printf(m, "RX Queues:    %d\n",
	       dev_ptr->is_zc_device ? dev_ptr->num_zc_dev_rx_queues : get_num_rx_queues(dev));

    if(dev_ptr->is_zc_device) {
      zc_dev_list *zc_dev_ptr = pf_ring_zc_dev_net_device_lookup(dev, 0);
      seq_printf(m, "Num RX Slots: %d\n", dev_ptr->num_zc_rx_slots);
      seq_printf(m, "Num TX Slots: %d\n", dev_ptr->num_zc_tx_slots);
      if (zc_dev_ptr) {
        seq_printf(m, "RX Slot Size: %d\n",
          zc_dev_ptr->zc_dev.mem_info.rx.packet_memory_slot_len ?
          zc_dev_ptr->zc_dev.mem_info.rx.packet_memory_slot_len :
          zc_dev_ptr->zc_dev.mem_info.tx.packet_memory_slot_len);
        seq_printf(m, "TX Slot Size: %d\n",
          zc_dev_ptr->zc_dev.mem_info.tx.packet_memory_slot_len);
      } 
    }
  }

  return(0);
}

/* **************** 82599 ****************** */

static int i82599_generic_handler(struct pf_ring_socket *pfr,
				  hw_filtering_rule *rule, hw_filtering_rule_command request)
{
  int rc = -1;

#ifdef I82599_HW_FILTERING_SUPPORT
  struct net_device *dev = pfr->ring_dev->dev;
  intel_82599_five_tuple_filter_hw_rule *ftfq_rule;
  intel_82599_perfect_filter_hw_rule *perfect_rule;
  struct ethtool_rxnfc cmd;
  struct ethtool_rx_flow_spec *fsp = (struct ethtool_rx_flow_spec *) &cmd.fs;

  if(dev == NULL) return(-1);

  if((dev->ethtool_ops == NULL) || (dev->ethtool_ops->set_rxnfc == NULL)) return(-1);

  debug_printk(2, "hw_filtering_rule[%s][request=%d][%p]\n",
	   dev->name, request, dev->ethtool_ops->set_rxnfc);

  memset(&cmd, 0, sizeof(struct ethtool_rxnfc));

  switch (rule->rule_family_type) {
    case intel_82599_five_tuple_rule:
      ftfq_rule = &rule->rule_family.five_tuple_rule;

      fsp->h_u.tcp_ip4_spec.ip4src = ftfq_rule->s_addr;
      fsp->h_u.tcp_ip4_spec.psrc   = ftfq_rule->s_port;
      fsp->h_u.tcp_ip4_spec.ip4dst = ftfq_rule->d_addr;
      fsp->h_u.tcp_ip4_spec.pdst   = ftfq_rule->d_port;
      fsp->flow_type   = ftfq_rule->proto;
      fsp->ring_cookie = ftfq_rule->queue_id;
      fsp->location    = rule->rule_id;

      cmd.cmd = (request == add_hw_rule ? ETHTOOL_PFRING_SRXFTRLINS : ETHTOOL_PFRING_SRXFTRLDEL);

      break;

    case intel_82599_perfect_filter_rule:
      perfect_rule = &rule->rule_family.perfect_rule;

      fsp->ring_cookie = perfect_rule->queue_id;
      fsp->location    = rule->rule_id;

      if(perfect_rule->s_addr) {
        fsp->h_u.tcp_ip4_spec.ip4src = htonl(perfect_rule->s_addr);
        fsp->m_u.tcp_ip4_spec.ip4src = 0xFFFFFFFF;
      }

      if(perfect_rule->d_addr) {
        fsp->h_u.tcp_ip4_spec.ip4dst = htonl(perfect_rule->d_addr);
        fsp->m_u.tcp_ip4_spec.ip4dst = 0xFFFFFFFF;
      }

      if(perfect_rule->s_port) {
        fsp->h_u.tcp_ip4_spec.psrc = htons(perfect_rule->s_port);
        fsp->m_u.tcp_ip4_spec.psrc = 0xFFFF;
      }

      if(perfect_rule->d_port) {
        fsp->h_u.tcp_ip4_spec.pdst = htons(perfect_rule->d_port);
        fsp->m_u.tcp_ip4_spec.pdst = 0xFFFF;
      }

      if(perfect_rule->vlan_id) {
        fsp->h_ext.vlan_tci = htons(perfect_rule->vlan_id);
	fsp->m_ext.vlan_tci = htons(0xFFF); // VLANID meaningful, VLAN priority ignored
	/* fsp->h_ext.vlan_etype
	 * fsp->m_ext.vlan_etype */
	fsp->flow_type |= FLOW_EXT;
      }

      switch (perfect_rule->proto) {
	case 6:   /* TCP */
          fsp->flow_type = TCP_V4_FLOW;
	  break;
	case 132: /* SCTP */
	  fsp->flow_type = SCTP_V4_FLOW;
	  break;
	case 17:  /* UDP */
	  fsp->flow_type = UDP_V4_FLOW;
	  break;
	default: /* * */
	  fsp->flow_type = IP_USER_FLOW;
	  break;
      }

      cmd.cmd = (request == add_hw_rule ? ETHTOOL_SRXCLSRLINS : ETHTOOL_SRXCLSRLDEL);

      break;

    default:
      break;
  }

  if(cmd.cmd) {

    rc = dev->ethtool_ops->set_rxnfc(dev, &cmd);

    if(debug_on(2)
     && rule->rule_family_type == intel_82599_perfect_filter_rule
     && rc < 0) {
      intel_82599_perfect_filter_hw_rule *perfect_rule = &rule->rule_family.perfect_rule;

      debug_printk(2, "ixgbe_set_rxnfc(%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d) returned %d\n",
             perfect_rule->s_addr >> 24 & 0xFF, perfect_rule->s_addr >> 16 & 0xFF,
             perfect_rule->s_addr >>  8 & 0xFF, perfect_rule->s_addr >>  0 & 0xFF,
             perfect_rule->s_port & 0xFFFF,
             perfect_rule->d_addr >> 24 & 0xFF, perfect_rule->d_addr >> 16 & 0xFF,
             perfect_rule->d_addr >>  8 & 0xFF, perfect_rule->d_addr >>  0 & 0xFF,
             perfect_rule->d_port & 0xFFFF,
	     rc);
    }
  }
#endif
  return(rc);
}

/* ************************************* */

static int handle_hw_filtering_rule(struct pf_ring_socket *pfr,
				    hw_filtering_rule *rule,
				    hw_filtering_rule_command command)
{

  debug_printk(2, "--> handle_hw_filtering_rule(command=%d)\n", command);

  switch(rule->rule_family_type) {
  case intel_82599_five_tuple_rule:
    if(pfr->ring_dev->hw_filters.filter_handlers.five_tuple_handler == NULL)
      return(-EINVAL);
    else
      return(i82599_generic_handler(pfr, rule, command));
    break;

  case intel_82599_perfect_filter_rule:
    if(pfr->ring_dev->hw_filters.filter_handlers.perfect_filter_handler == NULL)
      return(-EINVAL);
    else
      return(i82599_generic_handler(pfr, rule, command));
    break;

  case silicom_redirector_rule:
  case accolade_rule:
  case accolade_default:
  case generic_flow_id_rule:
  case generic_flow_tuple_rule:
    return(-EINVAL); /* handled in userland */
    break;
  }

  return(-EINVAL);
}

/* ***************************************** */

#ifdef ENABLE_PROC_WRITE_RULE

static int ring_proc_dev_rule_read(struct seq_file *m, void *data_not_used)
{
  if(m->private != NULL) {
    pf_ring_device *dev_ptr = (pf_ring_device*)m->private;
    struct net_device *dev = dev_ptr->dev;

    seq_printf(m, "Name:              %s\n", dev->name);
    seq_printf(m, "# Filters:         %d\n", dev_ptr->hw_filters.num_filters);
    seq_printf(m, "\nFiltering Rules:\n"
	       "[perfect rule]  +|-(rule_id,queue_id,vlan,tcp|udp,src_ip/mask,src_port,dst_ip/mask,dst_port)\n"
	       "Example:\t+(1,-1,0,tcp,192.168.0.10/32,25,10.6.0.0/16,0) (queue_id = -1 => drop)\n\n"
	       "[5 tuple rule]  +|-(rule_id,queue_id,tcp|udp,src_ip,src_port,dst_ip,dst_port)\n"
	       "Example:\t+(1,-1,tcp,192.168.0.10,25,0.0.0.0,0)\n\n"
	       "Note:\n\t- queue_id = -1 => drop\n\t- 0 = ignore value\n");
  }

  return(0);
}

/* ********************************** */

static void init_intel_82599_five_tuple_filter_hw_rule(u_int8_t queue_id, u_int8_t proto,
						       u_int32_t s_addr, u_int32_t d_addr,
						       u_int16_t s_port, u_int16_t d_port,
						       intel_82599_five_tuple_filter_hw_rule *rule)
{

  /* printk("init_intel_82599_five_tuple_filter_hw_rule()\n"); */

  memset(rule, 0, sizeof(intel_82599_five_tuple_filter_hw_rule));

  rule->queue_id = queue_id, rule->proto = proto;
  rule->s_addr = s_addr, rule->d_addr = d_addr;
  rule->s_port = s_port, rule->d_port = d_port;
}

/* ********************************** */

static void init_intel_82599_perfect_filter_hw_rule(u_int8_t queue_id,
						    u_int8_t proto, u_int16_t vlan,
						    u_int32_t s_addr, u_int8_t s_mask,
						    u_int32_t d_addr, u_int8_t d_mask,
						    u_int16_t s_port, u_int16_t d_port,
						    intel_82599_perfect_filter_hw_rule *rule)
{
  u_int32_t netmask;

  /* printk("init_intel_82599_perfect_filter_hw_rule()\n"); */

  memset(rule, 0, sizeof(intel_82599_perfect_filter_hw_rule));

  rule->queue_id = queue_id, rule->vlan_id = vlan, rule->proto = proto;

  rule->s_addr = s_addr;
  if(s_mask == 32) netmask = 0xFFFFFFFF; else netmask = ~(0xFFFFFFFF >> s_mask);
  rule->s_addr &= netmask;

  rule->d_addr = d_addr;
  if(d_mask == 32) netmask = 0xFFFFFFFF; else netmask = ~(0xFFFFFFFF >> d_mask);
  rule->d_addr &= netmask;

  rule->s_port = s_port, rule->d_port = d_port;
}

/* ********************************** */

static int ring_proc_dev_rule_write(struct file *file,
				    const char __user *buffer,
				    unsigned long count, void *data)
{
  char buf[128], add, proto[4] = { 0 };
  pf_ring_device *dev_ptr = (pf_ring_device*)data;
  int num, queue_id, vlan, rc, rule_id, protocol;
  int s_a, s_b, s_c, s_d, s_mask, s_port;
  int d_a, d_b, d_c, d_d, d_mask, d_port;
  hw_filtering_rule_request rule;
  u_int8_t found = 0;
  int debug = 0;

  if(data == NULL) return(0);

  if(count > (sizeof(buf)-1))             count = sizeof(buf) - 1;
  if(copy_from_user(buf, buffer, count))  return(-EFAULT);
  buf[sizeof(buf)-1] = '\0', buf[count] = '\0';

  debug_printk(2, "ring_proc_dev_rule_write(%s)\n", buf);

  num = sscanf(buf, "%c(%d,%d,%d,%c%c%c,%d.%d.%d.%d/%d,%d,%d.%d.%d.%d/%d,%d)",
	       &add, &rule_id, &queue_id, &vlan,
	       &proto[0], &proto[1], &proto[2],
	       &s_a, &s_b, &s_c, &s_d, &s_mask, &s_port,
	       &d_a, &d_b, &d_c, &d_d, &d_mask, &d_port);

  debug_printk(2, "ring_proc_dev_rule_write(%s): num=%d (1)\n", buf, num);

  if(num == 19) {
    if(proto[0] == 't')
      protocol = 6; /* TCP */
    else /* if(proto[0] == 'u') */
      protocol = 17; /* UDP */

    rule.rule.rule_id = rule_id;
    init_intel_82599_perfect_filter_hw_rule(queue_id, protocol, vlan,
					    ((s_a & 0xff) << 24) + ((s_b & 0xff) << 16) + ((s_c & 0xff) << 8) + (s_d & 0xff), s_mask,
					    ((d_a & 0xff) << 24) + ((d_b & 0xff) << 16) + ((d_c & 0xff) << 8) + (d_d & 0xff), d_mask,
					    s_port, d_port, &rule.rule.rule_family.perfect_rule);
    rule.rule.rule_family_type = intel_82599_perfect_filter_rule;
    found = 1;
  }

  if(!found) {
    num = sscanf(buf, "%c(%d,%d,%c%c%c,%d.%d.%d.%d,%d,%d.%d.%d.%d,%d)",
		 &add, &rule_id, &queue_id,
		 &proto[0], &proto[1], &proto[2],
		 &s_a, &s_b, &s_c, &s_d, &s_port,
		 &d_a, &d_b, &d_c, &d_d, &d_port);

    debug_printk(2, "ring_proc_dev_rule_write(%s): num=%d (2)\n", buf, num);

    if(num == 16) {
      if(proto[0] == 't')
	protocol = 6; /* TCP */
      else if(proto[0] == 'u')
	protocol = 17; /* UDP */
      else
	protocol = 0; /* any */

      rule.rule.rule_id = rule_id;
      init_intel_82599_five_tuple_filter_hw_rule(queue_id, protocol,
						 ((s_a & 0xff) << 24) + ((s_b & 0xff) << 16) + ((s_c & 0xff) << 8) + (s_d & 0xff),
						 ((d_a & 0xff) << 24) + ((d_b & 0xff) << 16) + ((d_c & 0xff) << 8) + (d_d & 0xff),
						 s_port, d_port, &rule.rule.rule_family.five_tuple_rule);
      rule.rule.rule_family_type = intel_82599_five_tuple_rule;
      found = 1;
    }
  }

  if(!found)
    return(-1);

  rule.command = (add == '+') ? add_hw_rule : remove_hw_rule;
  rc = handle_hw_filtering_rule(dev_ptr->dev, &rule);

  if(rc != -1) {
    /* Rule programmed successfully */

    if(add == '+')
      dev_ptr->hw_filters.num_filters++, pfr->num_hw_filtering_rules++;
    else {
      if(dev_ptr->hw_filters.num_filters > 0)
	dev_ptr->hw_filters.num_filters--;

      pfr->num_hw_filtering_rules--;
    }
  }

  return((int)count);
}

#endif

/* ********************************** */

static char* direction2string(packet_direction d)
{
  switch(d) {
  case rx_and_tx_direction: return("RX+TX");
  case rx_only_direction:   return("RX only");
  case tx_only_direction:   return("TX only");
  }

  return("???");
}

/* ********************************** */

static char* sockmode2string(socket_mode m)
{
  switch(m) {
  case send_and_recv_mode: return("RX+TX");
  case recv_only_mode:     return("RX only");
  case send_only_mode:     return("TX only");
  }

  return("???");
}

/* ********************************** */

static int ring_proc_get_info(struct seq_file *m, void *data_not_used)
{
  FlowSlotInfo *fsi;

  if(m->private == NULL) {
    /* /proc/net/pf_ring/info */
    seq_printf(m, "PF_RING Version          : %s (%s)\n", RING_VERSION, GIT_REV);
    seq_printf(m, "Total rings              : %d\n", atomic_read(&ring_table_size));
    seq_printf(m, "\nStandard (non ZC) Options\n");
    seq_printf(m, "Ring slots               : %d\n", min_num_slots);
    seq_printf(m, "Slot version             : %d\n", RING_FLOWSLOT_VERSION);
    seq_printf(m, "Capture TX               : %s\n", enable_tx_capture ? "Yes [RX+TX]" : "No [RX only]");
    seq_printf(m, "IP Defragment            : %s\n", enable_ip_defrag ? "Yes" : "No");
    seq_printf(m, "Socket Mode              : %s\n", quick_mode ? "Quick" : "Standard");

    if(enable_frag_coherence) {
      purge_idle_fragment_cache();
      seq_printf(m, "Cluster Fragment Queue   : %u\n", num_cluster_fragments);
      seq_printf(m, "Cluster Fragment Discard : %u\n", num_cluster_discarded_fragments);
    }
  } else {
    /* Detailed statistics about a socket */
    struct pf_ring_socket *pfr = (struct pf_ring_socket *)m->private;

    if(pfr) {
      int num = 0;
      struct list_head *ptr, *tmp_ptr;
      fsi = pfr->slots_info;

      seq_printf(m, "Bound Device(s)        : ");

      if(pfr->custom_bound_device_name[0] != '\0') {
	seq_printf(m, pfr->custom_bound_device_name);
      } else {
        pf_ring_net *netns = netns_lookup(sock_net(pfr->sk));
        list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
 	  pf_ring_device *dev_ptr = list_entry(ptr, pf_ring_device, device_list);
          if (device_net_eq(dev_ptr, netns->net)) {
            int32_t dev_index = ifindex_to_pf_index(netns, dev_ptr->dev->ifindex);
            if(dev_index >= 0 && test_bit(dev_index, pfr->pf_dev_mask)) {
              seq_printf(m, "%s%s", (num > 0) ? "," : "", dev_ptr->dev->name);
              num++;
            }
          }
	}
      }

      seq_printf(m, "\n");

      seq_printf(m, "Active                 : %d\n", pfr->ring_active);
      seq_printf(m, "Breed                  : %s\n", (pfr->zc_device_entry != NULL) ? "ZC" : "Standard");
      seq_printf(m, "Appl. Name             : %s\n", pfr->appl_name[0] != '\0' ? pfr->appl_name : "<unknown>");
      seq_printf(m, "Socket Mode            : %s\n", sockmode2string(pfr->mode));
      if(pfr->mode != send_only_mode) {
        seq_printf(m, "Capture Direction      : %s\n", direction2string(pfr->direction));
        if(pfr->zc_device_entry == NULL) {
          seq_printf(m, "Sampling Rate          : %d\n", pfr->sample_rate);
          seq_printf(m, "Filtering Sampling Rate: %u\n", pfr->filtering_sample_rate);
          seq_printf(m, "IP Defragment          : %s\n", enable_ip_defrag ? "Yes" : "No");
          seq_printf(m, "BPF Filtering          : %s\n", pfr->bpfFilter ? "Enabled" : "Disabled");
          seq_printf(m, "Sw Filt Hash Rules     : %d\n", pfr->num_sw_filtering_hash);
          seq_printf(m, "Sw Filt WC Rules       : %d\n", pfr->num_sw_filtering_rules);
          seq_printf(m, "Sw Filt Hash Match     : %llu\n", pfr->sw_filtering_hash_match);
          seq_printf(m, "Sw Filt Hash Miss      : %llu\n", pfr->sw_filtering_hash_miss);
          seq_printf(m, "Sw Filt Hash Filtered  : %llu\n", pfr->sw_filtering_hash_filtered);
        }
        seq_printf(m, "Hw Filt Rules          : %d\n", pfr->num_hw_filtering_rules);
        seq_printf(m, "Poll Pkt Watermark     : %d\n", pfr->poll_num_pkts_watermark);
        seq_printf(m, "Num Poll Calls         : %u\n", pfr->num_poll_calls);
        seq_printf(m, "Poll Watermark Timeout : %u\n", pfr->poll_watermark_timeout);
      }

      if(pfr->zc_device_entry != NULL) {
        /* ZC */
        seq_printf(m, "Channel Id             : %d\n", pfr->zc_device_entry->zc_dev.channel_id);
        if(pfr->mode != send_only_mode)
          seq_printf(m, "Num RX Slots           : %d\n", pfr->zc_device_entry->zc_dev.mem_info.rx.packet_memory_num_slots);
        if(pfr->mode != recv_only_mode)
	  seq_printf(m, "Num TX Slots           : %d\n", pfr->zc_device_entry->zc_dev.mem_info.tx.packet_memory_num_slots);
      } else if(fsi != NULL) {
        /* Standard PF_RING */
	seq_printf(m, "Channel Id Mask        : 0x%016llX\n", pfr->channel_id_mask);
	seq_printf(m, "VLAN Id                : %d\n", pfr->vlan_id);
        if(pfr->cluster_id != 0)
          seq_printf(m, "Cluster Id             : %d\n", pfr->cluster_id);
	seq_printf(m, "Slot Version           : %d [%s]\n", fsi->version, RING_VERSION);
	seq_printf(m, "Min Num Slots          : %d\n", fsi->min_num_slots);
	seq_printf(m, "Bucket Len             : %d\n", fsi->data_len);
	seq_printf(m, "Slot Len               : %d [bucket+header]\n", fsi->slot_len);
	seq_printf(m, "Tot Memory             : %llu\n", fsi->tot_mem);
        if(pfr->mode != send_only_mode) {
	  seq_printf(m, "Tot Packets            : %lu\n", (unsigned long)fsi->tot_pkts);
	  seq_printf(m, "Tot Pkt Lost           : %lu\n", (unsigned long)fsi->tot_lost);
	  seq_printf(m, "Tot Insert             : %lu\n", (unsigned long)fsi->tot_insert);
	  seq_printf(m, "Tot Read               : %lu\n", (unsigned long)fsi->tot_read);
	  seq_printf(m, "Insert Offset          : %lu\n", (unsigned long)fsi->insert_off);
	  seq_printf(m, "Remove Offset          : %lu\n", (unsigned long)fsi->remove_off);
	  seq_printf(m, "Num Free Slots         : %lu\n",  (unsigned long)get_num_ring_free_slots(pfr));
        }
        if(pfr->mode != recv_only_mode) {
	  seq_printf(m, "TX: Send Ok            : %lu\n", (unsigned long)fsi->good_pkt_sent);
	  seq_printf(m, "TX: Send Errors        : %lu\n", (unsigned long)fsi->pkt_send_error);
        }
        if(pfr->mode != send_only_mode) {
	  seq_printf(m, "Reflect: Fwd Ok        : %lu\n", (unsigned long)fsi->tot_fwd_ok);
	  seq_printf(m, "Reflect: Fwd Errors    : %lu\n", (unsigned long)fsi->tot_fwd_notok);
        }
      }

      if (pfr->cluster_referee) {
        /* ZC cluster */
        struct list_head *obj_ptr, *obj_tmp_ptr;
        mutex_lock(&cluster_referee_lock);
        list_for_each_safe(obj_ptr, obj_tmp_ptr, &pfr->cluster_referee->objects_list) {
          cluster_object *obj_entry = list_entry(obj_ptr, cluster_object, list);
          switch (obj_entry->object_type) {
            case 1: /* OBJECT_GENERIC_QUEUE */
              seq_printf(m, "ZC-Queue-%u-Status      : %s\n",
                obj_entry->object_id, obj_entry->lock_bitmap ? "locked" : "available");
            break;
            case 2: /* OBJECT_BUFFERS_POOL */
              seq_printf(m, "ZC-Pool-%u-Status       : %s\n",
                obj_entry->object_id, obj_entry->lock_bitmap ? "locked" : "available");
            break;
            default:
            break;
          }
        }
        mutex_unlock(&cluster_referee_lock);
      }
    } else
      seq_printf(m, "WARNING m->private == NULL\n");
  }

  return 0;
}

/* ********************************** */

static void ring_proc_init(pf_ring_net *netns)
{
  netns->proc_dir = proc_mkdir("pf_ring", netns->net->proc_net);

  if(netns->proc_dir == NULL) {
    printk("[PF_RING] unable to create /proc/net/pf_ring [net=%pK]\n", netns->net);
    return;
  }

  netns->proc_dev_dir   = proc_mkdir(PROC_DEV,   netns->proc_dir);
  netns->proc_stats_dir = proc_mkdir(PROC_STATS, netns->proc_dir);

  netns->proc = proc_create(PROC_INFO /* name */,
			  0 /* read-only */,
			  netns->proc_dir /* parent */,
			  &ring_proc_fops /* file operations */);

  if(netns->proc == NULL) {
    printk("[PF_RING] unable to register proc file [net=%pK]\n", netns->net);
    return;
  }

  debug_printk(1, "registered /proc/net/pf_ring [net=%pK]\n", netns->net);
}

/* ********************************** */

static void ring_proc_term(pf_ring_net *netns)
{
  if(netns->proc_dir == NULL)
    return;

  debug_printk(1, "Removing /proc/net/pf_ring [net=%pK]\n", netns->net);

  remove_proc_entry(PROC_INFO,  netns->proc_dir);
  remove_proc_entry(PROC_STATS, netns->proc_dir);
  remove_proc_entry(PROC_DEV,   netns->proc_dir);

  if(netns->proc != NULL) {
    remove_proc_entry("pf_ring", netns->net->proc_net);
    debug_printk(1, "deregistered /proc/net/pf_ring [net=%pK]\n", netns->net);
  }
}

/* ********************************** */

static u_char *allocate_shared_memory(u_int64_t *mem_len)
{
  u_int64_t tot_mem = *mem_len;
  u_char *shared_mem;

  tot_mem = PAGE_ALIGN(tot_mem);

  /* Alignment necessary on ARM platforms */
  tot_mem += SHMLBA - (tot_mem % SHMLBA);

  /* Memory is already zeroed */
  shared_mem = vmalloc_user(tot_mem);

  *mem_len = tot_mem;
  return shared_mem;
}

static u_int32_t compute_ring_slot_len(struct pf_ring_socket *pfr, u_int32_t bucket_len) {
  u_int32_t slot_len;

  slot_len = pfr->slot_header_len + bucket_len;
  slot_len = ALIGN(slot_len + sizeof(u_int16_t) /* RING_MAGIC_VALUE */, sizeof(u_int64_t));

  return slot_len;
}

static u_int64_t compute_ring_tot_mem(u_int32_t min_num_slots, u_int32_t slot_len) {
  return (u_int64_t) sizeof(FlowSlotInfo) + ((u_int64_t) min_num_slots * slot_len);
}

static u_int32_t compute_ring_actual_min_num_slots(u_int64_t tot_mem, u_int32_t slot_len) {
  u_int64_t actual_min_num_slots;

  actual_min_num_slots = tot_mem - sizeof(FlowSlotInfo);
  do_div(actual_min_num_slots, slot_len);

  return actual_min_num_slots;
}

/*
 * Allocate ring memory used later on for
 * mapping it to userland
 */
static int ring_alloc_mem(struct sock *sk)
{
  u_int slot_len;
  u_int64_t tot_mem;
  struct pf_ring_socket *pfr = ring_sk(sk);
  u_int32_t num_slots = min_num_slots;

  /* Check if the memory has been already allocated */
  if(pfr->ring_memory != NULL) return(0);

  debug_printk(2, "ring_alloc_mem(bucket_len=%d)\n", pfr->bucket_len);

  /* **********************************************

   * *************************************
   * *                                   *
   * *        FlowSlotInfo               *
   * *                                   *
   * ************************************* <-+
   * *        FlowSlot                   *   |
   * *************************************   |
   * *        FlowSlot                   *   |
   * *************************************   +- >= min_num_slots
   * *        FlowSlot                   *   |
   * *************************************   |
   * *        FlowSlot                   *   |
   * ************************************* <-+
   *
   * ********************************************** */

  if(pfr->header_len == short_pkt_header)
    pfr->slot_header_len = offsetof(struct pfring_pkthdr, extended_hdr.tx); /* <ts,caplen,len,timestamp_ns,flags */
  else
    pfr->slot_header_len = sizeof(struct pfring_pkthdr);

  slot_len = compute_ring_slot_len(pfr, pfr->bucket_len);
  tot_mem = compute_ring_tot_mem(num_slots, slot_len);

  /* In case of jumbo MTU (9K) or lo (65K), recompute the ring size */
  if (pfr->bucket_len > 1600) {
    /* Compute the ring size assuming a standard MTU to limit the ring size */
    u_int32_t virtual_bucket_len = 1600, virtual_slot_len;
    virtual_slot_len = compute_ring_slot_len(pfr, virtual_bucket_len);
    tot_mem = compute_ring_tot_mem(num_slots, virtual_slot_len);
    num_slots = compute_ring_actual_min_num_slots(tot_mem, slot_len);

    /* Ensure a min num slots = MIN_NUM_SLOTS */
    if (num_slots < MIN_NUM_SLOTS) {
      /* Use the real bucket len, but limit the number of slots */
      num_slots = MIN_NUM_SLOTS;
      tot_mem = compute_ring_tot_mem(num_slots, slot_len);
    }

    debug_printk(1, "[PF_RING] Warning: jumbo mtu or snaplen (%u), resizing slots.. "
           "(num_slots = %u x slot_len = %u)\n",
      pfr->bucket_len, num_slots, slot_len);
  }

  if(tot_mem > UINT_MAX) {
    printk("[PF_RING] Warning: ring size (num_slots = %u x slot_len = %u) exceeds max, resizing..\n",
      num_slots, slot_len);
    tot_mem = UINT_MAX;
  }

  /* Memory is already zeroed */
  pfr->ring_memory = allocate_shared_memory(&tot_mem);

  if(pfr->ring_memory != NULL) {
    debug_printk(2, "successfully allocated %lu bytes at 0x%08lx\n",
	     (unsigned long) tot_mem, (unsigned long) pfr->ring_memory);
  } else {
    printk("[PF_RING] ERROR: not enough memory for ring\n");
    return(-1);
  }

  pfr->slots_info = (FlowSlotInfo *) pfr->ring_memory;
  pfr->ring_slots = (u_char *) (pfr->ring_memory + sizeof(FlowSlotInfo));

  pfr->slots_info->version = RING_FLOWSLOT_VERSION;
  pfr->slots_info->slot_len = slot_len;
  pfr->slots_info->data_len = pfr->bucket_len;
  pfr->slots_info->min_num_slots = compute_ring_actual_min_num_slots(tot_mem, slot_len);
  pfr->slots_info->tot_mem = tot_mem;
  pfr->slots_info->sample_rate = 1;

  debug_printk(2, "allocated %d slots [slot_len=%d][tot_mem=%llu]\n",
	   pfr->slots_info->min_num_slots, pfr->slots_info->slot_len,
	   pfr->slots_info->tot_mem);

  pfr->insert_page_id = 1, pfr->insert_slot_id = 0;
  pfr->sw_filtering_rules_default_accept_policy = 1;
  pfr->num_sw_filtering_hash = pfr->num_sw_filtering_rules = pfr->num_hw_filtering_rules = 0;

  return(0);
}

/* ********************************** */

/*
 * ring_insert()
 *
 * store the sk in a new element and add it
 * to the head of the list.
 */
static inline int ring_insert(struct sock *sk)
{
  struct pf_ring_socket *pfr;

  debug_printk(2, "ring_insert\n");

  if(lockless_list_add(&ring_table, sk) == -1)
    return -1;

  atomic_inc(&ring_table_size);

  pfr = (struct pf_ring_socket *) ring_sk(sk);
  bitmap_zero(pfr->pf_dev_mask, MAX_NUM_DEV_IDX);
  pfr->num_bound_devices = 0;

  return 0;
}

/* ********************************** */

/*
 * ring_remove()
 *
 * For each of the elements in the list:
 *  - check if this is the element we want to delete
 *  - if it is, remove it from the list, and free it.
 *
 * stop when we find the one we're looking for(break),
 * or when we reach the end of the list.
 */
static inline void ring_remove(struct sock *sk_to_delete)
{
  struct pf_ring_socket *pfr_to_delete = ring_sk(sk_to_delete);
  u_int8_t master_found = 0, socket_found = 0;
  u_int32_t last_list_idx;
  struct sock *sk;

  debug_printk(2, "ring_remove()\n");

  sk = (struct sock*)lockless_list_get_first(&ring_table, &last_list_idx);

  while(sk != NULL) {
    struct pf_ring_socket *pfr;

    pfr = ring_sk(sk);

    if(pfr->master_ring == pfr_to_delete) {
      debug_printk(2, "Removing master ring\n");

      pfr->master_ring = NULL, master_found = 1;
    } else if(sk == sk_to_delete) {
      debug_printk(2, "Found socket to remove\n");

      socket_found = 1;
    }

    if(master_found && socket_found)
      break;
    else
      sk = (struct sock*)lockless_list_get_next(&ring_table, &last_list_idx);
  }

  if(socket_found) {
    if(lockless_list_remove(&ring_table, sk_to_delete) == -1)
      printk("[PF_RING] WARNING: Unable to find socket to remove!!\n");
    else
      atomic_dec(&ring_table_size);
  } else
    printk("[PF_RING] WARNING: Unable to find socket to remove!!!\n");

  debug_printk(2, "leaving ring_remove()\n");
}

/* ********************************** */

static inline u_int32_t hash_pkt(u_int16_t vlan_id,
                                 u_int8_t smac[ETH_ALEN], u_int8_t dmac[ETH_ALEN],
                                 u_int8_t ip_version, u_int8_t l3_proto,
                                 ip_addr host_peer_a, ip_addr host_peer_b,
                                 u_int16_t port_peer_a, u_int16_t port_peer_b)
{
  u_char i;
  u_int32_t hash = vlan_id;

  if(ip_version == 4)
    hash += host_peer_a.v4 + host_peer_b.v4;
  else if(ip_version == 6)
  {
    for (i=0 ; i < 4 ; ++i)
      hash += host_peer_a.v6.s6_addr32[i]
            + host_peer_b.v6.s6_addr32[i];
  }
  else if(l3_proto == 0)    /* non-IP protocols */
  {
    for (i=0 ; i < ETH_ALEN ; ++i)
      hash += smac[i] + dmac[i];
  }
  hash += l3_proto + port_peer_a + port_peer_b;
  return hash;
}

/* ********************************** */

#define HASH_PKT_HDR_RECOMPUTE   (1<<0)
#define HASH_PKT_HDR_MASK_SRC    (1<<1)
#define HASH_PKT_HDR_MASK_DST    (1<<2)
#define HASH_PKT_HDR_MASK_PORT   (1<<3)
#define HASH_PKT_HDR_MASK_PROTO  (1<<4)
#define HASH_PKT_HDR_MASK_VLAN   (1<<5)
#define HASH_PKT_HDR_MASK_TUNNEL (1<<6)
#define HASH_PKT_HDR_MASK_MAC    (1<<7)

static inline u_int32_t hash_pkt_header(struct pfring_pkthdr *hdr, u_int32_t flags)
{
  if(hdr->extended_hdr.pkt_hash == 0 || (flags & HASH_PKT_HDR_RECOMPUTE))
  {
    u_int8_t use_tunneled = hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id != NO_TUNNEL_ID &&
        !(flags & HASH_PKT_HDR_MASK_TUNNEL);

    hdr->extended_hdr.pkt_hash = hash_pkt(
      (flags & HASH_PKT_HDR_MASK_VLAN)
        ? 0 : hdr->extended_hdr.parsed_pkt.vlan_id,
      (flags & HASH_PKT_HDR_MASK_MAC)
        ? zeromac : (use_tunneled ? hdr->extended_hdr.parsed_pkt.tunnel.tunneled_smac
                                  : hdr->extended_hdr.parsed_pkt.smac),
      (flags & HASH_PKT_HDR_MASK_MAC)
        ? zeromac : (use_tunneled ? hdr->extended_hdr.parsed_pkt.tunnel.tunneled_dmac
                                  : hdr->extended_hdr.parsed_pkt.dmac),
      use_tunneled ? hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_version
                   : hdr->extended_hdr.parsed_pkt.ip_version,
      (flags & HASH_PKT_HDR_MASK_PROTO)
        ? 0 : (use_tunneled ? hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto
                            : hdr->extended_hdr.parsed_pkt.l3_proto),
      (flags & HASH_PKT_HDR_MASK_SRC)
        ? ip_zero : (use_tunneled ? hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src
                                  : hdr->extended_hdr.parsed_pkt.ip_src),
      (flags & HASH_PKT_HDR_MASK_DST)
        ? ip_zero : (use_tunneled ? hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst
                                  : hdr->extended_hdr.parsed_pkt.ip_dst),
      (flags & (HASH_PKT_HDR_MASK_SRC | HASH_PKT_HDR_MASK_PORT))
        ? 0 : (use_tunneled ? hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port
                            : hdr->extended_hdr.parsed_pkt.l4_src_port),
      (flags & (HASH_PKT_HDR_MASK_DST | HASH_PKT_HDR_MASK_PORT))
        ? 0 : (use_tunneled ? hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port
                            : hdr->extended_hdr.parsed_pkt.l4_dst_port));
  }

  return hdr->extended_hdr.pkt_hash;
}

/* ******************************************************* */

static int parse_raw_pkt(u_char *data, u_int data_len,
			 struct pfring_pkthdr *hdr,
			 u_int16_t *ip_id)
{
  struct ethhdr *eh = (struct ethhdr *)data;
  u_int16_t displ = sizeof(struct ethhdr), ip_len, fragment_offset = 0, tunnel_offset = 0;
  u_int16_t tunnel_len;

  memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt));

  /* Default */
  hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = NO_TUNNEL_ID;
  *ip_id = 0;

  if(data_len < sizeof(struct ethhdr)) return(0);

  /* MAC address */
  memcpy(&hdr->extended_hdr.parsed_pkt.dmac, eh->h_dest, sizeof(eh->h_dest));
  memcpy(&hdr->extended_hdr.parsed_pkt.smac, eh->h_source, sizeof(eh->h_source));

  hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);

  if(hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_8021Q /* 802.1q (VLAN) */) {
    struct eth_vlan_hdr *vh;

    hdr->extended_hdr.parsed_pkt.offset.vlan_offset = sizeof(struct ethhdr);
    vh = (struct eth_vlan_hdr *) &data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset];
    hdr->extended_hdr.parsed_pkt.vlan_id = ntohs(vh->h_vlan_id) & VLAN_VID_MASK;
    hdr->extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
    displ += sizeof(struct eth_vlan_hdr);

    if(hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_8021Q /* 802.1q (VLAN) */) { /* QinQ */
      hdr->extended_hdr.parsed_pkt.offset.vlan_offset += sizeof(struct eth_vlan_hdr);
      vh = (struct eth_vlan_hdr *) &data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset];
      hdr->extended_hdr.parsed_pkt.qinq_vlan_id = ntohs(vh->h_vlan_id) & VLAN_VID_MASK;
      hdr->extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
      displ += sizeof(struct eth_vlan_hdr);

      while (hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_8021Q /* 802.1q (VLAN) */) { /* More QinQ */
	if ((displ + sizeof(struct eth_vlan_hdr)) >= data_len)
          return(0);
        hdr->extended_hdr.parsed_pkt.offset.vlan_offset += sizeof(struct eth_vlan_hdr);
        vh = (struct eth_vlan_hdr *) &data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset];
        hdr->extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
        displ += sizeof(struct eth_vlan_hdr);
      }
    }
  }

  if(hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_MPLS_UC /* MPLS Unicast Traffic */) {
    int i = 0, max_tags = 10, last_tag = 0;
    u_int32_t tag;
    u_int16_t iph_start;

    for (i = 0; i < max_tags && !last_tag; i++) {
      if ((displ + 4) >= data_len)
        return(0);

      tag = htonl(*((u_int32_t *) (&data[displ])));

      if(tag & 0x00000100) /* Found last MPLS tag */
        last_tag = 1;

      displ += 4;
    }

    if(i == max_tags) /* max tags reached for MPLS packet */
      return(0);

    iph_start = htons(*((u_int16_t *) (&data[displ])));

    if((iph_start & 0x4000) == 0x4000) { /* Found IP4 Packet after tags */
      hdr->extended_hdr.parsed_pkt.eth_type = ETH_P_IP;
    } else if((iph_start & 0x6000) == 0x6000) { /* Found IP6 Packet after tags */
      hdr->extended_hdr.parsed_pkt.eth_type = ETH_P_IPV6;
    } else { /* Cannot determine packet type after MPLS labels */
      return(0);
    }
  }

  hdr->extended_hdr.parsed_pkt.offset.l3_offset = displ;

  if(hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_IP /* IPv4 */) {
    struct iphdr *ip;
    u_int16_t frag_off;

    hdr->extended_hdr.parsed_pkt.ip_version = 4;

    if(data_len < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct iphdr)) return(0);

    ip = (struct iphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);
    *ip_id = ip->id, frag_off = ntohs(ip->frag_off);

    if(frag_off & 0x1FFF /* Fragment offset */)
      hdr->extended_hdr.flags |= PKT_FLAGS_IP_FRAG_OFFSET; /* Packet offset > 0 */
    if(frag_off & 0x2000 /* More Fragments set */)
      hdr->extended_hdr.flags |= PKT_FLAGS_IP_MORE_FRAG;

    hdr->extended_hdr.parsed_pkt.ipv4_src = ntohl(ip->saddr);
    hdr->extended_hdr.parsed_pkt.ipv4_dst = ntohl(ip->daddr);
    hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
    hdr->extended_hdr.parsed_pkt.ipv4_tos = ip->tos;
    fragment_offset = ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
    ip_len  = ip->ihl*4;
  } else if(hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_IPV6 /* IPv6 */) {
    struct kcompact_ipv6_hdr *ipv6;

    hdr->extended_hdr.parsed_pkt.ip_version = 6;

    if(data_len < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct kcompact_ipv6_hdr)) return(0);

    ipv6 = (struct kcompact_ipv6_hdr*)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);
    ip_len = sizeof(struct kcompact_ipv6_hdr);

    /* Values of IPv6 addresses are stored as network byte order */
    memcpy(&hdr->extended_hdr.parsed_pkt.ip_src.v6, &ipv6->saddr, sizeof(ipv6->saddr));
    memcpy(&hdr->extended_hdr.parsed_pkt.ip_dst.v6, &ipv6->daddr, sizeof(ipv6->daddr));

    hdr->extended_hdr.parsed_pkt.l3_proto = ipv6->nexthdr;
    hdr->extended_hdr.parsed_pkt.ipv6_tos = ipv6->priority; /* IPv6 class of service */

    /*
      RFC2460 4.1  Extension Header Order
      IPv6 header
      Hop-by-Hop Options header
      Destination Options header
      Routing header
      Fragment header
      Authentication header
      Encapsulating Security Payload header
      Destination Options header
      upper-layer header
    */

    /* Note: NEXTHDR_AUTH, NEXTHDR_ESP, NEXTHDR_IPV6, NEXTHDR_MOBILITY are not handled */
    while (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP	    ||
	   hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST    ||
	   hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING ||
	   hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_FRAGMENT) {
      struct kcompact_ipv6_opt_hdr *ipv6_opt;

      if(data_len < hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len + sizeof(struct kcompact_ipv6_opt_hdr))
        return 1;

      ipv6_opt = (struct kcompact_ipv6_opt_hdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len]);
      ip_len += sizeof(struct kcompact_ipv6_opt_hdr);
      if(hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP     ||
          hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST    ||
          hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING)
        ip_len += ipv6_opt->hdrlen * 8;

      hdr->extended_hdr.parsed_pkt.l3_proto = ipv6_opt->nexthdr;
    }

    if(hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_NONE)
      hdr->extended_hdr.parsed_pkt.l3_proto = 0;

  } else {
    hdr->extended_hdr.parsed_pkt.l3_proto = 0;
    return(0); /* No IP */
  }

  if (ip_len == 0)
    return(0); /* Bogus IP */

  hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset+ip_len;

  if(!fragment_offset) {
    if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {          /* TCP */
      struct tcphdr *tcp;

      if(data_len < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct tcphdr)) return(1);
      tcp = (struct tcphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

      hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source);
      hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + (tcp->doff * 4);
      hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq);
      hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
      hdr->extended_hdr.parsed_pkt.tcp.flags = (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
	(tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
	(tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);
    } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {   /* UDP */
      struct udphdr *udp;

      if(data_len < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr)) return(1);
      udp = (struct udphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

      hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr);

      /* GTP */
      if((hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_SIGNALING_PORT)
         || (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_SIGNALING_PORT)
	 || (hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_U_DATA_PORT)
	 || (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_U_DATA_PORT)) {
	struct gtp_v1_hdr *gtp;

        if(data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+sizeof(struct gtp_v1_hdr))) return(1);

        gtp = (struct gtp_v1_hdr *) (&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset]);
	tunnel_len = sizeof(struct gtp_v1_hdr);

	if(((gtp->flags & GTP_FLAGS_VERSION) >> GTP_FLAGS_VERSION_SHIFT) == GTP_VERSION_1) {
          struct iphdr *tunneled_ip;

	  hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = ntohl(gtp->teid);

	  if((hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_U_DATA_PORT)
	     || (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_U_DATA_PORT)) {
	    if(gtp->flags & (GTP_FLAGS_EXTENSION | GTP_FLAGS_SEQ_NUM | GTP_FLAGS_NPDU_NUM)) {
	      struct gtp_v1_opt_hdr *gtpopt;

	      if(data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len+sizeof(struct gtp_v1_opt_hdr)))
		return(1);

	      gtpopt = (struct gtp_v1_opt_hdr *) (&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset + tunnel_len]);
	      tunnel_len += sizeof(struct gtp_v1_opt_hdr);

	      if((gtp->flags & GTP_FLAGS_EXTENSION) && gtpopt->next_ext_hdr) {
		struct gtp_v1_ext_hdr *gtpext;
		u_int8_t *next_ext_hdr = NULL;

		do {
		  if(data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len+1 /* 8 bit len field */)) return(1);
		  gtpext = (struct gtp_v1_ext_hdr *) (&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len]);
		  tunnel_len += (gtpext->len * GTP_EXT_HDR_LEN_UNIT_BYTES);
		  if((gtpext->len == 0) || (data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len))) return(1);
		  next_ext_hdr = (u_int8_t *) (&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len-1 /* 8 bit next_ext_hdr field */]);
		} while(*next_ext_hdr != 0);
	      }
	    }

parse_tunnel_ip:
	    if(data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len+sizeof(struct iphdr))) return(1);
	    tunneled_ip = (struct iphdr *) (&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset + tunnel_len]);

	    if(tunneled_ip->version == 4 /* IPv4 */) {
	      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_version = 4;
	      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4 = ntohl(tunneled_ip->saddr);
	      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4 = ntohl(tunneled_ip->daddr);
	      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ip->protocol;
	      fragment_offset = tunneled_ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
	      ip_len = tunneled_ip->ihl*4;
	      tunnel_offset = hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len+ip_len;
	    } else if(tunneled_ip->version == 6 /* IPv6 */) {
	      struct kcompact_ipv6_hdr* tunneled_ipv6;

	      if(data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len+sizeof(struct kcompact_ipv6_hdr))) return(1);
	      tunneled_ipv6 = (struct kcompact_ipv6_hdr *) (&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset + tunnel_len]);

	      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_version = 6;
	      /* Values of IPv6 addresses are stored as network byte order */
	      memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6, &tunneled_ipv6->saddr, sizeof(tunneled_ipv6->saddr));
	      memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6, &tunneled_ipv6->daddr, sizeof(tunneled_ipv6->daddr));
	      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ipv6->nexthdr;

	      ip_len = sizeof(struct kcompact_ipv6_hdr), tunnel_offset = hdr->extended_hdr.parsed_pkt.offset.payload_offset+tunnel_len;

	      while(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_HOP
		    || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_DEST
		    || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ROUTING
		    || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_AUTH
		    || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ESP
		    || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_FRAGMENT) {
		struct kcompact_ipv6_opt_hdr *ipv6_opt;

		if(data_len < (tunnel_offset+ip_len+sizeof(struct kcompact_ipv6_opt_hdr))) return(1);

		ipv6_opt = (struct kcompact_ipv6_opt_hdr *)(&data[tunnel_offset+ip_len]);
		ip_len += sizeof(struct kcompact_ipv6_opt_hdr), fragment_offset = 0;
		if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_AUTH)
		  /*
		    RFC4302 2.2. Payload Length: This 8-bit field specifies the
		    length of AH in 32-bit words (4-byte units), minus "2".
		  */
		  ip_len += ipv6_opt->hdrlen * 4;
		else if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto != NEXTHDR_FRAGMENT)
		  ip_len += ipv6_opt->hdrlen;

		hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = ipv6_opt->nexthdr;
	      } /* while */

	      tunnel_offset += ip_len;
	    } else {
	      return(1);
            }

            if (ip_len == 0)
              return(1); /* Bogus IP */

	  parse_tunneled_packet:
	    if(!fragment_offset) {
	      if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_TCP) {
		struct tcphdr *tcp;

		if(data_len < tunnel_offset + sizeof(struct tcphdr)) return(1);
		tcp = (struct tcphdr *)(&data[tunnel_offset]);

		hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(tcp->source),
		  hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(tcp->dest);
	      } else if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_UDP) {
		struct udphdr *udp;

		if(data_len < tunnel_offset + sizeof(struct udphdr)) return(1);
		udp = (struct udphdr *)(&data[tunnel_offset]);

		hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(udp->source),
		  hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(udp->dest);

		if((hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port == MOBILE_IP_PORT)
		   || (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port == MOBILE_IP_PORT)) {
		  /* FIX: missing implementation (TODO) */
		}
	      }
	    }
	  }
	}
      } else if((hdr->extended_hdr.parsed_pkt.l4_src_port == MOBILE_IP_PORT)
		|| (hdr->extended_hdr.parsed_pkt.l4_dst_port == MOBILE_IP_PORT)) {
	/* FIX: missing implementation (TODO) */
      } else if(((hdr->extended_hdr.parsed_pkt.l4_src_port == VXLAN_IP_PORT)
                 || (hdr->extended_hdr.parsed_pkt.l4_dst_port == VXLAN_IP_PORT))
                && (data_len > hdr->extended_hdr.parsed_pkt.offset.payload_offset + sizeof(struct vxlan_hdr) + 14)) {
        struct vxlan_hdr *vxlanh = (struct vxlan_hdr *) (&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset]);
        if((vxlanh->flags[0] & 0x08) && vxlanh->res == 0) {
          hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = (vxlanh->vni[0] << 16) + (vxlanh->vni[1] << 8) + vxlanh->vni[2];
          eh = (struct ethhdr *) (&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset+sizeof(struct vxlan_hdr)]);
          memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_dmac, eh->h_dest, sizeof(eh->h_dest));
          memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_smac, eh->h_source, sizeof(eh->h_source));
          tunnel_len = sizeof(struct vxlan_hdr) + 14;
          switch(ntohs(eh->h_proto)) {
            case ETH_P_ARP:
              break;
            case ETH_P_IP:
            case ETH_P_IPV6:
              goto parse_tunnel_ip;
              break;
            default:
              debug_printk(2, "VXLAN found unsupported Ethertype:%04X\n", ntohs(eh->h_proto));
          }
        }
      }
    } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_GRE /* 0x47 */) {    /* GRE */
      struct gre_header *gre = (struct gre_header*)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);
      int gre_offset;

      if(data_len < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct gre_header)) return(1);

      gre->flags_and_version = ntohs(gre->flags_and_version);
      gre->proto = ntohs(gre->proto);
      gre_offset = sizeof(struct gre_header);
      if((gre->flags_and_version & GRE_HEADER_VERSION) == 0) {
        if(gre->flags_and_version & (GRE_HEADER_CHECKSUM | GRE_HEADER_ROUTING)) gre_offset += 4;
        if(gre->flags_and_version & GRE_HEADER_KEY) {
	  u_int32_t *tunnel_id = (u_int32_t*)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset+gre_offset]);
	  gre_offset += 4;
	  hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = ntohl(*tunnel_id);
        }
        if(gre->flags_and_version & GRE_HEADER_SEQ_NUM)  gre_offset += 4;

        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + gre_offset;

        if(gre->proto == ETH_P_IP /* IPv4 */) {
	  struct iphdr *tunneled_ip;

	  if(data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+sizeof(struct iphdr))) return(1);
	  tunneled_ip = (struct iphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset]);

	  hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_version = 4;
	  hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4 = ntohl(tunneled_ip->saddr);
	  hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4 = ntohl(tunneled_ip->daddr);
	  hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ip->protocol;

	  fragment_offset = tunneled_ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
	  ip_len = tunneled_ip->ihl*4;
	  tunnel_offset = hdr->extended_hdr.parsed_pkt.offset.payload_offset + ip_len;
        } else if(gre->proto == ETH_P_IPV6 /* IPv6 */) {
	  struct kcompact_ipv6_hdr* tunneled_ipv6;

	  if(data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+sizeof(struct kcompact_ipv6_hdr))) return(1);
	  tunneled_ipv6 = (struct kcompact_ipv6_hdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset]);

	  hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_version = 6;
	  /* Values of IPv6 addresses are stored as network byte order */
	  memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6, &tunneled_ipv6->saddr, sizeof(tunneled_ipv6->saddr));
	  memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6, &tunneled_ipv6->daddr, sizeof(tunneled_ipv6->daddr));
	  hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ipv6->nexthdr;

	  ip_len = sizeof(struct kcompact_ipv6_hdr), tunnel_offset = hdr->extended_hdr.parsed_pkt.offset.payload_offset;

	  while(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_HOP
		|| hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_DEST
		|| hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ROUTING
		|| hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_AUTH
		|| hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ESP
		|| hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_FRAGMENT) {
	    struct kcompact_ipv6_opt_hdr *ipv6_opt;

	    if(data_len < (tunnel_offset+ip_len+sizeof(struct kcompact_ipv6_opt_hdr))) return(1);

	    ipv6_opt = (struct kcompact_ipv6_opt_hdr *)(&data[tunnel_offset+ip_len]);
	    ip_len += sizeof(struct kcompact_ipv6_opt_hdr), fragment_offset = 0;
	    if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_AUTH)
	      ip_len += ipv6_opt->hdrlen * 4;
	    else if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto != NEXTHDR_FRAGMENT)
	      ip_len += ipv6_opt->hdrlen;

	    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = ipv6_opt->nexthdr;
	  } /* while */

	  tunnel_offset += ip_len;
        } else {
	  return(1);
        }

        if (ip_len == 0)
          return(1); /* Bogus IP */

	goto parse_tunneled_packet; /* Parse tunneled ports */
      } else { /* TODO handle other GRE versions */
	hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
      }

    } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_ICMP) {  /* ICMP */
      struct icmphdr *icmp;

      icmp = (struct icmphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);
      hdr->extended_hdr.parsed_pkt.icmp_type = icmp->type;
      hdr->extended_hdr.parsed_pkt.icmp_code = icmp->code;
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct icmphdr);

    } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_SCTP) { /* SCTP */
      struct sctphdr *sctp;

      sctp = (struct sctphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);
      hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(sctp->source);
      hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(sctp->dest);
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct sctphdr);

    } else { /* Unknown protocol */
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
    }

  } else { /* Fragment */
    hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
  }

  hash_pkt_header(hdr, 0);

  return(1); /* IP */
}

/* ********************************** */

static int parse_pkt(struct sk_buff *skb,
		     u_int8_t real_skb,
		     int skb_displ,
		     struct pfring_pkthdr *hdr,
		     u_int16_t *ip_id)
{
  u_char buffer[128]; /* Enough for standard and tunneled headers */
  int data_len = min((u_int16_t)(skb->len + skb_displ), (u_int16_t)sizeof(buffer));
  u_int16_t vlan_id;
  int rc;

  /* hdr->extended_hdr.process.pid = task_pid_nr(current); */
  
  skb_copy_bits(skb, -skb_displ, buffer, data_len);

  rc = parse_raw_pkt(buffer, data_len, hdr, ip_id);

  /* Check for stripped vlan id (hw offload) */

  if(__vlan_hwaccel_get_tag(skb, &vlan_id) == 0 && vlan_id != 0 &&
     !(hdr->extended_hdr.flags & PKT_FLAGS_VLAN_HWACCEL)) { 

    hdr->extended_hdr.flags |= PKT_FLAGS_VLAN_HWACCEL;

    vlan_id &= VLAN_VID_MASK;

    if (hdr->extended_hdr.parsed_pkt.vlan_id != 0)
      hdr->extended_hdr.parsed_pkt.qinq_vlan_id = hdr->extended_hdr.parsed_pkt.vlan_id;
    hdr->extended_hdr.parsed_pkt.vlan_id = vlan_id;

    hash_pkt_header(hdr, HASH_PKT_HDR_RECOMPUTE); /* force hash recomputation */

    if (hdr->extended_hdr.parsed_pkt.offset.vlan_offset == 0)
      hdr->extended_hdr.parsed_pkt.offset.vlan_offset = sizeof(struct ethhdr);
    else /* QinQ */
      hdr->extended_hdr.parsed_pkt.offset.vlan_offset += sizeof(struct eth_vlan_hdr);

    hdr->extended_hdr.parsed_pkt.offset.l3_offset += sizeof(struct eth_vlan_hdr);
    if (hdr->extended_hdr.parsed_pkt.offset.l4_offset)
      hdr->extended_hdr.parsed_pkt.offset.l4_offset += sizeof(struct eth_vlan_hdr);

    if (hdr->extended_hdr.parsed_pkt.offset.payload_offset)
      hdr->extended_hdr.parsed_pkt.offset.payload_offset += sizeof(struct eth_vlan_hdr);
  }
  
  return(rc);
}

/* ********************************** */

static int hash_bucket_match(sw_filtering_hash_bucket *hash_bucket,
                             struct pfring_pkthdr *hdr,
                             u_char mask_src, u_char mask_dst)
{
  /*
    When protocol of host_peer is IPv4, s6_addr32[0] contains IPv4
    address and the value of other elements of s6_addr32 are 0.
  */
  if(hash_bucket->rule.ip_version == hdr->extended_hdr.parsed_pkt.ip_version &&
     hash_bucket->rule.proto == hdr->extended_hdr.parsed_pkt.l3_proto &&
     hash_bucket->rule.vlan_id == hdr->extended_hdr.parsed_pkt.vlan_id &&
     ((hash_bucket->rule.host4_peer_a == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_src) &&
       hash_bucket->rule.host4_peer_b == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_dst) &&
       hash_bucket->rule.port_peer_a  == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.l4_src_port) &&
       hash_bucket->rule.port_peer_b  == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.l4_dst_port))
      ||
      (hash_bucket->rule.host4_peer_a == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_dst) &&
       hash_bucket->rule.host4_peer_b == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_src) &&
       hash_bucket->rule.port_peer_a  == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.l4_dst_port) &&
       hash_bucket->rule.port_peer_b  == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.l4_src_port)))) {
    if(hdr->extended_hdr.parsed_pkt.ip_version == 6) {
      if((memcmp(&hash_bucket->rule.host6_peer_a, (mask_src ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_src), sizeof(ip_addr)) == 0 &&
          memcmp(&hash_bucket->rule.host6_peer_b, (mask_dst ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_dst), sizeof(ip_addr)) == 0)
	   ||
	 (memcmp(&hash_bucket->rule.host6_peer_a, (mask_dst ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_dst), sizeof(ip_addr)) == 0 &&
	  memcmp(&hash_bucket->rule.host6_peer_b, (mask_src ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_src), sizeof(ip_addr)) == 0)) {
        return 1;
      }
    } else { /* ip_version == 4 */
      return 1;
    }
  }

  return 0;
}

/* ********************************** */

static inline int hash_filtering_rule_match(hash_filtering_rule *a,
					    hash_filtering_rule *b)
{
  debug_printk_rules_comparison(2, a, b);

  if((a->ip_version == b->ip_version)
      &&(a->proto == b->proto)
      && (a->vlan_id == b->vlan_id)
      && (((a->host4_peer_a == b->host4_peer_a)
      && (a->host4_peer_b == b->host4_peer_b)
      && (a->port_peer_a == b->port_peer_a)
      && (a->port_peer_b == b->port_peer_b))
    ||
     ((a->host4_peer_a == b->host4_peer_b)
      && (a->host4_peer_b == b->host4_peer_a)
      && (a->port_peer_a == b->port_peer_b)
      && (a->port_peer_b == b->port_peer_a)))) {
      if(a->ip_version == 6) {
        if(((memcmp(&a->host6_peer_a, &b->host6_peer_a, sizeof(ip_addr)) == 0)
             && (memcmp(&a->host6_peer_b, &b->host6_peer_b, sizeof(ip_addr)) == 0))
           ||
             ((memcmp(&a->host6_peer_a, &b->host6_peer_b, sizeof(ip_addr)) == 0)
             && (memcmp(&a->host6_peer_b, &b->host6_peer_a, sizeof(ip_addr)) == 0))) {
           return 1;
        }
      } else { /* ip_version == 4 */
        return 1;
      }
  }

  return 0;
}

/* ********************************** */

static inline int hash_bucket_match_rule(sw_filtering_hash_bucket *hash_bucket,
				  hash_filtering_rule *rule)
{
  return hash_filtering_rule_match(&hash_bucket->rule, rule);
}

/* ********************************** */

static inline int match_ipv6(ip_addr *addr, ip_addr *rule_addr, ip_addr *rule_mask) {
  int i;
  if(rule_mask->v6.s6_addr32[0] != 0)
    for(i=0; i<4; i++)
      if((addr->v6.s6_addr32[i] & rule_mask->v6.s6_addr32[i]) != rule_addr->v6.s6_addr32[i])
        return(0);
  return(1);
}

/* ********************************** */

/* 0 = no match, 1 = match */
static int match_filtering_rule(struct pf_ring_socket *pfr,
				sw_filtering_rule_element * rule,
				struct pfring_pkthdr *hdr,
				struct sk_buff *skb,
				int displ,
				rule_action_behaviour *behaviour)
{
  u_int8_t empty_mac[ETH_ALEN] = { 0 }; /* NULL MAC address */

  debug_printk(2, "\n");

  *behaviour = rule->rule.rule_action;

   if((hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP)
      && rule->rule.core_fields.tcp.flags > 0
      && (hdr->extended_hdr.parsed_pkt.tcp.flags != rule->rule.core_fields.tcp.flags))
     return(0);

  if((rule->rule.core_fields.if_index > 0)
     && (hdr->extended_hdr.if_index != UNKNOWN_INTERFACE)
     && (hdr->extended_hdr.if_index != rule->rule.core_fields.if_index))
    return(0);

  if((rule->rule.core_fields.vlan_id > 0)
     && (hdr->extended_hdr.parsed_pkt.vlan_id != rule->rule.core_fields.vlan_id))
    return(0);

  if((rule->rule.core_fields.eth_type > 0)
       && (hdr->extended_hdr.parsed_pkt.eth_type != rule->rule.core_fields.eth_type))
      return(0);

  if((rule->rule.core_fields.proto > 0)
     && (hdr->extended_hdr.parsed_pkt.l3_proto != rule->rule.core_fields.proto))
    return(0);

  if((rule->rule.extended_fields.optional_fields & FILTER_TUNNEL_ID_FLAG)
     && (hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id != rule->rule.extended_fields.tunnel.tunnel_id))
    return(0);

  if(hdr->extended_hdr.parsed_pkt.ip_version == 6) {
    /* IPv6 */
    if(!match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_src,
		   &rule->rule.extended_fields.tunnel.dhost,
		   &rule->rule.extended_fields.tunnel.dhost_mask)
       || !match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_dst,
		      &rule->rule.extended_fields.tunnel.shost,
		      &rule->rule.extended_fields.tunnel.shost_mask))
      return(0);
  } else {
    /* IPv4 */
    if((hdr->extended_hdr.parsed_pkt.ip_src.v4 & rule->rule.extended_fields.tunnel.dhost_mask.v4) != rule->rule.extended_fields.tunnel.dhost.v4
       || (hdr->extended_hdr.parsed_pkt.ip_dst.v4 & rule->rule.extended_fields.tunnel.shost_mask.v4) != rule->rule.extended_fields.tunnel.shost.v4)
      return(0);
  }

  if((memcmp(rule->rule.core_fields.dmac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.dmac, rule->rule.core_fields.dmac, ETH_ALEN) != 0))
    goto swap_direction;

  if((memcmp(rule->rule.core_fields.smac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.smac, rule->rule.core_fields.smac, ETH_ALEN) != 0))
    goto swap_direction;

  if(hdr->extended_hdr.parsed_pkt.ip_version == 6) {
    /* IPv6 */
    if(!match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_src,
		   &rule->rule.core_fields.shost,
		   &rule->rule.core_fields.shost_mask)
       || !match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_dst,
		      &rule->rule.core_fields.dhost,
		      &rule->rule.core_fields.dhost_mask))
        goto swap_direction;
  } else {
    /* IPv4 */
    if((hdr->extended_hdr.parsed_pkt.ip_src.v4 & rule->rule.core_fields.shost_mask.v4) != rule->rule.core_fields.shost.v4
       || (hdr->extended_hdr.parsed_pkt.ip_dst.v4 & rule->rule.core_fields.dhost_mask.v4) != rule->rule.core_fields.dhost.v4)
        goto swap_direction;
  }

  if((rule->rule.core_fields.sport_high != 0)
    && ((hdr->extended_hdr.parsed_pkt.l4_src_port < rule->rule.core_fields.sport_low)
	|| (hdr->extended_hdr.parsed_pkt.l4_src_port > rule->rule.core_fields.sport_high)))
    goto swap_direction;

  if((rule->rule.core_fields.dport_high != 0)
     && ((hdr->extended_hdr.parsed_pkt.l4_dst_port < rule->rule.core_fields.dport_low)
	 || (hdr->extended_hdr.parsed_pkt.l4_dst_port > rule->rule.core_fields.dport_high)))
    goto swap_direction;

  goto success;

swap_direction:

  if(!rule->rule.bidirectional)
    return(0);

  if((memcmp(rule->rule.core_fields.dmac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.smac, rule->rule.core_fields.dmac, ETH_ALEN) != 0))
    return(0);

  if((memcmp(rule->rule.core_fields.smac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.dmac, rule->rule.core_fields.smac, ETH_ALEN) != 0))
    return(0);

  if(hdr->extended_hdr.parsed_pkt.ip_version == 6) {
    /* IPv6 */
    if(!match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_src,
		   &rule->rule.core_fields.dhost,
		   &rule->rule.core_fields.dhost_mask)
       || !match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_dst,
		      &rule->rule.core_fields.shost,
		      &rule->rule.core_fields.shost_mask))
      return(0);
  } else {
    /* IPv4 */
    if((hdr->extended_hdr.parsed_pkt.ip_src.v4 & rule->rule.core_fields.dhost_mask.v4) != rule->rule.core_fields.dhost.v4
       || (hdr->extended_hdr.parsed_pkt.ip_dst.v4 & rule->rule.core_fields.shost_mask.v4) != rule->rule.core_fields.shost.v4)
      return(0);
  }

  if((rule->rule.core_fields.sport_high != 0)
    && ((hdr->extended_hdr.parsed_pkt.l4_dst_port < rule->rule.core_fields.sport_low)
	|| (hdr->extended_hdr.parsed_pkt.l4_dst_port > rule->rule.core_fields.sport_high)))
    return(0);

  if((rule->rule.core_fields.dport_high != 0)
     && ((hdr->extended_hdr.parsed_pkt.l4_src_port < rule->rule.core_fields.dport_low)
	 || (hdr->extended_hdr.parsed_pkt.l4_src_port > rule->rule.core_fields.dport_high)))
    return(0);

success:

  if(rule->rule.balance_pool > 0) {
    u_int32_t balance_hash = hash_pkt_header(hdr, 0) % rule->rule.balance_pool;

    if(balance_hash != rule->rule.balance_id)
      return(0);
  }

#ifdef CONFIG_TEXTSEARCH
  if(rule->pattern[0] != NULL) {
    debug_printk(2, "pattern\n");

    if((hdr->extended_hdr.parsed_pkt.offset.payload_offset > 0)
       && (hdr->caplen > hdr->extended_hdr.parsed_pkt.offset.payload_offset)) {
      char *payload = (char *)&(skb->data[hdr->extended_hdr.parsed_pkt.offset.payload_offset /* -displ */ ]);
      int rc = 0, payload_len =
	hdr->caplen - hdr->extended_hdr.parsed_pkt.offset.payload_offset - displ;

      if(payload_len > 0) {
	int i;
	struct ts_state state;

	if(debug_on(2)) {
	  debug_printk(2, "Trying to match pattern [caplen=%d][len=%d][displ=%d][payload_offset=%d][",
		 hdr->caplen, payload_len, displ,
		 hdr->extended_hdr.parsed_pkt.offset.payload_offset);

	  for(i = 0; i < payload_len; i++)
	    printk("[%d/%c]", i, payload[i] & 0xFF);
	  printk("]\n");
	}

	payload[payload_len] = '\0';

	debug_printk(2, "Attempt to match [%s]\n", payload);

	for(i = 0; (i < MAX_NUM_PATTERN) && (rule->pattern[i] != NULL); i++) {
	  debug_printk(2, "Attempt to match pattern %d\n", i);
	  rc = (textsearch_find_continuous
		(rule->pattern[i], &state,
		 payload, payload_len) != UINT_MAX) ? 1 : 0;
	  if(rc == 1)
	    break;
	}

	debug_printk(2, "Match returned: %d [payload_len=%d][%s]\n",
		 rc, payload_len, payload);

	if(rc == 0)
	  return(0);	/* No match */
      } else
	return(0);	/* No payload data */
    } else
      return(0);	/* No payload data */
  }
#endif

  *behaviour = rule->rule.rule_action;

  debug_printk(2, "MATCH (ifindex=%d, vlan=%u, proto=%u, sip=%u, sport=%u, dip=%u, dport=%u)\n"
                  "      [rule(ifindex=%d, vlan=%u, proto=%u, ip=%u:%u, port=%u:%u-%u:%u)(behaviour=%d)]\n",
           hdr->extended_hdr.if_index,
	   hdr->extended_hdr.parsed_pkt.vlan_id, hdr->extended_hdr.parsed_pkt.l3_proto,
	   hdr->extended_hdr.parsed_pkt.ipv4_src, hdr->extended_hdr.parsed_pkt.l4_src_port,
	   hdr->extended_hdr.parsed_pkt.ipv4_dst, hdr->extended_hdr.parsed_pkt.l4_dst_port,
           rule->rule.core_fields.if_index,
	   rule->rule.core_fields.vlan_id,
	   rule->rule.core_fields.proto,
	   rule->rule.core_fields.shost.v4,
	   rule->rule.core_fields.dhost.v4,
	   rule->rule.core_fields.sport_low, rule->rule.core_fields.sport_high,
	   rule->rule.core_fields.dport_low, rule->rule.core_fields.dport_high,
	   *behaviour);

  rule->rule.internals.jiffies_last_match = jiffies;

  return(1); /* match */
}

/* ********************************** */

static inline void set_skb_time(struct sk_buff *skb, struct pfring_pkthdr *hdr)
{
  /* BD - API changed for time keeping */
  if(ktime_to_ns(skb->tstamp) == 0)
    __net_timestamp(skb); /* If timestamp is missing add it */

  hdr->ts = ktime_to_timeval(skb->tstamp);

  /* Use hardware timestamps when present. If not, just use software timestamps */
  hdr->extended_hdr.timestamp_ns = ktime_to_ns(skb_hwtstamps(skb)->hwtstamp);

  //debug_printk(2, "hwts=%llu/dev=%s\n",
  //    hdr->extended_hdr.timestamp_ns,
  //    skb->dev ? skb->dev->name : "???");

  if(hdr->extended_hdr.timestamp_ns == 0)
    hdr->extended_hdr.timestamp_ns = ktime_to_ns(skb->tstamp);
}

/* ********************************** */

/*
  Generic function for copying either a skb or a raw
  memory block to the ring buffer

  Return:
  - 0 = packet was not copied (e.g. slot was full)
  - 1 = the packet was copied (i.e. there was room for it)
*/
static inline int copy_data_to_ring(struct sk_buff *skb,
				    struct pf_ring_socket *pfr,
				    struct pfring_pkthdr *hdr,
				    int displ, int offset,
				    void *raw_data, uint raw_data_len)
{
  u_char *ring_bucket;
  u_int64_t off;
  u_short do_lock = (
    (skb->dev->type == ARPHRD_LOOPBACK) ||
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0))
    (netif_is_bridge_master(skb->dev)) ||
#else
    (skb->dev->priv_flags & IFF_EBRIDGE) ||
#endif
    (enable_tx_capture && pfr->direction != rx_only_direction) ||
    (pfr->num_channels_per_ring > 1) ||
    (pfr->channel_id_mask == RING_ANY_CHANNEL && lock_rss_queues(skb->dev)) ||
    (pfr->rehash_rss != NULL && get_num_rx_queues(skb->dev) > 1) ||
    (pfr->num_bound_devices > 1) ||
    (pfr->cluster_id != 0) ||
    (force_ring_lock)
  );

  if(pfr->ring_slots == NULL) return(0);

  /* We need to lock as two ksoftirqd might put data onto the same ring */

  if(do_lock) spin_lock_bh(&pfr->ring_index_lock);
  // smp_rmb();

  if(pfr->tx.enable_tx_with_bounce && pfr->header_len == long_pkt_header
     && pfr->slots_info->kernel_remove_off != pfr->slots_info->remove_off /* optimization to avoid too many locks */
     && pfr->slots_info->remove_off != get_next_slot_offset(pfr, pfr->slots_info->kernel_remove_off)) {
    spin_lock_bh(&pfr->tx.consume_tx_packets_lock);
    consume_pending_pkts(pfr, 0);
    spin_unlock_bh(&pfr->tx.consume_tx_packets_lock);
  }

  off = pfr->slots_info->insert_off;
  pfr->slots_info->tot_pkts++;

  if(!check_free_ring_slot(pfr)) /* Full */ {
    /* No room left */

    pfr->slots_info->tot_lost++;

   if(do_lock) spin_unlock_bh(&pfr->ring_index_lock);
    return(0);
  }

  ring_bucket = get_slot(pfr, off);

  if(skb != NULL) {
    /* Copy skb data */

    hdr->caplen = min_val(hdr->caplen, pfr->bucket_len - offset);

    if(hdr->ts.tv_sec == 0)
      set_skb_time(skb, hdr);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
    if(skb->dev->features & NETIF_F_RXCSUM) {
      hdr->extended_hdr.flags |= PKT_FLAGS_CHECKSUM_OFFLOAD;
      if(skb_csum_unnecessary(skb))
        hdr->extended_hdr.flags |= PKT_FLAGS_CHECKSUM_OK;
    }
#endif

    if(hdr->caplen > 0) {

      if (hdr->extended_hdr.flags & PKT_FLAGS_VLAN_HWACCEL) {
	/* VLAN-tagged packet with stripped VLAN tag */
        u_int16_t *b;
        struct vlan_ethhdr *v = vlan_eth_hdr(skb);
        u16 vlan_tci = 0;

        /* Reading vlan_tci from skb again as we need the tci including priority */
        __vlan_hwaccel_get_tag(skb, &vlan_tci);

        /* len/caplen reset outside, we can increment all the time */
	hdr->len += sizeof(struct eth_vlan_hdr);
	hdr->caplen = min_val(pfr->bucket_len - offset, hdr->caplen + sizeof(struct eth_vlan_hdr));

        skb_copy_bits(skb, -displ, &ring_bucket[pfr->slot_header_len + offset], 12 /* MAC src/dst */);

        b = (u_int16_t*) &ring_bucket[pfr->slot_header_len + offset + 12 /* MAC src/dst */];
        b[0] = ntohs(ETH_P_8021Q), b[1] = htons(vlan_tci /* including priority */), b[2] = v->h_vlan_proto;

        if(skb_copy_bits(skb, -displ + sizeof(struct ethhdr),
             &ring_bucket[pfr->slot_header_len + offset + sizeof(struct ethhdr) + sizeof(struct eth_vlan_hdr)],
             (int) hdr->caplen - (sizeof(struct ethhdr) + sizeof(struct eth_vlan_hdr))) < 0)
          printk("[PF_RING] %s: vlan reinjection error [skb->len=%u][caplen=%u]\n", __FUNCTION__,
		 skb->len, (unsigned int) (hdr->caplen - (sizeof(struct ethhdr) + sizeof(struct eth_vlan_hdr))));

      } else {
        skb_copy_bits(skb, -displ, &ring_bucket[pfr->slot_header_len + offset], (int) hdr->caplen);
      }
    }

    if(pfr->tx.enable_tx_with_bounce &&
        pfr->header_len == long_pkt_header &&
        skb != NULL) {
      /* The TX transmission is supported only with long_pkt_header
       * where we can read the id of the output interface */

      hdr->extended_hdr.tx.reserved = skb_clone(skb, GFP_ATOMIC);

      if(displ > 0) {
        skb_push(hdr->extended_hdr.tx.reserved, displ);
      }
    }
  } else {
    /* Copy Raw data */
    hdr->len = raw_data_len;
    hdr->caplen = min_val(raw_data_len, pfr->bucket_len);
    memcpy(&ring_bucket[pfr->slot_header_len], raw_data, hdr->caplen);
    if(pfr->header_len == long_pkt_header)
      hdr->extended_hdr.if_index = FAKE_PACKET;
    /* printk("[PF_RING] Copied raw data at slot with offset %d [len=%d, caplen=%d]\n", off, hdr->len, hdr->caplen); */
  }

  /* Copy extended packet header */
  memcpy(ring_bucket, hdr, pfr->slot_header_len);

  /* Set Magic value */
  memset(&ring_bucket[pfr->slot_header_len + offset + hdr->caplen], RING_MAGIC_VALUE, sizeof(u_int16_t));

  /* Update insert offset */
  pfr->slots_info->insert_off = get_next_slot_offset(pfr, off);

  /* NOTE: smp_* barriers are _compiler_ barriers on UP, mandatory barriers on SMP
   * a consumer _must_ see the new value of tot_insert only after the buffer update completes */
  smp_mb(); //wmb();

  pfr->slots_info->tot_insert++;

 if(do_lock) spin_unlock_bh(&pfr->ring_index_lock);

 if(num_queued_pkts(pfr) >= pfr->poll_num_pkts_watermark)
    wake_up_interruptible(&pfr->ring_slots_waitqueue);

  return(1);
}

/* ********************************** */

static inline int copy_raw_data_to_ring(struct pf_ring_socket *pfr,
				 struct pfring_pkthdr *dummy_hdr,
				 void *raw_data, uint raw_data_len)
{
  return(copy_data_to_ring(NULL, pfr, dummy_hdr, 0, 0, raw_data, raw_data_len));
}

/* ********************************** */

static inline int add_pkt_to_ring(struct sk_buff *skb,
				  u_int8_t real_skb,
				  struct pf_ring_socket *_pfr,
				  struct pfring_pkthdr *hdr,
				  int displ, int channel_id,
				  int offset)
{
  struct pf_ring_socket *pfr = (_pfr->master_ring != NULL) ? _pfr->master_ring : _pfr;
  u_int64_t channel_id_bit = ((u_int64_t) ((u_int64_t) 1) << channel_id);

  if((!pfr->ring_active) || (!skb))
    return(0);

  if((pfr->channel_id_mask != RING_ANY_CHANNEL)
     && (channel_id != -1 /* any channel */)
     && (!(pfr->channel_id_mask & channel_id_bit)))
    return(0); /* Wrong channel */

  if(real_skb)
    return(copy_data_to_ring(skb, pfr, hdr, displ, offset, NULL, 0));
  else
    return(copy_raw_data_to_ring(pfr, hdr, skb->data, hdr->len));
}

/* ********************************** */

static void free_filtering_rule(sw_filtering_rule_element * entry, u_int8_t freeing_ring)
{
#ifdef CONFIG_TEXTSEARCH
  int i;
#endif

#ifdef CONFIG_TEXTSEARCH
  for(i = 0; (i < MAX_NUM_PATTERN) && (entry->pattern[i] != NULL); i++)
    textsearch_destroy(entry->pattern[i]);
#endif

  if(entry->rule.internals.reflector_dev != NULL)
    dev_put(entry->rule.internals.reflector_dev); /* Release device */
}

/* ************************************* */

static void free_sw_filtering_hash_bucket(sw_filtering_hash_bucket * bucket)
{
  if(bucket->rule.internals.reflector_dev != NULL)
    dev_put(bucket->rule.internals.reflector_dev);	/* Release device */
}

/*
  NOTE

  I jeopardize the get_coalesce/set_eeprom fields for my purpose
  until hw filtering support is part of the kernel

*/

/* ************************************* */

static int handle_sw_filtering_hash_bucket(struct pf_ring_socket *pfr,
					   sw_filtering_hash_bucket *rule,
					   u_char add_rule)
{
  int rc = -1;
  u_int32_t hash_idx;

  if(rule->rule.ip_version != 4 && rule->rule.ip_version != 6) /* safety check */
    return(-EINVAL);

  hash_idx = hash_pkt(rule->rule.vlan_id, zeromac, zeromac,
                      rule->rule.ip_version, rule->rule.proto,
	              rule->rule.host_peer_a, rule->rule.host_peer_b,
                      rule->rule.port_peer_a, rule->rule.port_peer_b)
    % perfect_rules_hash_size;

  debug_printk_rule_info(2, &rule->rule, "hash_idx=%u rule_id=%u add_rule=%d\n",
    hash_idx, rule->rule.rule_id, add_rule);

  if(add_rule) {

    /* Checking reflector device */
    if(rule->rule.reflector_device_name[0] != '\0') {
      if((pfr->ring_dev->dev != NULL) &&
         rule->rule.rule_action != bounce_packet_and_stop_rule_evaluation &&
         rule->rule.rule_action != bounce_packet_and_continue_rule_evaluation &&
         (strcmp(rule->rule.reflector_device_name, pfr->ring_dev->dev->name) == 0)) {
	debug_printk(2, "You cannot use as reflection device the same device on "
	       "which this ring is bound\n");
        return(-EFAULT);
      }

      rule->rule.internals.reflector_dev = dev_get_by_name(sock_net(pfr->sk), rule->rule.reflector_device_name);

      if(rule->rule.internals.reflector_dev == NULL) {
        printk("[PF_RING] Unable to find device %s\n",
	       rule->rule.reflector_device_name);
        return(-EFAULT);
      }
    } else
      rule->rule.internals.reflector_dev = NULL;

    /* initialiting hash table */
    if(pfr->sw_filtering_hash == NULL) {
      pfr->sw_filtering_hash = (sw_filtering_hash_bucket **)
	kcalloc(perfect_rules_hash_size, sizeof(sw_filtering_hash_bucket *), GFP_ATOMIC);

      if(pfr->sw_filtering_hash == NULL) {
        debug_printk(2, "returned %d [0]\n", -EFAULT);
        return(-EFAULT);
      }

      debug_printk(2, "allocated memory\n");
    }
  }

  if(pfr->sw_filtering_hash == NULL) {
    /* We're trying to delete a hash rule from an empty hash */
    return(-EFAULT);
  }

  if(pfr->sw_filtering_hash[hash_idx] == NULL) {
    if(add_rule) {
      rule->next = NULL;
      pfr->sw_filtering_hash[hash_idx] = rule;
      rc = 0;
    } else {
      debug_printk(2, "returned %d [1]\n", -1);
      return(-1);	/* Unable to find the specified rule */
    }
  } else {
    sw_filtering_hash_bucket *prev = NULL, *bucket = pfr->sw_filtering_hash[hash_idx];

    while(bucket != NULL) {
      if(hash_filtering_rule_match(&bucket->rule, &rule->rule)) {
	if(add_rule) {
	  debug_printk(1, "duplicate found (rule_id=%u) while adding rule (rule_id=%u): discarded\n",
	  	       bucket->rule.rule_id, rule->rule.rule_id);
	  return(-EEXIST);
	} else {
	  /* We've found the bucket to delete */

	  debug_printk(2, "found a bucket to delete: removing it\n");
	  if(prev == NULL)
	    pfr->sw_filtering_hash[hash_idx] = bucket->next;
	  else
	    prev->next = bucket->next;

	  free_sw_filtering_hash_bucket(bucket);
	  kfree(bucket);
	  pfr->num_sw_filtering_hash--;
	  debug_printk(2, "returned %d [2]\n", 0);
	  return(0);
	}
      } else {
	prev = bucket;
	bucket = bucket->next;
      }
    }

    if(add_rule) {
      /* If the flow arrived until here, then this rule is unique */
      debug_printk(2, "no duplicate rule found: adding the rule\n");

      rule->next = pfr->sw_filtering_hash[hash_idx];
      pfr->sw_filtering_hash[hash_idx] = rule;
      rc = 0;
    } else {
      /* The rule we searched for has not been found */
      rc = -1;
    }
  }

  if(add_rule && rc == 0) {
    pfr->num_sw_filtering_hash++;

    /* Avoid immediate rule purging */
    rule->rule.internals.jiffies_last_match = jiffies;
  }

  debug_printk(2, "returned %d [3]\n", rc);

  return(rc);
}

/* ************************************* */

static int add_sw_filtering_rule_element(struct pf_ring_socket *pfr, sw_filtering_rule_element *rule)
{
  struct list_head *ptr;
  int idx = 0;
  sw_filtering_rule_element *entry;
  struct list_head *prev = NULL;

  /* Implement an ordered add looking backwards (probably we have incremental ids) */
  prev = &pfr->sw_filtering_rules;
  list_for_each_prev(ptr, &pfr->sw_filtering_rules) {
    entry = list_entry(ptr, sw_filtering_rule_element, list);

    if(entry->rule.rule_id == rule->rule.rule_id) {
      printk("[PF_RING] %s:%d Rule already exists (rule_id=%u)\n", __FUNCTION__, __LINE__, rule->rule.rule_id);
      return(-EEXIST);
    }

    if(entry->rule.rule_id < rule->rule.rule_id)
      break;

    prev = ptr; /* position where to insert the new entry after checks */
  }

  /* Rule checks */

  if(rule->rule.reflector_device_name[0] != '\0') {
    if((pfr->ring_dev->dev != NULL) &&
       rule->rule.rule_action != bounce_packet_and_stop_rule_evaluation &&
       rule->rule.rule_action != bounce_packet_and_continue_rule_evaluation &&
       (strcmp(rule->rule.reflector_device_name, pfr->ring_dev->dev->name) == 0)) {
      debug_printk(2, "You cannot use as reflection device the same device on which this ring is bound\n");
      return(-EFAULT);
    }

    rule->rule.internals.reflector_dev = dev_get_by_name(sock_net(pfr->sk), rule->rule.reflector_device_name);

    if(rule->rule.internals.reflector_dev == NULL) {
      printk("[PF_RING] Unable to find device %s\n", rule->rule.reflector_device_name);
      return(-EFAULT);
    }
  } else
    rule->rule.internals.reflector_dev = NULL;

  debug_printk(2, "SO_ADD_FILTERING_RULE: About to add rule %d\n",
	   rule->rule.rule_id);

  /* Compile pattern if present */
  if(strlen(rule->rule.extended_fields.payload_pattern) > 0) {
    char *pattern = rule->rule.extended_fields.payload_pattern;

    printk("[PF_RING] About to compile pattern '%s'\n", pattern);

    while(pattern && (idx < MAX_NUM_PATTERN)) {
      char *pipe = strchr(pattern, '|');

      if(pipe)
	pipe[0] = '\0';

#ifdef CONFIG_TEXTSEARCH
      rule->pattern[idx] = textsearch_prepare("bm"	/* Boyer-Moore */
					      /* "kmp" = Knuth-Morris-Pratt */
					      , pattern, strlen(pattern),
					      GFP_KERNEL,
					      TS_AUTOLOAD
#ifdef TS_IGNORECASE
					      | TS_IGNORECASE
#endif
					      );
      if(rule->pattern[idx])
	printk("[PF_RING] Compiled pattern '%s' [idx=%d]\n", pattern, idx);
#endif
      if(pipe)
	pattern = &pipe[1], idx++;
      else
	break;
    }
  } else {
#ifdef CONFIG_TEXTSEARCH
    rule->pattern[0] = NULL;
#endif
  }

  list_add_tail(&rule->list, prev);
  pfr->num_sw_filtering_rules++;
  rule->rule.internals.jiffies_last_match = jiffies; /* Avoid immediate rule purging */

  return(0);
}

/* ************************************* */

static int remove_sw_filtering_rule_element(struct pf_ring_socket *pfr, u_int16_t rule_id)
{
  int rule_found = 0;
  struct list_head *ptr, *tmp_ptr;

  list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
    sw_filtering_rule_element *entry;
    entry = list_entry(ptr, sw_filtering_rule_element, list);

    if(entry->rule.rule_id == rule_id) {
      list_del(ptr);
      free_filtering_rule(entry, 0);
      kfree(entry);

      pfr->num_sw_filtering_rules--;

      debug_printk(2, "SO_REMOVE_FILTERING_RULE: rule %d has been removed\n", rule_id);
      rule_found = 1;
      break;
    }
  }	/* for */

  return(rule_found);
}

/* ********************************** */

static int reflect_packet(struct sk_buff *skb,
			  struct pf_ring_socket *pfr,
			  struct net_device *reflector_dev,
			  int displ,
			  rule_action_behaviour behaviour,
			  u_int8_t do_clone_skb)
{
  int ret;
  struct sk_buff *cloned;

  debug_printk(2, "reflect_packet(%s) called\n", reflector_dev->name);

  if(reflector_dev == NULL || !(reflector_dev->flags & IFF_UP) /* interface down */ ) {
    pfr->slots_info->tot_fwd_notok++;
    return -ENETDOWN;
  }

  if(do_clone_skb) {
    cloned = skb_clone(skb, GFP_ATOMIC);
    if(cloned == NULL) {
      pfr->slots_info->tot_fwd_notok++;
      return -ENOMEM;
    }
  } else {
    cloned = skb;
  }

  cloned->pkt_type = PACKET_OUTGOING;
  cloned->dev = reflector_dev;

  if(displ > 0) {
    skb_push(cloned, displ);
  }

  skb_reset_network_header(skb);

  if(behaviour == bounce_packet_and_stop_rule_evaluation ||
      behaviour == bounce_packet_and_continue_rule_evaluation) {
    char dst_mac[6];
    /* Swap mac addresses (be aware that data is also forwarded to userspace) */
    memcpy(dst_mac, cloned->data, 6);
    memcpy(cloned->data, &cloned->data[6], 6);
    memcpy(&cloned->data[6], dst_mac, 6);
  }

  ret = dev_queue_xmit(cloned);

  debug_printk(2, "dev_queue_xmit(%s) returned %d\n", reflector_dev->name, ret);

  if(ret != NETDEV_TX_OK) {
    pfr->slots_info->tot_fwd_notok++;
    return -ENETDOWN;
  }

  pfr->slots_info->tot_fwd_ok++;
  return 0;
}

/* ********************************** */

int check_perfect_rules(struct sk_buff *skb,
			struct pf_ring_socket *pfr,
			struct pfring_pkthdr *hdr,
			int *fwd_pkt,
			int displ,
			sw_filtering_hash_bucket **p_hash_bucket)
{
  u_int32_t hash_idx;
  sw_filtering_hash_bucket *hash_bucket;
  int hash_found = 0;

  hash_idx = hash_pkt(
    hdr->extended_hdr.parsed_pkt.vlan_id,
    hdr->extended_hdr.parsed_pkt.smac,
    hdr->extended_hdr.parsed_pkt.dmac,
    hdr->extended_hdr.parsed_pkt.ip_version,
    hdr->extended_hdr.parsed_pkt.l3_proto,
    hdr->extended_hdr.parsed_pkt.ip_src,
    hdr->extended_hdr.parsed_pkt.ip_dst,
    hdr->extended_hdr.parsed_pkt.l4_src_port,
    hdr->extended_hdr.parsed_pkt.l4_dst_port)
    % perfect_rules_hash_size;
  hash_bucket = pfr->sw_filtering_hash[hash_idx];

  while(hash_bucket != NULL) {
    if(hash_bucket_match(hash_bucket, hdr, 0, 0)) {
      *p_hash_bucket = hash_bucket;
      hash_found = 1;
      break;
    } else
      hash_bucket = hash_bucket->next;
  } /* while */

  if(hash_found) {
    rule_action_behaviour behaviour = forward_packet_and_stop_rule_evaluation;

    behaviour = hash_bucket->rule.rule_action;

    switch(behaviour) {
    case forward_packet_and_stop_rule_evaluation:
      *fwd_pkt = 1;
      break;
    case dont_forward_packet_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      break;
    case execute_action_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      break;
    case execute_action_and_continue_rule_evaluation:
      *fwd_pkt = 0;
      hash_found = 0;	/* This way we also evaluate the list of rules */
      break;
    case forward_packet_add_rule_and_stop_rule_evaluation:
      *fwd_pkt = 1;
      break;
    case reflect_packet_and_stop_rule_evaluation:
    case bounce_packet_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      reflect_packet(skb, pfr, hash_bucket->rule.internals.reflector_dev, displ, behaviour, 1);
      break;
    case reflect_packet_and_continue_rule_evaluation:
    case bounce_packet_and_continue_rule_evaluation:
      *fwd_pkt = 0;
      reflect_packet(skb, pfr, hash_bucket->rule.internals.reflector_dev, displ, behaviour, 1);
      hash_found = 0;	/* This way we also evaluate the list of rules */
      break;
    }
  }

  return(hash_found);
}

/* ********************************** */

int check_wildcard_rules(struct sk_buff *skb,
			 struct pf_ring_socket *pfr,
			 struct pfring_pkthdr *hdr,
			 int *fwd_pkt,
			 int displ)
{
  struct list_head *ptr, *tmp_ptr;

  debug_printk(2, "Entered check_wildcard_rules()\n");

  read_lock_bh(&pfr->ring_rules_lock);

  list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
    sw_filtering_rule_element *entry;
    rule_action_behaviour behaviour = forward_packet_and_stop_rule_evaluation;

    entry = list_entry(ptr, sw_filtering_rule_element, list);

    debug_printk(2, "Checking rule %d\n", entry->rule.rule_id);

    if(match_filtering_rule(pfr, entry, hdr, skb, displ, &behaviour)) {
      debug_printk(2, "Packet MATCH\n");

      debug_printk(2, "rule_id=%d behaviour=%d\n", entry->rule.rule_id, behaviour);

      hdr->extended_hdr.parsed_pkt.last_matched_rule_id = entry->rule.rule_id;

      if(behaviour == forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 1;
	break;
      } else if(behaviour == forward_packet_add_rule_and_stop_rule_evaluation) {
	sw_filtering_hash_bucket  *hash_bucket  = NULL;
	int rc = 0;
	*fwd_pkt = 1;

	/* we have done with rule evaluation,
	 * now we need a write_lock to add rules */
	read_unlock_bh(&pfr->ring_rules_lock);

	/* Creating an hash rule from packet headers */
	hash_bucket = (sw_filtering_hash_bucket *)kcalloc(1, sizeof(sw_filtering_hash_bucket), GFP_ATOMIC);

	if(hash_bucket != NULL) {
	  hash_bucket->rule.vlan_id = hdr->extended_hdr.parsed_pkt.vlan_id;
	  hash_bucket->rule.ip_version = hdr->extended_hdr.parsed_pkt.ip_version;
	  hash_bucket->rule.proto = hdr->extended_hdr.parsed_pkt.l3_proto;
	  hash_bucket->rule.host4_peer_a = hdr->extended_hdr.parsed_pkt.ipv4_src;
	  hash_bucket->rule.host4_peer_b = hdr->extended_hdr.parsed_pkt.ipv4_dst;
	  hash_bucket->rule.port_peer_a = hdr->extended_hdr.parsed_pkt.l4_src_port;
	  hash_bucket->rule.port_peer_b = hdr->extended_hdr.parsed_pkt.l4_dst_port;
	  hash_bucket->rule.rule_action = forward_packet_and_stop_rule_evaluation;
	  hash_bucket->rule.reflector_device_name[0] = '\0';
	  hash_bucket->rule.internals.reflector_dev = NULL;

          write_lock_bh(&pfr->ring_rules_lock);
	  rc = handle_sw_filtering_hash_bucket(pfr, hash_bucket, 1 /* add rule */);
	  write_unlock_bh(&pfr->ring_rules_lock);

	  if(rc != 0) {
	    kfree(hash_bucket);
	    hash_bucket = NULL;
	  } else {
	    debug_printk(2, "Added rule: [%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d][tot_rules=%d]\n",
		     ((hash_bucket->rule.host4_peer_a >> 24) & 0xff), ((hash_bucket->rule.host4_peer_a >> 16) & 0xff),
		     ((hash_bucket->rule.host4_peer_a >> 8) & 0xff), ((hash_bucket->rule.host4_peer_a >> 0) & 0xff),
		     hash_bucket->rule.port_peer_a, ((hash_bucket->rule.host4_peer_b >> 24) & 0xff),
		     ((hash_bucket->rule.host4_peer_b >> 16) & 0xff), ((hash_bucket->rule.host4_peer_b >> 8) & 0xff),
		     ((hash_bucket->rule.host4_peer_b >> 0) & 0xff), hash_bucket->rule.port_peer_b, pfr->num_sw_filtering_hash);
	  }
	}

        /* Negative return values are not handled by the caller, it is better to return always 0.
	 * Note: be careful with unlock code when moving this */
        return(0);

	break;
      } else if(behaviour == dont_forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 0;
	break;
      }

      if(entry->rule.rule_action == forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 1;
	break;
      } else if(entry->rule.rule_action == dont_forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 0;
	break;
      } else if(entry->rule.rule_action == execute_action_and_stop_rule_evaluation) {
	printk("[PF_RING] *** execute_action_and_stop_rule_evaluation\n");
	break;
      } else if(entry->rule.rule_action == execute_action_and_continue_rule_evaluation) {
	/* The action has already been performed inside match_filtering_rule()
	   hence instead of stopping rule evaluation, the next rule
	   will be evaluated */
      } else if((entry->rule.rule_action == reflect_packet_and_stop_rule_evaluation)
		|| (entry->rule.rule_action == bounce_packet_and_stop_rule_evaluation)) {
	*fwd_pkt = 0;
	reflect_packet(skb, pfr, entry->rule.internals.reflector_dev, displ, entry->rule.rule_action, 1);
	break;
      } else if((entry->rule.rule_action == reflect_packet_and_continue_rule_evaluation)
		|| (entry->rule.rule_action == bounce_packet_and_continue_rule_evaluation)) {
	*fwd_pkt = 1;
	reflect_packet(skb, pfr, entry->rule.internals.reflector_dev, displ, entry->rule.rule_action, 1);
      }
    } else {
      debug_printk(2, "Packet not matched\n");
    }
  }  /* for */

  read_unlock_bh(&pfr->ring_rules_lock);

  return(0);
}

/* ********************************** */

int bpf_filter_skb(struct sk_buff *skb,
		   struct pf_ring_socket *pfr,
		   int displ)
{
  unsigned res = 1;
  u8 *skb_head = skb->data;
  int skb_len = skb->len;
  struct sk_filter *filter;

  if(displ > 0) {
    /* Move off the offset (we modify the packet for the sake of filtering)
     * thus we need to restore it later on
     * NOTE: displ = 0 | skb_network_offset(skb) */
    skb_push(skb, displ);
  }

  rcu_read_lock();

  filter = rcu_dereference(pfr->sk->sk_filter);

  if(filter != NULL) {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
    res = sk_run_filter(skb, filter->insns, filter->len);
#elif(LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0))
    res = sk_run_filter(skb, filter->insns);
#elif(LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
    res = SK_RUN_FILTER(filter, skb);
#else
    //res = (sk_filter(pfr->sk, skb) == 0) ? 1 : 0;
    res = bpf_prog_run_clear_cb(filter->prog, skb);
#endif
  }

  rcu_read_unlock();

  /* Restore */
  if(displ > 0) {
    /* skb_pull(skb, displ); */
    skb->data = skb_head;
    skb->len = skb_len;
  }

  if(debug_on(2) && res == 0 /* Filter failed */ )
    debug_printk(2, "skb filtered out by bpf [len=%d][tot=%llu]"
	   "[insert_off=%llu][pkt_type=%d][cloned=%d]\n",
	   (int)skb->len, pfr->slots_info->tot_pkts,
	   pfr->slots_info->insert_off, skb->pkt_type,
	   skb->cloned);

  return res; /* 0 to drop packet */
}

/* ********************************** */

u_int32_t default_rehash_rss_func(struct sk_buff *skb, struct pfring_pkthdr *hdr)
{
  return hash_pkt_header(hdr, 0);
}

/* ********************************** */

/*
 * Add the specified skb to the ring so that userland apps
 * can use the packet.
 *
 * Return code:
 *  0 packet successully processed but no room in the ring
 *  1 packet successully processed and available room in the ring
 * -1  processing error (e.g. the packet has been discarded by
 *                       filter, ring not active...)
 *
 */
static int add_skb_to_ring(struct sk_buff *skb,
			   u_int8_t real_skb,
			   struct pf_ring_socket *pfr,
			   struct pfring_pkthdr *hdr,
			   int is_ip_pkt, int displ,
			   int channel_id,
			   u_int32_t num_rx_channels)
{
  int fwd_pkt = 0, rc = 0;
  u_int8_t hash_found = 0;
  u32 remainder;

  if(pfr && pfr->rehash_rss != NULL && skb->dev)
    channel_id = pfr->rehash_rss(skb, hdr) % get_num_rx_queues(skb->dev);

  /* This is a memory holder for storing parsed packet information
     that will then be freed when the packet has been handled
  */

  if((!pfring_enabled) || ((!pfr->ring_active) && (pfr->master_ring == NULL)))
    return(-1);

  if(pfr->num_rx_channels != num_rx_channels) /* Constantly updated */
    pfr->num_rx_channels = num_rx_channels;
  hdr->extended_hdr.parsed_pkt.last_matched_rule_id = (u_int16_t)-1;

  atomic_inc(&pfr->num_ring_users);

  /* [1] BPF Filtering */
  if(pfr->bpfFilter) {
    if(bpf_filter_skb(skb, pfr, displ) == 0) {
      atomic_dec(&pfr->num_ring_users);
      return(-1);
    }
  }

  /* Extensions */
  fwd_pkt = pfr->sw_filtering_rules_default_accept_policy;

  /* ************************** */

  /* [2] Filter packet according to rules */

  debug_printk(2, "ring_id=%d pfr->filtering_sample_rate=%u pfr->filtering_sampling_size=%u\n",
    pfr->ring_id, pfr->filtering_sample_rate, pfr->filtering_sampling_size);

  /* [2.1] Search the hash */
  if(pfr->sw_filtering_hash != NULL) {
    sw_filtering_hash_bucket *hash_bucket = NULL;

    read_lock_bh(&pfr->ring_rules_lock);

    hash_found = check_perfect_rules(skb, pfr, hdr, &fwd_pkt, displ, &hash_bucket);

    if(hash_found) {
      hash_bucket->rule.internals.jiffies_last_match = jiffies;
      hash_bucket->match++;
      pfr->sw_filtering_hash_match++;

      if(!fwd_pkt && pfr->filtering_sample_rate) {
        /* If there is a filter for the session, let 1 packet every first 'filtering_sample_rate' packets, to pass the filter.
         * Note that the above rate keeps the ratio defined by 'FILTERING_SAMPLING_RATIO' */
        div_u64_rem(hash_bucket->match, pfr->filtering_sampling_size, &remainder);
        if(remainder < FILTERING_SAMPLING_RATIO) {
          hash_bucket->match_forward++;
          fwd_pkt=1;
        }
      }

      if(fwd_pkt == 0) {
        hash_bucket->filtered++;
        pfr->sw_filtering_hash_filtered++;
      }
    } else {
      pfr->sw_filtering_hash_miss++;
    }

    read_unlock_bh(&pfr->ring_rules_lock);
  }

  /* [2.2] Search rules list */
  if((!hash_found) && (pfr->num_sw_filtering_rules > 0)) {
    if(check_wildcard_rules(skb, pfr, hdr, &fwd_pkt, displ) != 0)
      fwd_pkt = 0;
  }

  if(fwd_pkt) { /* We accept the packet: it needs to be queued */

    /* [3] Packet sampling */
    if(pfr->sample_rate > 1) {
      spin_lock_bh(&pfr->ring_index_lock);

      if(pfr->pktToSample <= 1) {
	pfr->pktToSample = pfr->sample_rate;
      } else {
        pfr->slots_info->tot_pkts++;
	pfr->pktToSample--;

	spin_unlock_bh(&pfr->ring_index_lock);
	atomic_dec(&pfr->num_ring_users);
	return(-1);
      }

      spin_unlock_bh(&pfr->ring_index_lock);
    }

    if(hdr->caplen > 0) {
      /* Copy the packet into the bucket */
      int offset;

      offset = 0;

      rc = add_pkt_to_ring(skb, real_skb, pfr, hdr, displ, channel_id, offset);
    }
  }

  atomic_dec(&pfr->num_ring_users);
  return(rc);
}

/* ********************************** */

static int hash_pkt_cluster(ring_cluster_element *cluster_ptr,
			    struct pfring_pkthdr *hdr)
{
  /* Predefined masks */
  static int mask_5_tuple = HASH_PKT_HDR_MASK_MAC,
             mask_4_tuple = HASH_PKT_HDR_MASK_MAC | HASH_PKT_HDR_MASK_PROTO,
             mask_2_tuple = HASH_PKT_HDR_MASK_MAC | HASH_PKT_HDR_MASK_PROTO | HASH_PKT_HDR_MASK_PORT;

  int flags = 0;
  cluster_type cluster_mode = cluster_ptr->cluster.hashing_mode;
  u_int8_t l3_proto = hdr->extended_hdr.parsed_pkt.l3_proto;

  if(cluster_mode == cluster_round_robin)
    return cluster_ptr->cluster.hashing_id++;

  if(cluster_mode < cluster_per_inner_flow || cluster_mode == cluster_per_flow_ip_5_tuple)
    flags |= HASH_PKT_HDR_MASK_TUNNEL;

  /* For the rest, set at least these 2 flags */
  flags |= HASH_PKT_HDR_RECOMPUTE | HASH_PKT_HDR_MASK_VLAN;

  if((cluster_mode == cluster_per_flow_ip_5_tuple)
     || (cluster_mode == cluster_per_inner_flow_ip_5_tuple)) {
    if(l3_proto == 0) {
      /* Non-IP packets: use only MAC addresses, mask all else */
      flags |= ~(HASH_PKT_HDR_MASK_TUNNEL | HASH_PKT_HDR_MASK_MAC);
      return hash_pkt_header(hdr, flags);
    }

    /* else, it's like 5-tuple for IP packets */
    cluster_mode = cluster_per_flow_5_tuple;
  }

  flags |= HASH_PKT_HDR_MASK_MAC;  /* Mask off the MAC addresses for IP packets */

  switch (cluster_mode)
  {
  case cluster_per_flow_5_tuple:
  case cluster_per_inner_flow_5_tuple:
    flags |= mask_5_tuple;
    break;

  case cluster_per_flow_tcp_5_tuple:
  case cluster_per_inner_flow_tcp_5_tuple:
    if(l3_proto == IPPROTO_TCP)
    {
      flags |= mask_5_tuple;
      break;
    }
    /* else, fall through, because it's like 2-tuple for non-TCP packets */

  case cluster_per_flow_2_tuple:
  case cluster_per_inner_flow_2_tuple:
    flags |= mask_2_tuple;
    break;

  case cluster_per_flow_4_tuple:
  case cluster_per_inner_flow_4_tuple:
    flags |= mask_4_tuple;
    break;

  case cluster_per_flow:
  case cluster_per_inner_flow:    /* No more flags for those 2 modes */
    break;

  default:  /* this ought to be an error */
    printk("[PF_RING] undefined clustering type.\n");
  }

  return hash_pkt_header(hdr, flags);
}

/* ********************************** */

static inline int is_valid_skb_direction(packet_direction direction, u_char recv_packet)
{
  switch(direction) {
  case rx_and_tx_direction:
    return(1);
  case rx_only_direction:
    if(recv_packet) return(1);
    break;
  case tx_only_direction:
    if(!recv_packet) return(1);
    break;
  }

  return(0);
}

/* ********************************** */

static inline int is_stack_injected_skb(struct sk_buff *skb)
{
  return skb->queue_mapping == 0xffff;
}

/* ********************************** */

static struct sk_buff* defrag_skb(struct sk_buff *skb,
				  u_int16_t displ,
				  struct pfring_pkthdr *hdr,
				  int *defragmented_skb)
{
  struct sk_buff *cloned = NULL;
  struct iphdr *iphdr = NULL;
  struct sk_buff *skk = NULL, *ret_skb = skb;
  u_int16_t bkp_transport_header = skb->transport_header;
  u_int16_t bkp_network_header = skb->network_header;

  skb_set_network_header(skb, hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ);
  skb_reset_transport_header(skb);

  iphdr = ip_hdr(skb);

  if(iphdr && (iphdr->version == 4)) {

    if(iphdr->frag_off & htons(IP_MF | IP_OFFSET)) {
      if((cloned = skb_clone(skb, GFP_ATOMIC)) != NULL) {
        int vlan_offset = 0;
        int tot_len, tot_frame_len;

        if(displ && (hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ) /*VLAN*/) {
	  vlan_offset = 4;
          skb_pull(cloned, vlan_offset);
          displ += vlan_offset;
	}

	skb_set_network_header(cloned, hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ);
	skb_reset_transport_header(cloned);
        iphdr = ip_hdr(cloned);

        tot_len = ntohs(iphdr->tot_len);
        tot_frame_len = hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ + tot_len;

        if (tot_frame_len < (cloned->len + displ)) {
          debug_printk(2, "[defrag] actual frame len (%d) < skb len (%d) Padding?\n",
                       tot_frame_len, cloned->len + displ);
          skb_trim(cloned, tot_frame_len); /* trim tail */
        }

	if (debug_on(2)) {
	  int ihl, end;
	  int offset = ntohs(iphdr->frag_off);

	  offset &= IP_OFFSET;
	  offset <<= 3;
	  ihl = iphdr->ihl * 4;
          end = offset + cloned->len - ihl;

	  debug_printk(2, 
                 "There is a fragment to handle [proto=%d][frag_off=%u]"
		 "[ip_id=%u][ip_hdr_len=%d][end=%d][network_header=%d][displ=%d]\n",
		 iphdr->protocol, offset,
		 ntohs(iphdr->id),
		 ihl, end,
		 hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ, displ);
	}

	skk = ring_gather_frags(cloned);

	if(skk != NULL) {
	  u_int16_t ip_id;

	  if(debug_on(2)) {
	    unsigned char *c;
	    debug_printk(2, "IP reasm on new skb [skb_len=%d]"
		   "[head_len=%d][nr_frags=%d][frag_list=%p]\n",
		   (int)skk->len,
		   skb_headlen(skk),
		   skb_shinfo(skk)->nr_frags,
		   skb_shinfo(skk)->frag_list);
	    c = skb_network_header(skk);
	    debug_printk(2, "IP header "
	           "%X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X\n",
		   c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9],
		   c[10], c[11], c[12], c[13], c[14], c[15], c[16], c[17], c[18], c[19]);
	    c -= displ;
	    debug_printk(2, "L2 header "
	           "%X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X\n",
		   c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9],
		   c[10], c[11], c[12], c[13], c[14], c[15], c[16], c[17]);
          }

	  if(vlan_offset > 0) {
	    skb_push(skk, vlan_offset);
	    displ -= vlan_offset;
	  }

	  hdr->len = hdr->caplen = skk->len + displ;
	  parse_pkt(skk, 1, displ, hdr, &ip_id);

	  *defragmented_skb = 1;
	  ret_skb = skk;
	} else {
          ret_skb = NULL; /* mask rcvd fragments */
	}
      }
    }
  }

  /* Restore skb */
  skb->transport_header = bkp_transport_header;
  skb->network_header   = bkp_network_header;

  return(ret_skb);
}

/* ********************************** */

/*
  PF_RING main entry point

  Return code
  0 - Packet not handled
  1 - Packet handled successfully
  2 - Packet handled successfully but unable to copy it into
      the ring due to lack of available space
*/

int pf_ring_skb_ring_handler(struct sk_buff *skb,
			    u_int8_t recv_packet,
			    u_int8_t real_skb /* 1=real skb, 0=faked skb */,
			    /*
			      This return value is set to 1 in case
			      the input skb is in use by PF_RING and thus
			      the caller should NOT free it
			    */
			    int32_t channel_id,
			    u_int32_t num_rx_channels)
{
  struct sock *skElement;
  int rc = 0, is_ip_pkt = 0, room_available = 0;
  struct pfring_pkthdr hdr;
  int displ = 0;
  int defragmented_skb = 0;
  struct sk_buff *skk = NULL;
  u_int32_t last_list_idx;
  struct sock *sk;
  struct pf_ring_socket *pfr;
  ring_cluster_element *cluster_ptr;
  u_int16_t ip_id = 0;
  u_int32_t skb_hash = 0;
  u_int8_t skb_hash_set = 0;
  int dev_index;
  pf_ring_net *netns;
  
  /* Check if there's at least one PF_RING ring defined that
     could receive the packet: if none just stop here */

  if(atomic_read(&ring_table_size) == 0)
    return(0);

  /* this should not happen, if this is not the case we should create a dummy
   * interface with ifindex = UNKNOWN_INTERFACE to be assigned to skb->dev */
  if(skb->dev == NULL) {
    printk("[PF_RING] skb->dev is not set\n");
    return 0;
  }

  if(recv_packet && real_skb) {
    displ = skb->dev->hard_header_len;
#ifdef CONFIG_RASPBERRYPI_FIRMWARE
    if(displ > 14) /* on RaspberryPi RX skbs have wrong hard_header_len value (26) */
      displ = 14;
#endif
  }
  
  netns = netns_lookup(dev_net(skb->dev));
  dev_index = ifindex_to_pf_index(netns, skb->dev->ifindex);

  if(dev_index < 0)
    return 0;

  if(netns->num_any_rings == 0 && netns->num_rings_per_device[dev_index] == 0)
    return 0;

#ifdef PROFILING
  uint64_t rdt = _rdtsc(), rdt1, rdt2;
#endif

  if(channel_id == -1 /* unknown: any channel */) {
    channel_id = skb_get_rx_queue(skb);
    if (channel_id >= 0xff /* unknown */)
      channel_id = 0;
  }

  if(channel_id > MAX_NUM_RX_CHANNELS) {
    channel_id = channel_id % MAX_NUM_RX_CHANNELS;
  }

  if((!skb) /* Invalid skb */ ||((!enable_tx_capture) && (!recv_packet))) {
    /* An outgoing packet is about to be sent out but we decided not to handle transmitted packets. */
    return(0);
  }

#ifdef PROFILING
  rdt1 = _rdtsc();
#endif

  memset(&hdr, 0, sizeof(hdr));

  hdr.ts.tv_sec = 0;
  hdr.len = hdr.caplen = skb->len + displ;
  hdr.extended_hdr.flags = 0;

  if(quick_mode) {
    pfr = netns->quick_mode_rings[dev_index][channel_id];

    if (pfr != NULL /* socket present */
        && !(pfr->zc_device_entry /* ZC socket (1-copy mode) */
             && !recv_packet /* sent by the stack */)
        && !(pfr->discard_injected_pkts 
             && is_stack_injected_skb(skb))){

      if(pfr->rehash_rss != NULL) {
        is_ip_pkt = parse_pkt(skb, real_skb, displ, &hdr, &ip_id);
        channel_id = pfr->rehash_rss(skb, &hdr) % get_num_rx_queues(skb->dev);
        pfr = netns->quick_mode_rings[dev_index][channel_id];
      }

      if(is_valid_skb_direction(pfr->direction, recv_packet)) {
        rc = 1;

        if(pfr->sample_rate > 1) {
          spin_lock_bh(&pfr->ring_index_lock);
          if(pfr->pktToSample <= 1) {
            pfr->pktToSample = pfr->sample_rate;
          } else {
            pfr->slots_info->tot_pkts++;
            pfr->pktToSample--;
            rc = 0;
          }
          spin_unlock_bh(&pfr->ring_index_lock);
        }

        if(rc == 1)
          room_available |= copy_data_to_ring(real_skb ? skb : NULL, pfr, &hdr,
					      displ, 0, NULL, 0);
      }
    }
  } else {
    is_ip_pkt = parse_pkt(skb, real_skb, displ, &hdr, &ip_id);

    if(enable_ip_defrag) {
      if(real_skb
	 && is_ip_pkt
	 && recv_packet) {

        skb = skk = defrag_skb(skb, displ, &hdr, &defragmented_skb);

        if(skb == NULL)
          return(0);
      }
    }

    hdr.extended_hdr.if_index = skb->dev->ifindex;
    hdr.extended_hdr.tx.bounce_interface = UNKNOWN_INTERFACE;
    hdr.extended_hdr.tx.reserved = NULL;
    hdr.extended_hdr.rx_direction = recv_packet;

    /* [1] Check unclustered sockets */
    sk = (struct sock*)lockless_list_get_first(&ring_table, &last_list_idx);

    while(sk != NULL) {
      pfr = ring_sk(sk);

      if(pfr != NULL
         && (net_eq(dev_net(skb->dev), sock_net(sk))) /* same namespace */
	 && (pfr->ring_slots != NULL)
	 && (
	     test_bit(dev_index, pfr->pf_dev_mask)
	     || (pfr->ring_dev == &any_device_element /* any */)
#if(LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
	     || ((skb->dev->flags & IFF_SLAVE) && (pfr->ring_dev->dev == skb->dev->master))
#endif
	    )
	 && (pfr->ring_dev != &none_device_element) /* Not a dummy socket bound to "none" */
	 && (pfr->cluster_id == 0 /* No cluster */ )
	 && is_valid_skb_direction(pfr->direction, recv_packet)
	 && ((pfr->vlan_id == RING_ANY_VLAN) /* Accept all VLANs... */
	     /* Accept untagged packets only... */
	     || ((pfr->vlan_id == RING_NO_VLAN) && (hdr.extended_hdr.parsed_pkt.vlan_id == 0))
	     /* ...or just the specified VLAN */
	     || (pfr->vlan_id == hdr.extended_hdr.parsed_pkt.vlan_id)
	     || (pfr->vlan_id == hdr.extended_hdr.parsed_pkt.qinq_vlan_id)
            )
        && !(pfr->zc_device_entry /* ZC socket (1-copy mode) */
             && !recv_packet /* sent by the stack */)
        && !(pfr->discard_injected_pkts 
             && is_stack_injected_skb(skb))){
	/* We've found the ring where the packet can be stored */
	int old_len = hdr.len, old_caplen = hdr.caplen;  /* Keep old lenght */

	room_available |= add_skb_to_ring(skb, real_skb, pfr, &hdr, is_ip_pkt,
					  displ, channel_id, num_rx_channels);

	hdr.len = old_len, hdr.caplen = old_caplen;
	rc = 1;	/* Ring found: we've done our job */
      }

      sk = (struct sock*)lockless_list_get_next(&ring_table, &last_list_idx);
    }

    cluster_ptr = (ring_cluster_element*)lockless_list_get_first(&ring_cluster_list, &last_list_idx);

    if (cluster_ptr != NULL) {

      read_lock_bh(&ring_cluster_lock);

      /* [2] Check socket clusters */
      cluster_ptr = (ring_cluster_element*)lockless_list_get_first(&ring_cluster_list, &last_list_idx);
      while(cluster_ptr != NULL) {
        struct pf_ring_socket *pfr;
        u_short num_cluster_elements =
  #if(LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
          ACCESS_ONCE(cluster_ptr->cluster.num_cluster_elements);
  #else
          READ_ONCE(cluster_ptr->cluster.num_cluster_elements);
  #endif
        
        if(num_cluster_elements > 0) {
	  u_short num_iterations;
	  u_int32_t cluster_element_idx;
	  u_int8_t num_ip_flow_iterations = 0;
  
	  if(cluster_ptr->cluster.hashing_mode == cluster_per_flow_ip_with_dup_tuple) {
	    /*
	      This is a special mode that might lead to packet duplication and it is
	      handled on a custom way
	    */
	    skb_hash = hash_pkt_header(&hdr, HASH_PKT_HDR_MASK_DST | HASH_PKT_HDR_MASK_MAC
				       | HASH_PKT_HDR_MASK_PROTO | HASH_PKT_HDR_MASK_PORT
				       | HASH_PKT_HDR_RECOMPUTE | HASH_PKT_HDR_MASK_VLAN),
	      skb_hash_set = 1;
	  } else {
	    if(enable_frag_coherence
	       && is_ip_pkt
	       && (hdr.extended_hdr.parsed_pkt.ip_version == 4)
	       && (!skb_hash_set /* read hash once */)) {
	      int fragment_not_first = hdr.extended_hdr.flags & PKT_FLAGS_IP_FRAG_OFFSET;
	      int more_fragments     = hdr.extended_hdr.flags & PKT_FLAGS_IP_MORE_FRAG;
	      int first_fragment     = more_fragments && !fragment_not_first;
  
	      if(first_fragment) {
	        /* first fragment: compute hash (once for all clusters) */
	        skb_hash = hash_pkt_cluster(cluster_ptr, &hdr), skb_hash_set = 1;
  
	        /* add hash to cache */
	        add_fragment_app_id(hdr.extended_hdr.parsed_pkt.ipv4_src,
				    hdr.extended_hdr.parsed_pkt.ipv4_dst,
				    ip_id, skb_hash % num_cluster_elements);
	      } else if(fragment_not_first) {
	        /* fragment, but not the first: read hash from cache */
	        skb_hash = get_fragment_app_id(hdr.extended_hdr.parsed_pkt.ipv4_src,
					       hdr.extended_hdr.parsed_pkt.ipv4_dst,
					       ip_id, more_fragments), skb_hash_set = 1;
	      }
	    }
  
	    if(!skb_hash_set) {
	      /* compute hash (once for all clusters) */
	      skb_hash = hash_pkt_cluster(cluster_ptr, &hdr), skb_hash_set = 1;
	    }
	  }
  
          cluster_element_idx = skb_hash % num_cluster_elements;
  
        iterate_cluster_elements:
	  /*
	    We try to add the packet to the right cluster
	    element, but if we're working in round-robin and this
	    element is full, we try to add this to the next available
	    element. If none with at least a free slot can be found
	    then we give up :-(
	  */
	  for(num_iterations = 0;
	      num_iterations < num_cluster_elements;
	      num_iterations++) {
	      skElement = cluster_ptr->cluster.sk[cluster_element_idx];
  
	      if(skElement != NULL) {
		  pfr = ring_sk(skElement);
  
		  if(pfr != NULL
		     && net_eq(dev_net(skb->dev), sock_net(skElement)) /* same namespace */
		     && pfr->ring_slots != NULL
		     && (test_bit(dev_index, pfr->pf_dev_mask)
  #if(LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
		         || ((skb->dev->flags & IFF_SLAVE) && (pfr->ring_dev->dev == skb->dev->master))
  #endif
		        )
		     && is_valid_skb_direction(pfr->direction, recv_packet)
		     && ((pfr->vlan_id == RING_ANY_VLAN) /* Accept all VLANs... */
		         /* Accept untagged packets only... */
		         || ((pfr->vlan_id == RING_NO_VLAN) && (hdr.extended_hdr.parsed_pkt.vlan_id == 0))
		         /* ...or just the specified VLAN */
		         || (pfr->vlan_id == hdr.extended_hdr.parsed_pkt.vlan_id)
		         || (pfr->vlan_id == hdr.extended_hdr.parsed_pkt.qinq_vlan_id)
		        )
		   ) {
		    if(check_free_ring_slot(pfr) /* Not full */) {
		      /* We've found the ring where the packet can be stored */
		      int old_len = hdr.len, old_caplen = hdr.caplen;  /* Keep old lenght */
  
		      room_available |= add_skb_to_ring(skb, real_skb, pfr, &hdr, is_ip_pkt,
		                                        displ, channel_id, num_rx_channels);
  
		      hdr.len = old_len, hdr.caplen = old_caplen;
		      rc = 1; /* Ring found: we've done our job */
		      break;
  
		    } else if((cluster_ptr->cluster.hashing_mode != cluster_round_robin)
		              /* We're the last element of the cluster so no further cluster element to check */
		              || ((num_iterations + 1) >= num_cluster_elements)) {
		      pfr->slots_info->tot_pkts++, pfr->slots_info->tot_lost++;
		    }
		  }
	      }
  
	      if(cluster_ptr->cluster.hashing_mode != cluster_round_robin)
	        break;
	      else
	        cluster_element_idx = (cluster_element_idx + 1) % num_cluster_elements;
	  } /* for */
  
	  if((cluster_ptr->cluster.hashing_mode == cluster_per_flow_ip_with_dup_tuple)
	     && (num_ip_flow_iterations == 0)) {
	    u_int32_t new_cluster_element_idx = hash_pkt_header(&hdr, HASH_PKT_HDR_MASK_SRC | HASH_PKT_HDR_MASK_MAC
							        | HASH_PKT_HDR_MASK_PROTO | HASH_PKT_HDR_MASK_PORT
							        | HASH_PKT_HDR_RECOMPUTE | HASH_PKT_HDR_MASK_VLAN);
	    
	    new_cluster_element_idx %= num_cluster_elements;
	    
	    if(new_cluster_element_idx != cluster_element_idx) {
	      cluster_element_idx = new_cluster_element_idx, num_ip_flow_iterations = 1;
	      goto iterate_cluster_elements;
	    }
	  }
        }
  
        cluster_ptr = (ring_cluster_element*)lockless_list_get_next(&ring_cluster_list, &last_list_idx);

      } /* while*/

      read_unlock_bh(&ring_cluster_lock);

    } /* Clustering */
 
#ifdef PROFILING
    rdt1 = _rdtsc() - rdt1;
    rdt2 = _rdtsc();
#endif

    /* Fragment handling */
    if(skk != NULL && defragmented_skb)
      kfree_skb(skk);
  }

#ifdef PROFILING
  rdt2 = _rdtsc() - rdt2;
  rdt = _rdtsc() - rdt;

  debug_printk(2, "# cycles: %d [lock costed %d %d%%][free costed %d %d%%]\n",
	   (int)rdt, rdt - rdt1,
	   (int)((float)((rdt - rdt1) * 100) / (float)rdt), rdt2,
	   (int)((float)(rdt2 * 100) / (float)rdt));
#endif

  if((rc == 1) && (room_available == 0))
    rc = 2;

  return(rc); /*  0 = packet not handled */
}
EXPORT_SYMBOL(pf_ring_skb_ring_handler);

/* ********************************** */

static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev)
{
  int rc = 0;

  if(skb->pkt_type != PACKET_LOOPBACK) 
    rc = pf_ring_skb_ring_handler(skb,
			          skb->pkt_type != PACKET_OUTGOING,
			          1 /* real_skb */,
			          -1 /* unknown: any channel */,
                	          UNKNOWN_NUM_RX_CHANNELS);

  kfree_skb(skb);

  return rc;
}

/* ********************************** */

void register_device_handler(void)
{
  prot_hook.func = packet_rcv;
  prot_hook.type = htons(ETH_P_ALL);
  dev_add_pack(&prot_hook);
}

/* ********************************** */

void unregister_device_handler(void)
{
  dev_remove_pack(&prot_hook); /* Remove protocol hook */
}

/* ********************************** */

static int ring_create(struct net *net, struct socket *sock, int protocol
#if((LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)) || ((LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)) && defined(REDHAT_PATCHED_KERNEL)))
		       , int kern
#endif
		       )
{
  struct sock *sk;
  struct pf_ring_socket *pfr;
  int err = -ENOMEM;
  int pid = current->tgid;

  debug_printk(2, "[pid=%d]\n", pid);

  /* Are you root or with capabilities? */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
  if(!capable(CAP_NET_ADMIN)) {
    printk("[PF_RING] User is not capable, please run as root or setcap cap_net_admin\n");
#else
  if(!ns_capable(net->user_ns, CAP_NET_RAW)) {
    printk("[PF_RING] User is not capable, please run as root or setcap cap_net_raw\n");
#endif
    return -EPERM;
  }

  if(sock->type != SOCK_RAW)
    return -ESOCKTNOSUPPORT;

  if(protocol != htons(ETH_P_ALL))
    return -EPROTONOSUPPORT;

#if(LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0))
  sk = sk_alloc(net, PF_INET, GFP_KERNEL, &ring_proto);
#else
  sk = sk_alloc(net, PF_INET, GFP_KERNEL, &ring_proto, 1 /* FIXX kernel socket? */);
#endif

  if(sk == NULL)
    goto out;

  sock->ops = &ring_ops;
  sock_init_data(sock, sk);

  ring_sk(sk) = (struct pf_ring_socket *) kmalloc(sizeof(*pfr), GFP_KERNEL);

  if(!(pfr = ring_sk(sk)))
    goto free_sk;

  memset(pfr, 0, sizeof(*pfr));
  mutex_init(&pfr->ring_config_lock);
  pfr->sk = sk;
  pfr->ring_shutdown = 0;
  pfr->ring_active = 0;	/* We activate as soon as somebody waits for packets */
  pfr->num_rx_channels = UNKNOWN_NUM_RX_CHANNELS;
  pfr->channel_id_mask = RING_ANY_CHANNEL;
  pfr->bucket_len = DEFAULT_BUCKET_LEN;
  pfr->poll_num_pkts_watermark = DEFAULT_MIN_PKT_QUEUED;
  pfr->poll_watermark_timeout = DEFAULT_POLL_WATERMARK_TIMEOUT;
  pfr->queue_nonempty_timestamp = 0;
  pfr->header_len = quick_mode ? short_pkt_header : long_pkt_header;
  init_waitqueue_head(&pfr->ring_slots_waitqueue);
  spin_lock_init(&pfr->ring_index_lock);
  rwlock_init(&pfr->ring_rules_lock);
  atomic_set(&pfr->num_ring_users, 0);
  INIT_LIST_HEAD(&pfr->sw_filtering_rules);
  INIT_LIST_HEAD(&pfr->hw_filtering_rules);
  pfr->master_ring = NULL;
  pfr->ring_dev = &none_device_element; /* Unbound socket */
  pfr->sample_rate = 1;	/* No sampling */
  pfr->filtering_sample_rate = 0; /* No filtering sampling */
  pfr->filtering_sampling_size = 0;
  sk->sk_family = PF_RING;
  sk->sk_destruct = ring_sock_destruct;
  pfr->ring_id = atomic_inc_return(&ring_id_serial);
  pfr->vlan_id = RING_ANY_VLAN;
  spin_lock_init(&pfr->tx.consume_tx_packets_lock);
  pfr->tx.enable_tx_with_bounce = 0;
  pfr->tx.last_tx_dev_idx = UNKNOWN_INTERFACE, pfr->tx.last_tx_dev = NULL;

  pfr->ring_pid = pid;

  if(ring_insert(sk) == -1)
    goto free_pfr;

  ring_proc_add(pfr);

  debug_printk(2, "created\n");

  return(0);

free_pfr:
  kfree(ring_sk(sk));
free_sk:
  sk_free(sk);
out:
  return err;
}

/* ************************************* */

static int ring_proc_virtual_filtering_dev_get_info(struct seq_file *m, void *data_not_used)
{
  if(m->private != NULL) {
    virtual_filtering_device_info *info = (virtual_filtering_device_info*)m->private;
    char *dev_family = "???";

    switch(info->device_type) {
    case standard_nic_family:    dev_family = "Standard NIC"; break;
    case intel_82599_family:     dev_family = "Intel 82599"; break;
    }

    seq_printf(m, "Name:              %s\n", info->device_name);
    seq_printf(m, "Family:            %s\n", dev_family);
  }

  return (0);
}

/* ********************************** */

static int ring_proc_virtual_filtering_open(struct inode *inode, struct file *file)
{
  return single_open(file, ring_proc_virtual_filtering_dev_get_info, PDE_DATA(inode));
}

#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
static const struct file_operations ring_proc_virtual_filtering_fops = {
  .owner = THIS_MODULE,
  .open = ring_proc_virtual_filtering_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};
#else
static const struct proc_ops ring_proc_virtual_filtering_fops = {
  .proc_open = ring_proc_virtual_filtering_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};
#endif

/* ************************************* */

static virtual_filtering_device_element*
add_virtual_filtering_device(struct pf_ring_socket *pfr, virtual_filtering_device_info *info)
{
  virtual_filtering_device_element *elem;
  struct list_head *ptr, *tmp_ptr;
  pf_ring_net *netns;

  debug_printk(2, "add_virtual_filtering_device(%s)\n", info->device_name);

  if(info == NULL)
    return(NULL);

  /* Check if the same entry is already present */
  mutex_lock(&virtual_filtering_lock);
  list_for_each_safe(ptr, tmp_ptr, &virtual_filtering_devices_list) {
    virtual_filtering_device_element *filtering_ptr = list_entry(ptr,
								 virtual_filtering_device_element,
								 list);

    if(strcmp(filtering_ptr->info.device_name, info->device_name) == 0) {
      mutex_unlock(&virtual_filtering_lock);
      return(NULL); /* Entry alredy present */
    }
  }

  elem = kmalloc(sizeof(virtual_filtering_device_element), GFP_KERNEL);

  if(elem == NULL) {
    mutex_unlock(&virtual_filtering_lock);
    return(NULL);
  } else {
    memcpy(&elem->info, info, sizeof(virtual_filtering_device_info));
    INIT_LIST_HEAD(&elem->list);
  }

  list_add(&elem->list, &virtual_filtering_devices_list);  /* Add as first entry */
  mutex_unlock(&virtual_filtering_lock);

  /* Add /proc entry */
  netns = netns_lookup(sock_net(pfr->sk));
  if(netns != NULL) {
    elem->info.proc_entry = proc_mkdir(elem->info.device_name, netns->proc_dev_dir);
    proc_create_data(PROC_INFO, 0 /* read-only */,
		     elem->info.proc_entry,
		     &ring_proc_virtual_filtering_fops /* read */,
		     (void *) &elem->info);
  }

  return(elem);
}

/* ************************************* */

static int remove_virtual_filtering_device(struct pf_ring_socket *pfr, char *device_name)
{
  struct list_head *ptr, *tmp_ptr;
  pf_ring_net *netns;

  debug_printk(2, "remove_virtual_filtering_device(%s)\n", device_name);

  mutex_lock(&virtual_filtering_lock);
  list_for_each_safe(ptr, tmp_ptr, &virtual_filtering_devices_list) {
    virtual_filtering_device_element *filtering_ptr;

    filtering_ptr = list_entry(ptr, virtual_filtering_device_element, list);

    if(strcmp(filtering_ptr->info.device_name, device_name) == 0) {
      /* Remove /proc entry */
      netns = netns_lookup(sock_net(pfr->sk));
      if(netns != NULL) {
        remove_proc_entry(PROC_INFO, filtering_ptr->info.proc_entry);
        remove_proc_entry(filtering_ptr->info.device_name, netns->proc_dev_dir);
      }

      list_del(ptr);
      mutex_unlock(&virtual_filtering_lock);
      kfree(filtering_ptr);
      return(0);
    }
  }

  mutex_unlock(&virtual_filtering_lock);

  return(-EINVAL);	/* Not found */
}

/* ************************************* */

void reserve_memory(unsigned long base, unsigned long mem_len)
{
  struct page *page, *page_end;

  page_end = virt_to_page(base + mem_len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    SetPageReserved(page);
}

void unreserve_memory(unsigned long base, unsigned long mem_len)
{
  struct page *page, *page_end;

  page_end = virt_to_page(base + mem_len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    ClearPageReserved(page);
}

static void free_contiguous_memory(unsigned long mem, u_int mem_len)
{
  if(mem != 0) {
    unreserve_memory(mem, mem_len);
    free_pages(mem, get_order(mem_len));
  }
}

static unsigned long __get_free_pages_node(int nid, gfp_t gfp_mask, unsigned int order) {
  struct page *page;

  /* Just remember to do not use highmem flag:
   * VM_BUG_ON((gfp_mask & __GFP_HIGHMEM) != 0); */

  page = alloc_pages_node(nid, gfp_mask, order);

  if(!page)
    return 0;

  return (unsigned long) page_address(page);
}

static unsigned long alloc_contiguous_memory(u_int mem_len, int node)
{
  unsigned long mem = 0;

  /* trying to allocate memory on the selected numa node */
  mem = __get_free_pages_node(node, GFP_KERNEL, get_order(mem_len));

  if(!mem)
    __get_free_pages(GFP_KERNEL, get_order(mem_len));

  if(mem)
    reserve_memory(mem, mem_len);
  else
    debug_printk(2, "Failure (len=%d, order=%d)\n", mem_len, get_order(mem_len));

  return(mem);
}

/* ************************************* */

static struct dma_memory_info *allocate_extra_dma_memory(struct device *hwdev,
                                                         u_int32_t num_slots, u_int32_t slot_len, u_int32_t chunk_len)
{
  u_int i, num_slots_per_chunk, num_chunks;
  struct dma_memory_info *dma_memory;
  int numa_node =
#ifdef CONFIG_NUMA
    dev_to_node(hwdev)
#else
    -1
#endif
  ;

  /* Note: this function allocates up to num_slots slots. You can check the exact number by ... */

  num_slots_per_chunk = chunk_len / slot_len;
  num_chunks = (num_slots + num_slots_per_chunk-1) / num_slots_per_chunk;

  if(num_chunks == 0)
    return NULL;

  if((dma_memory = kcalloc(1, sizeof(struct dma_memory_info), GFP_KERNEL)) == NULL)
    return NULL;

  dma_memory->chunk_len = chunk_len;
  dma_memory->num_slots = num_slots;
  dma_memory->slot_len = slot_len;
  dma_memory->hwdev = hwdev;
  dma_memory->num_chunks = num_chunks;

  if((dma_memory->virtual_addr = kcalloc(1, sizeof(unsigned long) * dma_memory->num_chunks, GFP_KERNEL)) == NULL) {
    kfree(dma_memory);
    return NULL;
  }

  if((dma_memory->dma_addr = kcalloc(1, sizeof(u_int64_t) * dma_memory->num_slots, GFP_KERNEL)) == NULL) {
    kfree(dma_memory->virtual_addr);
    kfree(dma_memory);
    return NULL;
  }

  if(numa_node == -1) {
    debug_printk(2, "device node not set, selecting current node\n");
    numa_node = numa_node_id(); /* using current node if not set */
  }

  debug_printk(2, "Allocating %d DMA chunks of %d bytes on node %d [slots per chunk=%d]\n",
           dma_memory->num_chunks, dma_memory->chunk_len, numa_node, num_slots_per_chunk);

  /* Allocating memory chunks */
  for(i=0; i < dma_memory->num_chunks; i++) {
    dma_memory->virtual_addr[i] = alloc_contiguous_memory(dma_memory->chunk_len, numa_node);

    if(!dma_memory->virtual_addr[i]) {
      printk("[PF_RING] %s: Warning: no more free memory available! Allocated %d of %d chunks.\n",
	     __FUNCTION__, i + 1, dma_memory->num_chunks);

      dma_memory->num_chunks = i;
      dma_memory->num_slots = dma_memory->num_chunks * num_slots_per_chunk;
      break;
    }
  }

  /* Mapping DMA slots */
  for(i=0; i < dma_memory->num_slots; i++) {
    u_int chunk_id = i / num_slots_per_chunk;
    u_int offset = (i % num_slots_per_chunk) * dma_memory->slot_len;
    char *slot;

    if(!dma_memory->virtual_addr[chunk_id])
      break;

    slot = (char *) (dma_memory->virtual_addr[chunk_id] + offset);

    debug_printk(2, "Mapping DMA slot %d of %d [slot addr=%p][offset=%u]\n",
      i + 1, dma_memory->num_slots, slot, offset);

    dma_memory->dma_addr[i] = cpu_to_le64(
      pci_map_single(to_pci_dev(dma_memory->hwdev), slot,
                     dma_memory->slot_len,
                     PCI_DMA_BIDIRECTIONAL));

    if(dma_mapping_error(dma_memory->hwdev, dma_memory->dma_addr[i])) {
      printk("[PF_RING] %s: Error mapping DMA slot %d of %d \n", __FUNCTION__, i + 1, dma_memory->num_slots);
      dma_memory->dma_addr[i] = 0;
      dma_memory->num_slots = i;
      break;
    }
  }

  return dma_memory;
}

static void free_extra_dma_memory(struct dma_memory_info *dma_memory)
{
  u_int i;

  /* Unmapping DMA addresses */
  if(dma_memory->dma_addr) {
    for(i=0; i < dma_memory->num_slots; i++) {
      if(dma_memory->dma_addr[i]) {
        dma_unmap_single(dma_memory->hwdev, dma_memory->dma_addr[i],
	                 dma_memory->slot_len,
	                 PCI_DMA_BIDIRECTIONAL);
      }
    }
    kfree(dma_memory->dma_addr);
  }

  /* Freeing memory */
  if(dma_memory->virtual_addr) {
    for(i=0; i < dma_memory->num_chunks; i++) {
      if(dma_memory->virtual_addr[i]) {
        debug_printk(2, "Freeing chunk %d of %d\n", i, dma_memory->num_chunks);

        free_contiguous_memory(dma_memory->virtual_addr[i], dma_memory->chunk_len);
      }
    }
    kfree(dma_memory->virtual_addr);
  }

  kfree(dma_memory);
}

/* ********************************** */

static int create_cluster_referee(struct pf_ring_socket *pfr, u_int32_t cluster_id, u_int32_t *recovered)
{
  struct list_head *ptr, *tmp_ptr;
  struct cluster_referee *entry;
  struct cluster_referee *cr = NULL;

  if(pfr->cluster_referee) /* already called */
    return -1;

  mutex_lock(&cluster_referee_lock);

  /* checking if the cluster already exists */
  list_for_each_safe(ptr, tmp_ptr, &cluster_referee_list) {
    entry = list_entry(ptr, struct cluster_referee, list);

    if(entry->id == cluster_id) {

      debug_printk(2, "cluster %u already exists [users: %u]\n",
        cluster_id, entry->users);

      if(entry->master_running) /* multiple masters not allowed */
        goto unlock;

      cr = entry;
      break;
    }
  }

  /* Creating a new cluster */
  if(cr == NULL) {
    debug_printk(2, "attempting to create a referee for cluster %u\n", cluster_id);

    cr = kcalloc(1, sizeof(struct cluster_referee), GFP_KERNEL);

    if(cr == NULL) {
      debug_printk(2, "failure [cluster: %u]\n", cluster_id);
      goto unlock;
    }

    cr->id = cluster_id;
    INIT_LIST_HEAD(&cr->objects_list);

    list_add(&cr->list, &cluster_referee_list);

    debug_printk(2, "new cluster referee created for cluster %u\n",  cluster_id);

    *recovered = 0;
  } else {
    *recovered = 1;
  }

  pfr->cluster_role = cluster_master;
  pfr->cluster_referee = cr;
  cr->users++;
  cr->master_running = 1;

unlock:
  mutex_unlock(&cluster_referee_lock);

  if(cr == NULL) {
    debug_printk(2, "error\n");
    return -1;
  } else {
    debug_printk(2, "cluster %u found or created\n", cluster_id);
  }

  return 0;
}

static void remove_cluster_referee(struct pf_ring_socket *pfr)
{
  struct list_head *ptr, *tmp_ptr;
  struct cluster_referee *entry;
  struct list_head *c_obj_ptr, *c_obj_tmp_ptr;
  cluster_object *c_obj_entry = NULL;

  mutex_lock(&cluster_referee_lock);

  /* looking for the cluster */
  list_for_each_safe(ptr, tmp_ptr, &cluster_referee_list) {
    entry = list_entry(ptr, struct cluster_referee, list);

    if(entry == pfr->cluster_referee) {

      if(pfr->cluster_role == cluster_master)
        entry->master_running = 0;

      entry->users--;

      /* Note: we are not unlocking all objects locked by the actual socket
       * that have not been explicitly unlocked, this to recognize a crash */

      if(entry->users == 0) {

	/* removing all objects from cluster */
        list_for_each_safe(c_obj_ptr, c_obj_tmp_ptr, &entry->objects_list) {
          c_obj_entry = list_entry(c_obj_ptr, cluster_object, list);
	  list_del(c_obj_ptr);
	  kfree(c_obj_entry);
	}

        list_del(ptr);
        kfree(entry);
      }

      break;
    }
  }

  mutex_unlock(&cluster_referee_lock);

  pfr->cluster_referee = NULL;
}

static int publish_cluster_object(struct pf_ring_socket *pfr, u_int32_t cluster_id,
                                 u_int32_t object_type, u_int32_t object_id)
{
  struct list_head *ptr, *tmp_ptr;
  struct cluster_referee *entry, *cr = NULL;
  struct list_head *obj_ptr, *obj_tmp_ptr;
  cluster_object *obj_entry, *c_obj = NULL;
  int rc = -1;

  mutex_lock(&cluster_referee_lock);

  list_for_each_safe(ptr, tmp_ptr, &cluster_referee_list) {
    entry = list_entry(ptr, struct cluster_referee, list);
    if(entry->id == cluster_id) {
      cr = entry;
      break;
    }
  }

  if(cr == NULL) {
    debug_printk(2, "cluster %u not found\n", cluster_id);
    goto unlock;
  }

  list_for_each_safe(obj_ptr, obj_tmp_ptr, &cr->objects_list) {
    obj_entry = list_entry(obj_ptr, cluster_object, list);
    if(obj_entry->object_type == object_type && obj_entry->object_id == object_id) {
      /* already published (recovery?) */
      c_obj = obj_entry;
      break;
    }
  }

  if(c_obj == NULL) {
    c_obj = kcalloc(1, sizeof(cluster_object), GFP_KERNEL);
    if(c_obj == NULL) {
      debug_printk(2, "memory allocation failure\n");
      goto unlock;
    }

    c_obj->object_type = object_type;
    c_obj->object_id = object_id;

    list_add(&c_obj->list, &cr->objects_list);
  }

  debug_printk(2, "object %u.%u published in cluster %u\n", object_type, object_id, cluster_id);

  rc = 0;

unlock:
  mutex_unlock(&cluster_referee_lock);

  return rc;
}

static int lock_cluster_object(struct pf_ring_socket *pfr, u_int32_t cluster_id,
                               u_int32_t object_type, u_int32_t object_id, u_int32_t lock_mask)
{
  struct list_head *ptr, *tmp_ptr;
  struct cluster_referee *entry, *cr = NULL;
  struct list_head *obj_ptr, *obj_tmp_ptr;
  cluster_object *obj_entry, *c_obj = NULL;
  int rc = -1;

  mutex_lock(&cluster_referee_lock);

  list_for_each_safe(ptr, tmp_ptr, &cluster_referee_list) {
    entry = list_entry(ptr, struct cluster_referee, list);
    if(entry->id == cluster_id) {
      cr = entry;
      break;
    }
  }

  if(cr == NULL) {
    debug_printk(2, "cluster %u not found\n", cluster_id);
    goto unlock;
  }

  if(!cr->master_running) {
    debug_printk(2, "cluster %u not running, new locks are not allowed\n", cluster_id);
    goto unlock;
  }

  /* adding locked objects to the cluster */
  list_for_each_safe(obj_ptr, obj_tmp_ptr, &cr->objects_list) {
    obj_entry = list_entry(obj_ptr, cluster_object, list);

    debug_printk(2, "obj %u.%u\n", obj_entry->object_type, obj_entry->object_id);

    if(obj_entry->object_type == object_type && obj_entry->object_id == object_id) {
      c_obj = obj_entry;
      if(c_obj->lock_bitmap & lock_mask) {
        debug_printk(2, "trying to lock already-locked features on cluster %u\n", cluster_id);
        goto unlock;
      }
      break;
    }
  }

  if(c_obj == NULL) {
    debug_printk(2, "object %u.%u not in the public list of cluster %u\n", object_type, object_id, cluster_id);
    goto unlock;
  }

  c_obj->lock_bitmap |= lock_mask;

  debug_printk(2, "new object lock on cluster %u\n", cluster_id);

  if(pfr->cluster_referee == NULL) {
    pfr->cluster_referee = cr;
    cr->users++;
  }

  rc = 0;

unlock:
  mutex_unlock(&cluster_referee_lock);

  return rc;
}

/* *********************************************** */

static int unlock_cluster_object(struct pf_ring_socket *pfr, u_int32_t cluster_id,
                                 u_int32_t object_type, u_int32_t object_id, u_int32_t lock_mask)
{
  struct list_head *ptr, *tmp_ptr;
  struct cluster_referee *entry, *cr = NULL;
  struct list_head *c_obj_tmp_ptr, *c_obj_ptr;
  cluster_object *c_obj_entry = NULL;
  int rc = -1;

  mutex_lock(&cluster_referee_lock);

  /* looking for the cluster */
  list_for_each_safe(ptr, tmp_ptr, &cluster_referee_list) {
    entry = list_entry(ptr, struct cluster_referee, list);
    if(entry->id == cluster_id) {
      cr = entry;
      break;
    }
  }

  if(cr == NULL) {
    debug_printk(2, "cluster %u not found\n", cluster_id);
    goto unlock;
  }

  /* removing locked objects from cluster */
  list_for_each_safe(c_obj_ptr, c_obj_tmp_ptr, &entry->objects_list) {
    c_obj_entry = list_entry(c_obj_ptr, cluster_object, list);
    if(c_obj_entry->object_type == object_type && c_obj_entry->object_id == object_id) {
      c_obj_entry->lock_bitmap &= ~lock_mask;
      break;
    }
  }

  rc = 0;

unlock:
  mutex_unlock(&cluster_referee_lock);

  return rc;
}

/* *********************************************** */

static int is_netdev_promisc(struct net_device *netdev) {
  unsigned int if_flags;

  debug_printk(1, "checking promisc for %s\n", netdev->name);

  rtnl_lock();
  if_flags = (short) dev_get_flags(netdev);
  rtnl_unlock();

  return !!(if_flags & IFF_PROMISC);
}

/* *********************************************** */

static void set_netdev_promisc(struct net_device *netdev) {
  unsigned int if_flags;

  debug_printk(1, "setting promisc for %s\n", netdev->name);

  rtnl_lock();

  if_flags = (short) dev_get_flags(netdev);
  if(!(if_flags & IFF_PROMISC)) {
    if_flags |= IFF_PROMISC;
#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0) && \
    !(defined(REDHAT_PATCHED_KERNEL) && RHEL_MAJOR == 8 && RHEL_MINOR >= 1))
    dev_change_flags(netdev, if_flags);
#else
    dev_change_flags(netdev, if_flags, NULL);
#endif
  }

  rtnl_unlock();
}

/* *********************************************** */

static void unset_netdev_promisc(struct net_device *netdev) {
  unsigned int if_flags;

  debug_printk(1, "resetting promisc for %s\n", netdev->name);

  rtnl_lock();

  if_flags = (short) dev_get_flags(netdev);
  if(if_flags & IFF_PROMISC) {
    if_flags &= ~IFF_PROMISC;
#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0) && \
    !(defined(REDHAT_PATCHED_KERNEL) && RHEL_MAJOR == 8 && RHEL_MINOR >= 1))
    dev_change_flags(netdev, if_flags);
#else
    dev_change_flags(netdev, if_flags, NULL);
#endif
  }

  rtnl_unlock();
}

/* *********************************************** */

static void set_ringdev_promisc(pf_ring_device *ring_dev) {
  if(atomic_inc_return(&ring_dev->promisc_users) != 1) 
    return; /* not the first user (promisc already set) */

  if(is_netdev_promisc(ring_dev->dev)) {
    /* promisc already set via ifconfig */
    ring_dev->do_not_remove_promisc = 1;
    return;
  } 
 
  ring_dev->do_not_remove_promisc = 0;
  set_netdev_promisc(ring_dev->dev);
}

/* *********************************************** */

static void unset_ringdev_promisc(pf_ring_device *ring_dev) {
  if(!atomic_read(&ring_dev->promisc_users)) /*safety check */
    return; /* no users */

  if(atomic_dec_return(&ring_dev->promisc_users) != 0)
    return; /* not the last user (keep promisc) */

  if(ring_dev->do_not_remove_promisc)
    return; /* promisc set via ifconfig (keep promisc) */

  unset_netdev_promisc(ring_dev->dev);
}

/* *********************************************** */

static void set_socket_promisc(struct pf_ring_socket *pfr) {
  struct list_head *ptr, *tmp_ptr;

  if (pfr->promisc_enabled)
    return;

  set_ringdev_promisc(pfr->ring_dev);

  /* managing promisc for additional devices */
  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    pf_ring_device *dev_ptr = list_entry(ptr, pf_ring_device, device_list);
    int32_t dev_index = ifindex_to_pf_index(netns_lookup(sock_net(pfr->sk)),
                                            dev_ptr->dev->ifindex);
    if(pfr->ring_dev->dev->ifindex != dev_ptr->dev->ifindex &&
       dev_index >= 0 && test_bit(dev_index, pfr->pf_dev_mask))
      set_ringdev_promisc(dev_ptr);
  }

  pfr->promisc_enabled = 1;
}

/* *********************************************** */

static void unset_socket_promisc(struct pf_ring_socket *pfr) {
  struct list_head *ptr, *tmp_ptr;

  if (!pfr->promisc_enabled)
    return;

  unset_ringdev_promisc(pfr->ring_dev);

  /* managing promisc for additional devices */
  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    pf_ring_device *dev_ptr = list_entry(ptr, pf_ring_device, device_list);
    int32_t dev_index = ifindex_to_pf_index(netns_lookup(sock_net(pfr->sk)),
                                            dev_ptr->dev->ifindex);
    if(pfr->ring_dev->dev->ifindex != dev_ptr->dev->ifindex &&
       dev_index >= 0 && test_bit(dev_index, pfr->pf_dev_mask))
      unset_ringdev_promisc(dev_ptr);
  }

  pfr->promisc_enabled = 0;
}

/* *********************************************** */

static int ring_release(struct socket *sock)
{
  struct sock *sk = sock->sk;
  struct pf_ring_socket *pfr;
  pf_ring_net *netns;
  struct list_head *ptr, *tmp_ptr;
  void *ring_memory_ptr;
  int free_ring_memory = 1;

  if(!sk)
    return 0;

  pfr = ring_sk(sk);

  pfr->ring_active = 0;

  netns = netns_lookup(sock_net(sk));

  /* Wait until the ring is being used... */
  while(atomic_read(&pfr->num_ring_users) > 0) {
    schedule();
  }

  debug_printk(2, "called ring_release(%s)\n", pfr->ring_dev->dev->name);

  if(pfr->kernel_consumer_options) kfree(pfr->kernel_consumer_options);

  sock_orphan(sk);
  ring_proc_remove(pfr);

  if(pfr->tx.last_tx_dev != NULL)
    dev_put(pfr->tx.last_tx_dev); /* Release device */

  mutex_lock(&ring_mgmt_lock);

  if(pfr->ring_dev->dev && pfr->ring_dev == &any_device_element)
    netns->num_any_rings--;
  else {
    if(pfr->ring_dev) {
      int32_t dev_index = ifindex_to_pf_index(netns, pfr->ring_dev->dev->ifindex);
      if (dev_index >= 0) {

        /* Check all bound devices in case of multi devices */
        list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
          pf_ring_device *dev_ptr = list_entry(ptr, pf_ring_device, device_list);
          dev_index = ifindex_to_pf_index(netns, dev_ptr->dev->ifindex);
  	  if(dev_index >= 0 && test_bit(dev_index, pfr->pf_dev_mask)) {

            if(netns->num_rings_per_device[dev_index] > 0)
	      netns->num_rings_per_device[dev_index]--;

	    if(quick_mode) {
              int i;
              /* Reset quick mode for all channels */
              for(i=0; i<MAX_NUM_RX_CHANNELS; i++) {
                u_int64_t channel_id_bit = 1 << i;
	        if((pfr->channel_id_mask & channel_id_bit) && netns->quick_mode_rings[dev_index][i] == pfr)
	          netns->quick_mode_rings[dev_index][i] = NULL;
	      }
            }
          }
	}
      }
    }
  }

  if(pfr->ring_dev != &none_device_element) {
    if(pfr->cluster_id != 0)
      remove_from_cluster(sk, pfr);
  }

  ring_remove(sk);

  sock->sk = NULL;

  /* Free rules */
  if(pfr->ring_dev != &none_device_element) {
    list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
      sw_filtering_rule_element *rule;

      rule = list_entry(ptr, sw_filtering_rule_element, list);

      list_del(ptr);
      free_filtering_rule(rule, 1);
      kfree(rule);
    }

    /* Filtering hash rules */
    if(pfr->sw_filtering_hash) {
      int i;

      for(i = 0; i < perfect_rules_hash_size; i++) {
	if(pfr->sw_filtering_hash[i] != NULL) {
	  sw_filtering_hash_bucket *scan = pfr->sw_filtering_hash[i], *next;

	  while(scan != NULL) {
	    next = scan->next;

	    free_sw_filtering_hash_bucket(scan);
	    kfree(scan);
	    scan = next;
	  }
	}
      }

      kfree(pfr->sw_filtering_hash);
    }

    /* Free Hw Filtering Rules */
    if(pfr->num_hw_filtering_rules > 0) {
      list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
	hw_filtering_rule_element *hw_rule = list_entry(ptr, hw_filtering_rule_element, list);

	/* Remove hw rule */
	handle_hw_filtering_rule(pfr, &hw_rule->rule, remove_hw_rule);

	list_del(ptr);
	kfree(hw_rule);
      }
    }
  }

  if(pfr->v_filtering_dev != NULL) {
    remove_virtual_filtering_device(pfr, pfr->v_filtering_dev->info.device_name);
    pfr->v_filtering_dev = NULL;
    /* pfr->v_filtering_dev has been freed by remove_virtual_filtering_device() */
  }

  /* Free the ring buffer later, vfree needs interrupts enabled */
  ring_memory_ptr = pfr->ring_memory;
  ring_sk(sk) = NULL;
  skb_queue_purge(&sk->sk_write_queue);

  mutex_unlock(&ring_mgmt_lock);

  mutex_lock(&pfr->ring_config_lock);

  if(ring_memory_ptr != NULL && free_ring_memory)
    vfree(ring_memory_ptr);

  if(pfr->cluster_referee != NULL)
    remove_cluster_referee(pfr);

  if((pfr->zc_device_entry != NULL)
     && pfr->zc_device_entry->zc_dev.dev) {
    pfring_release_zc_dev(pfr);
  }

  if(pfr->extra_dma_memory != NULL) {
    free_extra_dma_memory(pfr->extra_dma_memory);
    pfr->extra_dma_memory = NULL;
  }

  if(pfr->promisc_enabled)
    unset_socket_promisc(pfr);

  mutex_unlock(&pfr->ring_config_lock);

  sock_put(sk);

  /*
     Wait long enough so that other threads using ring_table
     have finished referencing the socket pointer that
     we will be deleting
  */
  wmb();
  msleep(100 /* 100 msec */);

  kfree(pfr); /* Time to free */

  debug_printk(2, "ring_release: done\n");

  /* Some housekeeping tasks */
  lockless_list_empty(&delayed_memory_table, 1 /* free memory */);

  return 0;
}

/* ********************************** */

/*
 * We create a ring for this socket and bind it to the specified device
 */
static int packet_ring_bind(struct sock *sk, pf_ring_device *dev)
{
  struct pf_ring_socket *pfr = ring_sk(sk);
  pf_ring_net *netns;
  int32_t dev_index;

  netns = netns_lookup(sock_net(sk));

  if(dev->dev->type != ARPHRD_ETHER && dev->dev->type != ARPHRD_LOOPBACK) {
    printk("[PF_RING] bind: %s has unsupported type\n", dev->dev->name);
    return -EINVAL;
  }

  dev_index = ifindex_to_pf_index(netns, dev->dev->ifindex);

  if(dev_index < 0) {
    printk("[PF_RING] bind: %s dev index not found\n", dev->dev->name);
    return -EINVAL;
  }

  if(strcmp(dev->dev->name, "none") != 0 &&
      strcmp(dev->dev->name, "any") != 0 &&
      !(dev->dev->flags & IFF_UP)) {
    printk("[PF_RING] bind: device %s is down, bring it up to capture\n", dev->dev->name);
    return -ENETDOWN;
  }

  debug_printk(2, "packet_ring_bind(%s, bucket_len=%d) called\n",
               dev->dev->name, pfr->bucket_len);

  /* Set for all devices */
  set_bit(dev_index, pfr->pf_dev_mask);
  pfr->num_bound_devices++;

  /* We set the master device only when we have not yet set a device */
  if(pfr->ring_dev == &none_device_element) {
    /* Remove old binding (by default binding to none) BEFORE binding to a new device */
    ring_proc_remove(pfr);

    /* IMPORTANT
     * Leave this statement here as last one. In fact when
     * the ring_netdev != &none_device_element the socket is ready to be used. */
    pfr->ring_dev = dev;
    pfr->channel_id_mask = RING_ANY_CHANNEL;

    /* Time to rebind to a new device */
    ring_proc_add(pfr);
  }

  pfr->last_bind_dev = dev;

  pfr->num_rx_channels = get_num_rx_queues(pfr->ring_dev->dev);

  if(dev == &any_device_element && !quick_mode) {
    netns->num_any_rings++;
  } else {
    netns->num_rings_per_device[dev_index]++;
  }

  return 0;
}

/* ************************************* */

/* Bind to a device */
static int ring_bind(struct socket *sock, struct sockaddr *sa, int addr_len)
{
  struct sock *sk = sock->sk;
  struct net *net = sock_net(sk);
  pf_ring_device *dev = NULL;

  debug_printk(2, "ring_bind() called\n");

  /*
   * Check legality
   */
  if (addr_len == sizeof(struct sockaddr)) {
    char name[sizeof(sa->sa_data)+1];

    if (sa->sa_family != PF_RING)
      return(-EINVAL);

    memcpy(name, sa->sa_data, sizeof(sa->sa_data));

    /* Add trailing zero if missing */
    name[sizeof(name)-1] = '\0';

    debug_printk(2, "searching device %s\n", name);

    if(strcmp(name, "none") == 0 ||
       strcmp(name, "any") == 0)
      net = NULL; /* any namespace*/

    dev = pf_ring_device_name_lookup(net, name);

    if (dev == NULL) {
      printk("[PF_RING] bind: %s not found\n", name);
      return -EINVAL;
    }

  } else if (addr_len == sizeof(struct sockaddr_ll)) {
    struct sockaddr_ll *sll = (struct sockaddr_ll *) sa;     
    int ifindex = sll->sll_ifindex; 

    if (sll->sll_family != PF_RING)
      return(-EINVAL);

    if(ifindex == ANY_IFINDEX ||
       ifindex == NONE_IFINDEX)
      net = NULL; /* any namespace*/

    dev = pf_ring_device_ifindex_lookup(net, ifindex);

    if (dev == NULL) {
      printk("[PF_RING] bind: ifindex %d not found\n", ifindex);
      return -EINVAL;
    }

  } else {
    return(-EINVAL);
  }

  return(packet_ring_bind(sk, dev));
}

/* ************************************* */

static int do_memory_mmap(struct vm_area_struct *vma, unsigned long start_off, unsigned long size,
                          char *ptr, u_int ptr_pg_off, u_int flags, int mode)
{
  unsigned long start;

  /* we do not want to have this area swapped out, lock it */
  vma->vm_flags |= flags;

  start = vma->vm_start + start_off;

  debug_printk(2, "mode=%d, size=%lu, ptr=%p\n", mode, size, ptr);

  while(size > 0) {
    int rc;

    if(mode == 0) {
      rc = remap_vmalloc_range(vma, ptr, ptr_pg_off);
      break; /* Do not iterate */
    } else if(mode == 1) {
      rc = remap_pfn_range(vma, start, __pa(ptr) >> PAGE_SHIFT, PAGE_SIZE, PAGE_SHARED);
    } else {
      rc = remap_pfn_range(vma, start, ((unsigned long)ptr) >> PAGE_SHIFT, PAGE_SIZE, PAGE_SHARED);
    }

    if(rc) {
      debug_printk(2, "remap_pfn_range() failed\n");

      return(-EAGAIN);
    }

    start += PAGE_SIZE;
    ptr += PAGE_SIZE;
    if(size > PAGE_SIZE) {
      size -= PAGE_SIZE;
    } else {
      size = 0;
    }
  }

  return(0);
}

/* ************************************* */

static int ring_mmap(struct file *file,
		     struct socket *sock, struct vm_area_struct *vma)
{
  struct sock *sk = sock->sk;
  struct pf_ring_socket *pfr = ring_sk(sk);
  int rc;
  unsigned long mem_id = vma->vm_pgoff; /* using vm_pgoff as memory id */
  unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

  debug_printk(2, "called\n");

  if(size % PAGE_SIZE) {
    debug_printk(2, "failed: len is not multiple of PAGE_SIZE\n");

    return(-EINVAL);
  }

  debug_printk(2, "called, size: %ld bytes [bucket_len=%d]\n",
	       size, pfr->bucket_len);

  /* Trick for mapping packet memory chunks */
  if(mem_id >= 100) {
    mem_id -= 100;

    if(pfr->zc_dev) {
      if(pfr->extra_dma_memory && mem_id < pfr->extra_dma_memory->num_chunks) {
        /* Extra DMA memory */

        if(pfr->extra_dma_memory->virtual_addr == NULL)
          return(-EINVAL);

        if(size > pfr->extra_dma_memory->chunk_len) {
          debug_printk(2, "failed: area too large [%ld > %u]\n", size, pfr->extra_dma_memory->chunk_len);
          return(-EINVAL);
        }

        if((rc = do_memory_mmap(vma, 0, size, (void *)pfr->extra_dma_memory->virtual_addr[mem_id], 0, VM_LOCKED, 1)) < 0)
          return(rc);

	return(0);
      }
    }

    printk("[PF_RING] %s: failed: not ZC dev\n", __FUNCTION__);
    return(-EINVAL);
  }

  switch(mem_id) {
    /* RING */
    case 0:
      if(pfr->zc_dev != NULL) {
        printk("[PF_RING] %s: trying to map ring memory on ZC socket\n", __FUNCTION__);
	return(-EINVAL);
      }

      if(pfr->ring_memory == NULL) {
        if(ring_alloc_mem(sk) != 0) {
          printk("[PF_RING] %s: unable to allocate memory\n", __FUNCTION__);
          return(-EINVAL);
        }
      }

      /* If userspace tries to mmap beyond end of our buffer, then fail */
      if(size > pfr->slots_info->tot_mem) {
        debug_printk(2, "failed: area too large [%ld > %llu]\n", size, pfr->slots_info->tot_mem);
        return(-EINVAL);
      }

      debug_printk(2, "mmap [slot_len=%d][tot_slots=%d] for ring on device %s\n",
	       pfr->slots_info->slot_len, pfr->slots_info->min_num_slots, pfr->ring_dev->dev->name);

      if((rc = do_memory_mmap(vma, 0, size, (void *) pfr->ring_memory, 0, VM_LOCKED, 0)) < 0)
        return(rc);

      break;
    case 1:
      /* ZC: RX packet descriptors */
      if(pfr->zc_dev == NULL) {
        debug_printk(2, "failed: operation for ZC only");
        return(-EINVAL);
      }

      if(size > pfr->zc_dev->mem_info.rx.descr_packet_memory_tot_len) {
        debug_printk(2, "failed: area too large [%ld > %u]\n", size, pfr->zc_dev->mem_info.rx.descr_packet_memory_tot_len);
        return(-EINVAL);
      }

      if((rc = do_memory_mmap(vma, 0, size, (void *) pfr->zc_dev->rx_descr_packet_memory, 0, VM_LOCKED, 1)) < 0)
	return(rc);

      break;
    case 2:
      /* ZC: Physical card memory */
      if(pfr->zc_dev == NULL) {
        debug_printk(2, "failed: operation for ZC only");
        return(-EINVAL);
      }

      if(size > pfr->zc_dev->mem_info.phys_card_memory_len) {
        debug_printk(2, "failed: area too large [%ld > %u]\n", size, pfr->zc_dev->mem_info.phys_card_memory_len);
        return(-EINVAL);
      }

      if((rc = do_memory_mmap(vma, 0, size, (void *) pfr->zc_dev->phys_card_memory, 0, (
#if(LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
                                                                                           VM_IO | VM_RESERVED
#else
                                                                                           VM_IO | VM_DONTEXPAND | VM_DONTDUMP
#endif
	                                                                                  ), 2)) < 0)
	return(rc);

      break;
    case 3:
      /* ZC: TX packet descriptors */
      if(pfr->zc_dev == NULL) {
        debug_printk(2, "failed: operation for ZC only");
        return(-EINVAL);
      }

      if(size > pfr->zc_dev->mem_info.tx.descr_packet_memory_tot_len) {
        debug_printk(2, "failed: area too large [%ld > %u]\n", size, pfr->zc_dev->mem_info.tx.descr_packet_memory_tot_len);
        return(-EINVAL);
      }

      if((rc = do_memory_mmap(vma, 0, size, (void *) pfr->zc_dev->tx_descr_packet_memory, 0, VM_LOCKED, 1)) < 0)
	return(rc);

      break;
    default:
      return(-EAGAIN);
  }

  debug_printk(2, "succeeded\n");

  return 0;
}

/* ************************************* */

#if(LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0))
static int ring_recvmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t len, int flags)
#else
static int ring_recvmsg(struct socket *sock,
			struct msghdr *msg, size_t len, int flags)
#endif
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  u_int32_t queued_pkts, num_loops = 0;

  debug_printk(2, "ring_recvmsg called\n");

  pfr->ring_active = 1;

  while((queued_pkts = num_queued_pkts(pfr)) < MIN_QUEUED_PKTS) {
    wait_event_interruptible(pfr->ring_slots_waitqueue, 1);

    debug_printk(2, "-> ring_recvmsg "
	     "[queued_pkts=%d][num_loops=%d]\n",
	     queued_pkts, num_loops);

    if(queued_pkts > 0) {
      if(num_loops++ > MAX_QUEUE_LOOPS)
	break;
    }
  }

  return(queued_pkts);
}

/* ************************************* */

static int pf_ring_inject_packet_to_stack(struct net_device *netdev, struct msghdr *msg, size_t len)
{
  int err = 0;
  struct sk_buff *skb = __netdev_alloc_skb(netdev, len, GFP_KERNEL);

  if(skb == NULL)
    return -ENOBUFS;

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0))
  err = memcpy_from_msg(skb_put(skb,len), msg, len);
#else
  err = memcpy_fromiovec(skb_put(skb,len), msg->msg_iov, len);
#endif

  if(err)
    return err;

  skb->protocol = eth_type_trans(skb, netdev);
  skb->queue_mapping = 0xffff;

  err = netif_rx_ni(skb);

  if(unlikely(debug_on(2) && err == NET_RX_SUCCESS))
    debug_printk(2, "Packet injected into the linux kernel!\n");

  return err;
}

/* ************************************* */

/* This code is mostly coming from af_packet.c */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0))
static int ring_sendmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t len)
#else
static int ring_sendmsg(struct socket *sock,
			struct msghdr *msg, size_t len)
#endif
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  struct sockaddr_pkt *saddr;
  struct sk_buff *skb;
  __be16 proto = 0;
  int err = 0;

  /*
   *	Get and verify the address.
   */
  saddr = (struct sockaddr_pkt *)msg->msg_name;
  if(saddr) {
      if(saddr == NULL) proto = htons(ETH_P_ALL);

      if(msg->msg_namelen < sizeof(struct sockaddr)) {
	err = -EINVAL;
	goto out;
      }

      if(msg->msg_namelen == sizeof(struct sockaddr_pkt))
	proto = saddr->spkt_protocol;
  } else {
    err = -ENOTCONN;	/* SOCK_PACKET must be sent giving an address */
    goto out;
  }

  /*
   *	Find the device first to size check it
   */
  if(pfr->ring_dev->dev == NULL)
    goto out;

  err = -ENETDOWN;
  if(!(pfr->ring_dev->dev->flags & IFF_UP))
    goto out;

  /*
   *	You may not queue a frame bigger than the mtu. This is the lowest level
   *	raw protocol and you must do your own fragmentation at this level.
   */
  err = -EMSGSIZE;
  if(len > pfr->ring_dev->dev->mtu + pfr->ring_dev->dev->hard_header_len + VLAN_HLEN)
    goto out;

  if(pfr->stack_injection_mode) {
    err = pf_ring_inject_packet_to_stack(pfr->ring_dev->dev, msg, len);
    goto out;
  }

  err = -ENOBUFS;
  skb = sock_wmalloc(sock->sk, len + LL_RESERVED_SPACE(pfr->ring_dev->dev), 0, GFP_KERNEL);

  /*
   *	If the write buffer is full, then tough. At this level the user gets to
   *	deal with the problem - do your own algorithmic backoffs. That's far
   *	more flexible.
   */

  if(skb == NULL)
    goto out;

  /*
   *	Fill it in
   */

  /* FIXME: Save some space for broken drivers that write a
   * hard header at transmission time by themselves. PPP is the
   * notable one here. This should really be fixed at the driver level.
   */
  skb_reserve(skb, LL_RESERVED_SPACE(pfr->ring_dev->dev));
  skb_reset_network_header(skb);

  /* Try to align data part correctly */
  if(pfr->ring_dev->dev->header_ops) {
    skb->data -= pfr->ring_dev->dev->hard_header_len;
    skb->tail -= pfr->ring_dev->dev->hard_header_len;
    if(len < pfr->ring_dev->dev->hard_header_len)
      skb_reset_network_header(skb);
  }

  /* Returns -EFAULT on error */
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0))
  err = memcpy_from_msg(skb_put(skb,len), msg, len);
#else
  err = memcpy_fromiovec(skb_put(skb,len), msg->msg_iov, len);
#endif
  skb->protocol = proto;
  skb->dev = pfr->ring_dev->dev;
  skb->priority = sock->sk->sk_priority;
  if(err)
    goto out_free;

  /*
   *	Now send it
   */

  if(dev_queue_xmit(skb) != NETDEV_TX_OK) {
    err = -ENETDOWN; /* Probably we need a better error here */
    goto out;
  }

  pfr->slots_info->good_pkt_sent++;
  return(len);

 out_free:
  kfree_skb(skb);

 out:
  if(pfr->slots_info) {
    if(err == 0)
      pfr->slots_info->good_pkt_sent++;
    else
      pfr->slots_info->pkt_send_error++;
  }

  return err;
}

/* ************************************* */

unsigned int ring_poll(struct file *file,
		       struct socket *sock, poll_table * wait)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  int rc, mask = 0;
  u_long now=0;

  pfr->num_poll_calls++;

  if(unlikely(pfr->ring_shutdown))
    return(mask);

  if(pfr->zc_dev == NULL) {
    /* PF_RING mode (No ZC) */

    pfr->ring_active = 1;

    if(pfr->tx.enable_tx_with_bounce && pfr->header_len == long_pkt_header) {
      spin_lock_bh(&pfr->tx.consume_tx_packets_lock);
      consume_pending_pkts(pfr, 1);
      spin_unlock_bh(&pfr->tx.consume_tx_packets_lock);
    }

    if(num_queued_pkts(pfr) < pfr->poll_num_pkts_watermark /* || pfr->num_poll_calls == 1 */)
      poll_wait(file, &pfr->ring_slots_waitqueue, wait);

    /* Flush the queue when watermark reached */
    if(num_queued_pkts(pfr) >= pfr->poll_num_pkts_watermark) {
      mask |= POLLIN | POLLRDNORM;
      pfr->queue_nonempty_timestamp=0;
    }

    if( pfr->poll_watermark_timeout > 0 ) {
      /* Flush the queue also in case its not empty but timeout passed */
      if( num_queued_pkts(pfr) > 0 ) {
        now = jiffies;
        if( pfr->queue_nonempty_timestamp == 0 ) {
          pfr->queue_nonempty_timestamp = now;
        } else if( (jiffies_to_msecs(now - pfr->queue_nonempty_timestamp) >= (u_long)pfr->poll_watermark_timeout) ) {
            debug_printk(2, "[ring_id=%u] Flushing queue (num_queued_pkts=%llu, now=%lu, queue_nonempty_timestamp=%lu, diff=%u, pfr->poll_watermark_timeout=%u)\n",
                      pfr->ring_id, num_queued_pkts(pfr), now, pfr->queue_nonempty_timestamp, jiffies_to_msecs(now - pfr->queue_nonempty_timestamp), pfr->poll_watermark_timeout);
            mask |= POLLIN | POLLRDNORM;
            pfr->queue_nonempty_timestamp=0;
        }
      }
    }

    return(mask);
  } else {
    /* ZC mode */
    /* enable_debug = 1;  */

    debug_printk(2, "poll called on ZC device [%d]\n",
	     *pfr->zc_dev->interrupt_received);

    if(pfr->zc_dev->wait_packet_function_ptr == NULL) {
      debug_printk(2, "wait_packet_function_ptr is NULL: returning to caller\n");

      return(0);
    }

    rc = pfr->zc_dev->wait_packet_function_ptr(pfr->zc_dev->rx_adapter_ptr, 1);

    debug_printk(2, "wait_packet_function_ptr(1) returned %d\n", rc);

    if(rc == 0) {
      debug_printk(2, "calling poll_wait()\n");

      /* No packet arrived yet */
      poll_wait(file, pfr->zc_dev->packet_waitqueue, wait);

      debug_printk(2, "poll_wait() just returned\n");
    } else {
      rc = pfr->zc_dev->wait_packet_function_ptr(pfr->zc_dev->rx_adapter_ptr, 0);
    }

    debug_printk(2, "wait_packet_function_ptr(0) returned %d\n", rc);

    debug_printk(2, "poll %s return [%d]\n",
	     pfr->ring_dev->dev->name,
	     *pfr->zc_dev->interrupt_received);

    if(*pfr->zc_dev->interrupt_received) {
      return(POLLIN | POLLRDNORM);
    } else {
      return(0);
    }
  }
}

/* ************************************* */

int add_sock_to_cluster_list(ring_cluster_element *el, struct sock *sk)
{
  struct pf_ring_socket *pfr = ring_sk(sk);

  if(el->cluster.num_cluster_elements == CLUSTER_LEN)
    return(-1);	/* Cluster full */

  if (el->cluster.num_cluster_elements > 0) {
    struct sock *first_sk = el->cluster.sk[0];
    struct pf_ring_socket *first_pfr = ring_sk(first_sk);
    if (!bitmap_equal(first_pfr->pf_dev_mask, pfr->pf_dev_mask, MAX_NUM_DEV_IDX)) {
      printk("[PF_RING] Error: adding sockets with different interfaces to cluster %u\n", 
        el->cluster.cluster_id);
      return(-EINVAL);
    }
  }

  ring_sk(sk)->cluster_id = el->cluster.cluster_id;
  el->cluster.sk[el->cluster.num_cluster_elements] = sk;
  el->cluster.num_cluster_elements++;
  return(0);
}

/* ************************************* */

int remove_from_cluster_list(struct ring_cluster *el, struct sock *sock)
{
  int i, j;

  for(i = 0; i < CLUSTER_LEN; i++)
    if(el->sk[i] == sock) {
      el->num_cluster_elements--;

      if(el->num_cluster_elements > 0) {
	/* The cluster contains other elements */
	for(j = i; j < CLUSTER_LEN - 1; j++)
	  el->sk[j] = el->sk[j + 1];

	el->sk[CLUSTER_LEN - 1] = NULL;
      } else {
	/* Empty cluster */
	memset(el->sk, 0, sizeof(el->sk));
      }

      return(0);
    }

  return(-1); /* Not found */
}

/* ************************************* */

static int remove_from_cluster(struct sock *sock, struct pf_ring_socket *pfr)
{
  ring_cluster_element *cluster_ptr;
  u_int32_t last_list_idx;

  debug_printk(2, "--> remove_from_cluster(%d)\n", pfr->cluster_id);

  if(pfr->cluster_id == 0 /* 0 = No Cluster */ )
    return(0);	/* Nothing to do */

  write_lock_bh(&ring_cluster_lock);

  cluster_ptr = (ring_cluster_element*)lockless_list_get_first(&ring_cluster_list, &last_list_idx);

  while(cluster_ptr != NULL) {
    if(cluster_ptr->cluster.cluster_id == pfr->cluster_id) {
      int ret = remove_from_cluster_list(&cluster_ptr->cluster, sock);

      if(cluster_ptr->cluster.num_cluster_elements == 0) {
	lockless_list_remove(&ring_cluster_list, cluster_ptr);
	lockless_list_add(&delayed_memory_table, cluster_ptr); /* Free later */
      }

      write_unlock_bh(&ring_cluster_lock);
      return ret;
    }

    cluster_ptr = (ring_cluster_element*)lockless_list_get_next(&ring_cluster_list, &last_list_idx);
  }

  write_unlock_bh(&ring_cluster_lock);
  return(-EINVAL);	/* Not found */
}

/* ************************************* */

static int set_master_ring(struct sock *sock,
			   struct pf_ring_socket *pfr,
			   u_int32_t master_socket_id)
{
  int rc = -1;
  u_int32_t last_list_idx;
  struct sock *sk;

  debug_printk(2, "set_master_ring(%s=%d)\n",
	   pfr->ring_dev->dev ? pfr->ring_dev->dev->name : "none",
	   master_socket_id);

  sk = (struct sock*)lockless_list_get_first(&ring_table, &last_list_idx);

  while(sk != NULL) {
    struct pf_ring_socket *pfr;

    pfr = ring_sk(sk);

    if((pfr != NULL) && (pfr->ring_id == master_socket_id)) {
      pfr->master_ring = pfr;

      debug_printk(2, "Found set_master_ring(%s) -> %s\n",
	       pfr->ring_dev->dev ? pfr->ring_dev->dev->name : "none",
	       pfr->master_ring->ring_dev->dev->name);

      rc = 0;
      break;
    } else {
      debug_printk(2, "Skipping socket(%s)=%d\n",
	       pfr->ring_dev->dev ? pfr->ring_dev->dev->name : "none",
	       pfr->ring_id);
    }

    sk = (struct sock*)lockless_list_get_next(&ring_table, &last_list_idx);
  }

  debug_printk(2, "set_master_ring(%s, socket_id=%d) = %d\n",
	   pfr->ring_dev->dev ? pfr->ring_dev->dev->name : "none",
	   master_socket_id, rc);

  return(rc);
}

/* ************************************* */

static int add_sock_to_cluster(struct sock *sock,
			       struct pf_ring_socket *pfr,
			       struct add_to_cluster *cluster)
{
  ring_cluster_element *cluster_ptr;
  u_int32_t last_list_idx;
  int rc;

  debug_printk(2, "--> add_sock_to_cluster(%d)\n", cluster->clusterId);

  if(cluster->clusterId == 0 /* 0 = No Cluster */ )
    return(-EINVAL);

  if(pfr->cluster_id != 0)
    remove_from_cluster(sock, pfr);

  write_lock_bh(&ring_cluster_lock);

  cluster_ptr = (ring_cluster_element*)lockless_list_get_first(&ring_cluster_list, &last_list_idx);

  while(cluster_ptr != NULL) {
    if(cluster_ptr->cluster.cluster_id == cluster->clusterId) {

      /* Cluster already present, adding socket */
      rc = add_sock_to_cluster_list(cluster_ptr, sock);

      write_unlock_bh(&ring_cluster_lock);
      return(rc);
    }

    cluster_ptr = (ring_cluster_element*)lockless_list_get_next(&ring_cluster_list, &last_list_idx);
  }

  /* The cluster does not exist, creating it.. */

  if((cluster_ptr = kmalloc(sizeof(ring_cluster_element), GFP_KERNEL)) == NULL) {
    write_unlock_bh(&ring_cluster_lock);
    return(-ENOMEM);
  }

  INIT_LIST_HEAD(&cluster_ptr->list);

  cluster_ptr->cluster.cluster_id = cluster->clusterId;
  cluster_ptr->cluster.num_cluster_elements = 1;
  cluster_ptr->cluster.hashing_mode = cluster->the_type; /* Default */
  cluster_ptr->cluster.hashing_id = 0;

  memset(cluster_ptr->cluster.sk, 0, sizeof(cluster_ptr->cluster.sk));
  cluster_ptr->cluster.sk[0] = sock;
  pfr->cluster_id = cluster->clusterId;
  lockless_list_add(&ring_cluster_list, cluster_ptr);

  write_unlock_bh(&ring_cluster_lock);

  return(0); /* 0 = OK */
}

/* ************************************* */

static int pfring_select_zc_dev(struct pf_ring_socket *pfr, zc_dev_mapping *mapping)
{
  pf_ring_device *dev_ptr;
  zc_dev_list *entry;

  printk("[PF_RING] Trying to map ZC device %s@%d\n", mapping->device_name, mapping->channel_id);

  if(strlen(mapping->device_name) == 0)
    printk("[PF_RING] %s:%d ZC socket with empty device name!\n", __FUNCTION__, __LINE__);

  entry = pf_ring_zc_dev_name_lookup(mapping->device_name, mapping->channel_id);

  if(!entry) {
    printk("[PF_RING] %s:%d %s@%u mapping failed or not a ZC device\n", __FUNCTION__, __LINE__,
	   mapping->device_name, mapping->channel_id);
    return -1;
  }

  mapping->device_model = entry->zc_dev.mem_info.device_model;

  /* looking for ring_netdev device, setting it here as it is used
   * also before pfring_get_zc_dev to set promisc */
  dev_ptr = pf_ring_device_name_lookup(sock_net(pfr->sk), mapping->device_name);

  if(dev_ptr != NULL) {
    debug_printk(1, "found %s [%p]\n", dev_ptr->device_name, dev_ptr);
    pfr->ring_dev = dev_ptr;
  } else {
    printk("[PF_RING] %s:%d something got wrong adding %s@%u (device not found)\n", __FUNCTION__, __LINE__,
           mapping->device_name, mapping->channel_id);
    return -1; /* Something got wrong */
  }

  memcpy(&pfr->zc_mapping, mapping, sizeof(zc_dev_mapping));

  return 0;
}

/* ************************************* */

static int pfring_get_zc_dev(struct pf_ring_socket *pfr) {
  zc_dev_list *entry;
  int i, found, rc;
  int32_t dev_index;

  debug_printk(1, "%s@%d\n", pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);

  if(strlen(pfr->zc_mapping.device_name) == 0)
    printk("[PF_RING] %s:%d %s ZC socket with empty device name!\n", __FUNCTION__, __LINE__,
      pfr->zc_mapping.operation == add_device_mapping ? "opening" : "closing");

  entry = pf_ring_zc_dev_name_lookup(pfr->zc_mapping.device_name,
    pfr->zc_mapping.channel_id);

  if(!entry) {
    printk("[PF_RING] %s:%d %s@%u mapping failed or not a ZC device\n", __FUNCTION__, __LINE__,
	   pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);
    return -1;
  }

  dev_index = ifindex_to_pf_index(netns_lookup(sock_net(pfr->sk)),
                                  entry->zc_dev.dev->ifindex);

  if (dev_index < 0) {
    printk("[PF_RING] %s:%d %s@%u mapping failed, dev index not found\n", __FUNCTION__, __LINE__,
	   pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);
    return -1;
  }

  ring_proc_remove(pfr);

  debug_printk(1, "%s@%d [num_bound_sockets=%d][%p]\n",
           entry->zc_dev.dev->name, pfr->zc_mapping.channel_id,
           entry->num_bound_sockets, entry);

  spin_lock_bh(&entry->lock);
  found = 0;
  for (i=0; i<MAX_NUM_ZC_BOUND_SOCKETS; i++) {
    if(entry->bound_sockets[i] == NULL) {
      entry->bound_sockets[i] = pfr;
      entry->num_bound_sockets++;
      found = 1;
      break;
    }
  }
  spin_unlock_bh(&entry->lock);

  if(!found) {
    printk("[PF_RING] %s:%d something got wrong adding %s@%u\n", __FUNCTION__, __LINE__,
           pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);
    return -1; /* Something got wrong: too many mappings */
  }

  pfr->zc_device_entry = entry;
  pfr->zc_dev = &entry->zc_dev;

  debug_printk(1, "added mapping %s@%u [num_bound_sockets=%u]\n",
           pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id, entry->num_bound_sockets);

  rc = pfr->zc_dev->usage_notification(pfr->zc_dev->rx_adapter_ptr, pfr->zc_dev->tx_adapter_ptr, 1 /* lock */);

  if (rc != 0) {
    printk("[PF_RING] %s:%d something went wrong detaching %s@%u\n", __FUNCTION__, __LINE__,
           pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);
    return -1;
  }

  ring_proc_add(pfr);

  return 0;
}

/* ************************************* */

static int pfring_release_zc_dev(struct pf_ring_socket *pfr)
{
  zc_dev_list *entry = pfr->zc_device_entry;
  int i, found, rc;
  int32_t dev_index;

  debug_printk(1, "releasing %s@%d\n",
	   pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);

  if(entry == NULL) {
    printk("[PF_RING] %s:%d %s@%u unmapping failed\n", __FUNCTION__, __LINE__,
	   pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);
    return -1;
  }

  dev_index = ifindex_to_pf_index(netns_lookup(dev_net(entry->zc_dev.dev)),
                                  entry->zc_dev.dev->ifindex);

  if (dev_index < 0) {
    printk("[PF_RING] %s:%d %s@%u unmapping failed, dev index not found\n",
           __FUNCTION__, __LINE__,
	   pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);
    return -1;
  }

  spin_lock_bh(&entry->lock);
  found = 0;
  for (i = 0; i < MAX_NUM_ZC_BOUND_SOCKETS; i++) {
    if(entry->bound_sockets[i] == pfr) {
      entry->bound_sockets[i] = NULL;
      entry->num_bound_sockets--;
      found = 1;
      break;
    }
  }
  spin_unlock_bh(&entry->lock);

  if(!found) {
    printk("[PF_RING] %s:%d something got wrong removing socket bound to %s@%u\n",
           __FUNCTION__, __LINE__,
           entry->zc_dev.dev->name != NULL ? entry->zc_dev.dev->name : "?", entry->zc_dev.channel_id);
    return -1; /* Something got wrong */
  }

  debug_printk(1, "%s@%u removed mapping [num_bound_sockets=%u]\n",
           pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id, entry->num_bound_sockets);

  if(pfr->zc_dev != NULL) {
    rc = pfr->zc_dev->usage_notification(pfr->zc_dev->rx_adapter_ptr, pfr->zc_dev->tx_adapter_ptr, 0 /* unlock */);

    pfr->zc_device_entry = NULL;
    pfr->zc_dev = NULL;

    if (rc != 0) {
      printk("[PF_RING] %s:%d something went wrong reattaching %s@%u\n", __FUNCTION__, __LINE__,
             pfr->zc_mapping.device_name, pfr->zc_mapping.channel_id);
      return -1;
    }
  }

  return 0;
}

/* ************************************* */

static int get_fragment_app_id(u_int32_t ipv4_src_host, u_int32_t ipv4_dst_host, u_int16_t fragment_id, u_int8_t more_fragments)
{
  u_int hash_id = fragment_id % NUM_FRAGMENTS_HASH_SLOTS;
  struct list_head *ptr, *tmp_ptr;
  u_int8_t app_id = -1;

  if(num_cluster_fragments == 0)
    return(-1); /* no fragment */

  spin_lock_bh(&cluster_fragments_lock); /* TODO optimisation: lock per hash entry */

  list_for_each_safe(ptr, tmp_ptr, &cluster_fragment_hash[hash_id]) {
    struct hash_fragment_node *frag = list_entry(ptr, struct hash_fragment_node, frag_list);

    if(frag->ip_fragment_id == fragment_id
       && frag->ipv4_src_host == ipv4_src_host
       && frag->ipv4_dst_host == ipv4_dst_host) {
      /* Found: 1) return queue_id and 2) delete this entry if last fragment (not more_fragments) */
      app_id = frag->cluster_app_id;

      if(!more_fragments){
        list_del(ptr);
        kfree(frag);
        num_cluster_fragments--;
      }

      break; /* app_id found */
    }
  }

  spin_unlock_bh(&cluster_fragments_lock);

  return(app_id); /* Not found */
}

/* ************************************* */

static void purge_idle_fragment_cache(void)
{
  struct list_head *ptr, *tmp_ptr;

  if(likely(num_cluster_fragments == 0))
    return;

  if(next_fragment_purge_jiffies < jiffies ||
     num_cluster_fragments > (5*NUM_FRAGMENTS_HASH_SLOTS)) {
    int i;

    debug_printk(2, "[num_cluster_fragments=%d]\n", num_cluster_fragments);

    for(i=0; i<NUM_FRAGMENTS_HASH_SLOTS; i++) {
      list_for_each_safe(ptr, tmp_ptr, &cluster_fragment_hash[i]) {
        struct hash_fragment_node *frag = list_entry(ptr, struct hash_fragment_node, frag_list);

	if(frag->expire_jiffies < jiffies) {
          list_del(ptr);
	  kfree(frag);
          num_cluster_fragments--;
	} else break; /* optimisation: since list is ordered (we are adding to tail) we can skip this collision list */
      }
    } /* for */

    next_fragment_purge_jiffies = jiffies + 5*HZ /* 5 seconds in jiffies */;
  }
}

/* ************************************* */

static void add_fragment_app_id(u_int32_t ipv4_src_host, u_int32_t ipv4_dst_host,
				u_int16_t fragment_id, u_int8_t app_id)
{
  u_int hash_id = fragment_id % NUM_FRAGMENTS_HASH_SLOTS;
  struct list_head *ptr, *tmp_ptr;
  struct hash_fragment_node *frag;

  if(num_cluster_fragments > MAX_CLUSTER_FRAGMENTS_LEN) /* Avoid filling up all memory */
    return;

  spin_lock_bh(&cluster_fragments_lock);

  /* 1. Check if there is already the same entry on cache */
  list_for_each_safe(ptr, tmp_ptr, &cluster_fragment_hash[hash_id]) {
    frag = list_entry(ptr, struct hash_fragment_node, frag_list);

    if(frag->ip_fragment_id == fragment_id
       && frag->ipv4_src_host == ipv4_src_host
       && frag->ipv4_dst_host == ipv4_dst_host) {
      /* Duplicate found */
      frag->cluster_app_id = app_id;
      frag->expire_jiffies = jiffies + 5*HZ;
      spin_unlock_bh(&cluster_fragments_lock);
      return;
    }
  }

  /* 2. Not found, let's add it */
  if((frag = kmalloc(sizeof(struct hash_fragment_node), GFP_ATOMIC)) == NULL) {
    printk("[PF_RING] Out of memory (%s)\n", __FUNCTION__);
    spin_unlock_bh(&cluster_fragments_lock);
    return;
  }

  frag->ip_fragment_id = fragment_id;
  frag->ipv4_src_host = ipv4_src_host;
  frag->ipv4_dst_host = ipv4_dst_host;
  frag->cluster_app_id = app_id;
  frag->expire_jiffies = jiffies + 5*HZ;

  list_add_tail(&frag->frag_list, &cluster_fragment_hash[hash_id]);
  num_cluster_fragments++;
  next_fragment_purge_jiffies = frag->expire_jiffies;
  purge_idle_fragment_cache(); /* Just in case there are too many elements */
  spin_unlock_bh(&cluster_fragments_lock);
}

/* ************************************* */

static void purge_idle_hash_rules(struct pf_ring_socket *pfr,
				  u_int16_t rule_inactivity)
{
  int i, num_purged_rules = 0;
  unsigned long expire_jiffies =
    jiffies - msecs_to_jiffies(1000 * rule_inactivity);

  debug_printk(2, "purge_idle_hash_rules(rule_inactivity=%d)\n",
	   rule_inactivity);

  /* Free filtering hash rules inactive for more than rule_inactivity seconds */
  if(pfr->sw_filtering_hash != NULL) {
    for(i = 0; i < perfect_rules_hash_size; i++) {
      if(pfr->sw_filtering_hash[i] != NULL) {
	sw_filtering_hash_bucket *scan = pfr->sw_filtering_hash[i], *next, *prev = NULL;

	while(scan != NULL) {
	  int rc = 0;
	  next = scan->next;

	  if(scan->rule.internals.jiffies_last_match < expire_jiffies || rc > 0) {
	    /* Expired rule: free it */

	    debug_printk(2, "Purging hash rule "
		      /* "[last_match=%u][expire_jiffies=%u]" */
		      "[%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d][purged=%d][tot_rules=%d]\n",
		      /*
			(unsigned int)scan->rule.internals.jiffies_last_match,
			(unsigned int)expire_jiffies,
		      */
		      ((scan->rule.host4_peer_a >> 24) & 0xff),
		      ((scan->rule.host4_peer_a >> 16) & 0xff),
		      ((scan->rule.host4_peer_a >> 8)  & 0xff),
		      ((scan->rule.host4_peer_a >> 0)  & 0xff),
		      scan->rule.port_peer_a,
		      ((scan->rule.host4_peer_b >> 24) & 0xff),
		      ((scan->rule.host4_peer_b >> 16) & 0xff),
		      ((scan->rule.host4_peer_b >> 8)  & 0xff),
		      ((scan->rule.host4_peer_b >> 0) & 0xff),
		      scan->rule.port_peer_b,
		      num_purged_rules,
		      pfr->num_sw_filtering_hash);

	    free_sw_filtering_hash_bucket(scan);
	    kfree(scan);

	    if(prev == NULL)
	      pfr->sw_filtering_hash[i] = next;
	    else
	      prev->next = next;

	    pfr->num_sw_filtering_hash--;
	    num_purged_rules++;
	  } else
	    prev = scan;

	  scan = next;
	}
      }
    }
  }

  debug_printk(2, "Purged %d hash rules [tot_rules=%d]\n",
	   num_purged_rules, pfr->num_sw_filtering_hash);
}

/* ************************************* */

static void purge_idle_rules(struct pf_ring_socket *pfr,
			     u_int16_t rule_inactivity)
{
  struct list_head *ptr, *tmp_ptr;
  int num_purged_rules = 0;
  unsigned long expire_jiffies =
    jiffies - msecs_to_jiffies(1000 * rule_inactivity);

  debug_printk(2, "rule_inactivity=%d [num_sw_filtering_rules=%d]\n",
    rule_inactivity, pfr->num_sw_filtering_rules);

  /* Free filtering rules inactive for more than rule_inactivity seconds */
  if(pfr->num_sw_filtering_rules > 0) {
    list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
      int rc = 0;
      sw_filtering_rule_element *entry;
      entry = list_entry(ptr, sw_filtering_rule_element, list);

      if((!entry->rule.locked && entry->rule.internals.jiffies_last_match < expire_jiffies) || rc > 0) {
        /* Expired rule: free it */

	debug_printk(2, "Purging rule "
		  "[%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d][purged=%d][tot_rules=%d]\n",
		  ((entry->rule.core_fields.shost.v4 >> 24) & 0xff),
		  ((entry->rule.core_fields.shost.v4 >> 16) & 0xff),
		  ((entry->rule.core_fields.shost.v4 >> 8)  & 0xff),
		  ((entry->rule.core_fields.shost.v4 >> 0)  & 0xff),
		    entry->rule.core_fields.sport_low,
		  ((entry->rule.core_fields.dhost.v4 >> 24) & 0xff),
		  ((entry->rule.core_fields.dhost.v4 >> 16) & 0xff),
		  ((entry->rule.core_fields.dhost.v4 >> 8)  & 0xff),
		  ((entry->rule.core_fields.dhost.v4 >> 0) & 0xff),
		    entry->rule.core_fields.dport_low,
		  num_purged_rules,
		  pfr->num_sw_filtering_rules);

        list_del(ptr);
        free_filtering_rule(entry, 0);
        kfree(entry);

        pfr->num_sw_filtering_rules--;
        num_purged_rules++;
      }
    }
  }

  debug_printk(2, "Purged %d rules [tot_rules=%d]\n",
	   num_purged_rules, pfr->num_sw_filtering_rules);
}

/* ************************************* */

static int ring_proc_stats_read(struct seq_file *m, void *data_not_used)
{
  if(m->private != NULL) {
    struct pf_ring_socket *pfr = (struct pf_ring_socket*)m->private;

    seq_printf(m, "%s\n", pfr->statsString);
  }

  return(0);
}

/* ********************************** */

static int ring_proc_stats_open(struct inode *inode, struct file *file)
{
  return single_open(file, ring_proc_stats_read, PDE_DATA(inode));
}

#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
static const struct file_operations ring_proc_stats_fops = {
  .owner = THIS_MODULE,
  .open = ring_proc_stats_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};
#else
static const struct proc_ops ring_proc_stats_fops = {
  .proc_open = ring_proc_stats_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};
#endif

/* ************************************* */

int setSocketStats(struct pf_ring_socket *pfr)
{
  pf_ring_net *netns;
  int rc = 0;

  netns = netns_lookup(sock_net(pfr->sk));

  if(netns != NULL) {
    /* 1 - Check if the /proc entry exists otherwise create it */

    if(netns->proc_stats_dir != NULL) {
      if(pfr->ring_pid != current->tgid) {
	/* 
	   Probably the app forked as the PID has changed.
	   We need to update the filename as well the PID
	*/

	/* Remove old /proc names */
	ring_proc_remove(pfr);

	/* Update the PID */
	pfr->ring_pid = current->tgid;

	/* Recreate the /proc proc entry */
	ring_proc_add(pfr);

	/* Force a new entry for stats to be created */
	pfr->sock_proc_stats_name[0] = '\0';
      }
      
      if(pfr->sock_proc_stats_name[0] == '\0') {
	struct proc_dir_entry *entry;

	snprintf(pfr->sock_proc_stats_name, sizeof(pfr->sock_proc_stats_name),
		 "%d-%s.%d", pfr->ring_pid,
		 pfr->ring_dev->dev->name, pfr->ring_id);

	if((entry = proc_create_data(pfr->sock_proc_stats_name,
				     0 /* ro */,
				     netns->proc_stats_dir,
				     &ring_proc_stats_fops, pfr)) == NULL) {
	  pfr->sock_proc_stats_name[0] = '\0';
	  rc = -1;
	}
      }
    }
  }

  return rc;
}

/* ************************************* */

#if(defined(RHEL_RELEASE_CODE) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)))

/* sk_attach_filter/sk_detach_filter for some reason is undefined on CentOS
 * code from core/sock.c kernel 2.x */

static void sk_filter_rcu_release(struct rcu_head *rcu)
{
  struct sk_filter *fp = container_of(rcu, struct sk_filter, rcu);

  sk_filter_release(fp);
}

static void sk_filter_delayed_uncharge(struct sock *sk, struct sk_filter *fp)
{
  unsigned int size = sk_filter_len(fp);

  atomic_sub(size, &sk->sk_omem_alloc);
  call_rcu_bh(&fp->rcu, sk_filter_rcu_release);
}

int sk_attach_filter(struct sock_fprog *fprog, struct sock *sk)
{
  struct sk_filter *fp, *old_fp;
  unsigned int fsize = sizeof(struct sock_filter) * fprog->len;
  int err;

  /* Make sure new filter is there and in the right amounts. */
  if(fprog->filter == NULL)
    return -EINVAL;

  fp = sock_kmalloc(sk, fsize+sizeof(*fp), GFP_KERNEL);
  if(!fp)
    return -ENOMEM;
  if(copy_from_user(fp->insns, fprog->filter, fsize)) {
    sock_kfree_s(sk, fp, fsize+sizeof(*fp));
    return -EFAULT;
  }

  atomic_set(&fp->refcnt, 1);
  fp->len = fprog->len;

  err = sk_chk_filter(fp->insns, fp->len);
  if(err) {
    sk_filter_uncharge(sk, fp);
    return err;
  }

  rcu_read_lock_bh();
  old_fp = rcu_dereference(sk->sk_filter);
  rcu_assign_pointer(sk->sk_filter, fp);
  rcu_read_unlock_bh();

  if(old_fp)
    sk_filter_delayed_uncharge(sk, old_fp);
  return 0;
}

int sk_detach_filter(struct sock *sk)
{
  int ret = -ENOENT;
  struct sk_filter *filter;

  rcu_read_lock_bh();
  filter = rcu_dereference(sk->sk_filter);
  if(filter) {
    rcu_assign_pointer(sk->sk_filter, NULL);
    sk_filter_delayed_uncharge(sk, filter);
    ret = 0;
  }
  rcu_read_unlock_bh();
  return ret;
}

#endif

/* ************************************* */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0))
#define copy_from_sockptr copy_from_user
#define copy_to_sockptr copy_to_user
#else
#define copy_to_sockptr(dst,src,size) copy_to_sockptr_offset(dst, 0, src, size)
#endif

/* Code taken/inspired from core/sock.c */
static int ring_setsockopt(struct socket *sock,
			   int level, int optname,
#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0))
			   char __user * optval,
#else
			   sockptr_t optval,
#endif
			   unsigned
			   int optlen)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  int found = 1, ret = 0 /* OK */, i;
  u_int32_t ring_id;
  struct add_to_cluster cluster;
  u_int16_t rule_id, rule_inactivity, vlan_id;
  packet_direction direction;
  socket_mode sockmode;
  hw_filtering_rule hw_rule;
  struct list_head *ptr, *tmp_ptr;
  zc_dev_mapping mapping;

  if(pfr == NULL)
    return(-EINVAL);

  debug_printk(2, "--> ring_setsockopt(optname=%u)\n", optname);

  switch(optname) {
  case SO_ATTACH_FILTER:
    ret = -EINVAL;

    debug_printk(2, "BPF filter\n");

    if(optlen == sizeof(struct sock_fprog)) {
      struct sock_fprog fprog;

      ret = -EFAULT;

      if(copy_from_sockptr(&fprog, optval, sizeof(fprog)))
        break;

      if(fprog.len <= 1) { /* empty filter */
        ret = 0;
        break;
      }

      debug_printk(2, "BPF filter (len = %u)\n", fprog.len);


#if(defined(UTS_UBUNTU_RELEASE_ABI) && ( \
       (UBUNTU_VERSION_CODE == KERNEL_VERSION(4,2,0) && UTS_UBUNTU_RELEASE_ABI >= 28) || \
       (UBUNTU_VERSION_CODE == KERNEL_VERSION(4,4,0) && UTS_UBUNTU_RELEASE_ABI >= 22))) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,8) && LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,51) /* Debian 3.16.0-5 */ && LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))
      ret = __sk_attach_filter(&fprog, pfr->sk, sock_owned_by_user(pfr->sk));
#else
      ret = sk_attach_filter(&fprog, pfr->sk);
#endif

      if(ret == 0)
        pfr->bpfFilter = 1;
    }
    break;

  case SO_DETACH_FILTER:
    debug_printk(2, "Removing BPF filter\n");
#if(defined(UTS_UBUNTU_RELEASE_ABI) && ( \
       (UBUNTU_VERSION_CODE == KERNEL_VERSION(4,2,0) && UTS_UBUNTU_RELEASE_ABI >= 28) || \
       (UBUNTU_VERSION_CODE == KERNEL_VERSION(4,4,0) && UTS_UBUNTU_RELEASE_ABI >= 22))) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,8) && LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,51) /* Debian 3.16.0-5 */ && LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))
    ret = __sk_detach_filter(pfr->sk, sock_owned_by_user(pfr->sk));
#else
    ret = sk_detach_filter(pfr->sk);
#endif
    pfr->bpfFilter = 0;
    break;

  case SO_ADD_TO_CLUSTER:
    if(optlen != sizeof(cluster))
      return(-EINVAL);

    if(copy_from_sockptr(&cluster, optval, sizeof(cluster)))
      return(-EFAULT);

    write_lock_bh(&pfr->ring_rules_lock);
    ret = add_sock_to_cluster(sock->sk, pfr, &cluster);
    write_unlock_bh(&pfr->ring_rules_lock);
    break;

  case SO_REMOVE_FROM_CLUSTER:
    write_lock_bh(&pfr->ring_rules_lock);
    ret = remove_from_cluster(sock->sk, pfr);
    write_unlock_bh(&pfr->ring_rules_lock);
    break;

  case SO_SET_CHANNEL_ID:
  {
    u_int64_t channel_id_mask;
    u_int16_t num_channels = 0;
    pf_ring_net *netns = netns_lookup(sock_net(sock->sk));
    int32_t dev_index = ifindex_to_pf_index(netns,
                                            pfr->last_bind_dev->dev->ifindex);

    if(optlen != sizeof(channel_id_mask))
      return(-EINVAL);

    if(copy_from_sockptr(&channel_id_mask, optval, sizeof(channel_id_mask)))
      return(-EFAULT);

    num_channels = 0;

    if (dev_index < 0) {
      printk("[PF_RING] SO_SET_CHANNEL_ID failure, dev index not found\n");
      return(-EFAULT);
    }

    /*
      We need to set the quick_mode_rings[] for all channels set
      in channel_id_mask
    */

    if(quick_mode) {
      for (i = 0; i < pfr->num_rx_channels; i++) {
        u_int64_t channel_id_bit = ((u_int64_t) ((u_int64_t) 1) << i);

        if(channel_id_mask & channel_id_bit) {
	  if(netns->quick_mode_rings[dev_index][i] != NULL)
	    return(-EINVAL); /* Socket already bound on this device */
        }
      }
    }

    /* Everything seems to work thus let's set the values */

    for (i = 0; i < pfr->num_rx_channels; i++) {
      u_int64_t channel_id_bit = ((u_int64_t) ((u_int64_t) 1) << i);

      if(channel_id_mask & channel_id_bit) {
        debug_printk(2, "Setting channel %d\n", i);

	if(quick_mode) {
	  netns->quick_mode_rings[dev_index][i] = pfr;
	}

	num_channels++;
      }
    }

    /* Note: in case of multiple interfaces, channels are the same for all */
    pfr->num_channels_per_ring = num_channels;
    pfr->channel_id_mask = channel_id_mask;

    debug_printk(2, "[channel_id_mask=%016llX]\n", pfr->channel_id_mask);

    ret = 0;
    break;
  }

  case SO_SET_APPL_NAME:
    if(optlen >= sizeof(pfr->appl_name))
      return(-EINVAL);

    if(copy_from_sockptr(&pfr->appl_name, optval, optlen))
      return(-EFAULT);

    pfr->appl_name[optlen] = '\0';

    /* safety check - buffer termination */
    pfr->appl_name[sizeof(pfr->appl_name) - 1] = '\0';

    ret = 0;
    break;

  case SO_SET_PACKET_DIRECTION:
    if(optlen != sizeof(direction))
      return(-EINVAL);

    if(copy_from_sockptr(&direction, optval, sizeof(direction)))
      return(-EFAULT);

    pfr->direction = direction;
    debug_printk(2, "SO_SET_PACKET_DIRECTION [pfr->direction=%s][direction=%s]\n",
	     direction2string(pfr->direction), direction2string(direction));

    ret = 0;
    break;

  case SO_SET_SOCKET_MODE:
    if(optlen != sizeof(sockmode))
      return(-EINVAL);

    if(copy_from_sockptr(&sockmode, optval, sizeof(sockmode)))
      return(-EFAULT);

    pfr->mode = sockmode;
    debug_printk(2, "SO_SET_LINK_DIRECTION [pfr->mode=%s][mode=%s]\n",
	     sockmode2string(pfr->mode), sockmode2string(sockmode));

    ret = 0;
    break;

  case SO_PURGE_IDLE_HASH_RULES:
    if(optlen != sizeof(rule_inactivity))
      return(-EINVAL);

    if(copy_from_sockptr(&rule_inactivity, optval, sizeof(rule_inactivity)))
      return(-EFAULT);
    else {
      write_lock_bh(&pfr->ring_rules_lock);
      purge_idle_hash_rules(pfr, rule_inactivity);
      write_unlock_bh(&pfr->ring_rules_lock);
      ret = 0;
    }
    break;

  case SO_PURGE_IDLE_RULES:
    if(optlen != sizeof(rule_inactivity))
      return(-EINVAL);

    if(copy_from_sockptr(&rule_inactivity, optval, sizeof(rule_inactivity)))
      return(-EFAULT);
    else {
      write_lock_bh(&pfr->ring_rules_lock);
      purge_idle_rules(pfr, rule_inactivity);
      write_unlock_bh(&pfr->ring_rules_lock);
      ret = 0;
    }
    break;

  case SO_TOGGLE_FILTER_POLICY:
    if(optlen != sizeof(u_int8_t))
      return(-EINVAL);
    else {
      u_int8_t new_policy;

      if(copy_from_sockptr(&new_policy, optval, optlen))
	return(-EFAULT);

      write_lock_bh(&pfr->ring_rules_lock);
      pfr->sw_filtering_rules_default_accept_policy = new_policy;
      write_unlock_bh(&pfr->ring_rules_lock);
      /*
	debug_printk(2, "SO_TOGGLE_FILTER_POLICY: default policy is %s\n",
	pfr->sw_filtering_rules_default_accept_policy ? "accept" : "drop");
      */
    }
    break;

  case SO_ADD_FILTERING_RULE:
    debug_printk(2, "+++ SO_ADD_FILTERING_RULE(len=%d)(len=%u)\n",
	     optlen, (unsigned int)sizeof(ip_addr));

    if(pfr->ring_dev == &none_device_element)
      return(-EFAULT);

    if(optlen == sizeof(filtering_rule)) {
      int ret;
      sw_filtering_rule_element *rule;

      debug_printk(2, "Allocating memory [filtering_rule]\n");

      rule = (sw_filtering_rule_element *)
	kcalloc(1, sizeof(sw_filtering_rule_element), GFP_KERNEL);

      if(rule == NULL)
	return(-EFAULT);

      if(copy_from_sockptr(&rule->rule, optval, optlen))
	return(-EFAULT);

      INIT_LIST_HEAD(&rule->list);

      write_lock_bh(&pfr->ring_rules_lock);
      ret = add_sw_filtering_rule_element(pfr, rule);
      write_unlock_bh(&pfr->ring_rules_lock);

      if(ret != 0) { /* even if rc == -EEXIST */
        kfree(rule);
        return(ret);
      }
    } else if(optlen == sizeof(hash_filtering_rule)) {
      /* This is a hash rule */
      int ret;
      sw_filtering_hash_bucket *rule;

      rule = (sw_filtering_hash_bucket *)
        kcalloc(1, sizeof(sw_filtering_hash_bucket), GFP_KERNEL);

      if(rule == NULL)
	return(-EFAULT);

      if(copy_from_sockptr(&rule->rule, optval, optlen))
	return(-EFAULT);

      write_lock_bh(&pfr->ring_rules_lock);
      ret = handle_sw_filtering_hash_bucket(pfr, rule, 1 /* add */);
      write_unlock_bh(&pfr->ring_rules_lock);

      if(ret != 0) { /* even if rc == -EEXIST */
        kfree(rule);
        return(ret);
      }
    } else {
      printk("[PF_RING] Bad rule length (%d): discarded\n", optlen);
      return(-EFAULT);
    }
    break;

  case SO_REMOVE_FILTERING_RULE:
    if(pfr->ring_dev == &none_device_element) return(-EFAULT);

    if(optlen == sizeof(u_int16_t /* rule_id */ )) {
      /* This is a list rule */
      int rc;

      if(copy_from_sockptr(&rule_id, optval, optlen))
	return(-EFAULT);

      write_lock_bh(&pfr->ring_rules_lock);
      rc = remove_sw_filtering_rule_element(pfr, rule_id);
      write_unlock_bh(&pfr->ring_rules_lock);

      if(rc == 0) {
	debug_printk(2, "SO_REMOVE_FILTERING_RULE: rule %d does not exist\n", rule_id);
	return(-EFAULT);	/* Rule not found */
      }
    } else if(optlen == sizeof(hash_filtering_rule)) {
      /* This is a hash rule */
      sw_filtering_hash_bucket rule;
      int rc;

      if(copy_from_sockptr(&rule.rule, optval, optlen))
	return(-EFAULT);

      write_lock_bh(&pfr->ring_rules_lock);
      rc = handle_sw_filtering_hash_bucket(pfr, &rule, 0 /* delete */ );
      write_unlock_bh(&pfr->ring_rules_lock);

      if(rc != 0)
	return(rc);
    } else
      return(-EFAULT);
    break;

  case SO_SET_SAMPLING_RATE:
    if(optlen != sizeof(pfr->sample_rate))
      return(-EINVAL);

    if(copy_from_sockptr(&pfr->sample_rate, optval, sizeof(pfr->sample_rate)))
      return(-EFAULT);
    break;

  case SO_SET_FILTERING_SAMPLING_RATE:
	  if(optlen != sizeof(pfr->filtering_sample_rate))
		return(-EINVAL);

	  if(copy_from_sockptr(&pfr->filtering_sample_rate, optval, sizeof(pfr->filtering_sample_rate)))
		return(-EFAULT);

      pfr->filtering_sampling_size = pfr->filtering_sample_rate;

	  if((FILTERING_SAMPLING_RATIO)>0) { /* In case FILTERING_SAMPLING_RATIO will mistakenly not be positive */
	  	pfr->filtering_sampling_size *= (u_int32_t)(FILTERING_SAMPLING_RATIO);
	  }

	  debug_printk(2, "--> SO_SET_FILTERING_SAMPLING_RATE: filtering_sample_rate=%u, filtering_sampling_size=%u\n",
	  	pfr->filtering_sample_rate, pfr->filtering_sampling_size);
	  break;

  case SO_ACTIVATE_RING:
    debug_printk(2, "* SO_ACTIVATE_RING *\n");

    if(pfr->zc_device_entry != NULL && !pfr->ring_active /* already active, no check */) {
      int i;

      spin_lock_bh(&pfr->zc_device_entry->lock);

      for(i=0; i<MAX_NUM_ZC_BOUND_SOCKETS; i++) {
	if((pfr->zc_device_entry->bound_sockets[i] != NULL)
	   && pfr->zc_device_entry->bound_sockets[i]->ring_active) {
	  if(pfr->zc_device_entry->bound_sockets[i]->mode == pfr->mode
	     || pfr->zc_device_entry->bound_sockets[i]->mode == send_and_recv_mode
	     || pfr->mode == send_and_recv_mode) {
            spin_unlock_bh(&pfr->zc_device_entry->lock);
	    printk("[PF_RING] Unable to activate two or more ZC sockets on the same interface %s/link direction\n",
		   pfr->ring_dev->dev->name);
	    return(-EFAULT); /* No way: we can't have two sockets that are doing the same thing with ZC */
	  }
	} /* if */
      } /* for */

      pfr->ring_active = 1;

      spin_unlock_bh(&pfr->zc_device_entry->lock);

    } else {
      pfr->ring_active = 1;
    }

    break;

  case SO_DISCARD_INJECTED_PKTS:
    debug_printk(2, "* SO_DISCARD_INJECTED_PKTS *\n");

    pfr->discard_injected_pkts = 1;
    break;

  case SO_DEACTIVATE_RING:
    debug_printk(2, "* SO_DEACTIVATE_RING *\n");
    pfr->ring_active = 0;
    break;

  case SO_SET_POLL_WATERMARK:
    if(optlen != sizeof(u_int16_t))
      return(-EINVAL);
    else {
      u_int16_t threshold;

      if(pfr->slots_info != NULL)
	threshold = pfr->slots_info->min_num_slots/2;
      else
	threshold = min_num_slots;

      if(copy_from_sockptr(&pfr->poll_num_pkts_watermark, optval, optlen))
	return(-EFAULT);

      if(pfr->poll_num_pkts_watermark > threshold)
	pfr->poll_num_pkts_watermark = threshold;

      if(pfr->poll_num_pkts_watermark == 0)
	pfr->poll_num_pkts_watermark = 1;

      debug_printk(2, "--> SO_SET_POLL_WATERMARK=%d\n", pfr->poll_num_pkts_watermark);
    }
    break;

  case SO_SET_POLL_WATERMARK_TIMEOUT:
	  if(optlen != sizeof(u_int16_t))
		return(-EINVAL);
	  else {
		if(copy_from_sockptr(&pfr->poll_watermark_timeout, optval, optlen))
           return(-EFAULT);
		debug_printk(2, "--> SO_SET_POLL_WATERMARK_TIMEOUT=%u\n", pfr->poll_watermark_timeout);
	  }
  	break;

  case SO_RING_BUCKET_LEN:
    if(optlen != sizeof(u_int32_t))
      return(-EINVAL);

    if(copy_from_sockptr(&pfr->bucket_len, optval, optlen))
      return(-EFAULT);

    debug_printk(2, "--> SO_RING_BUCKET_LEN=%d\n", pfr->bucket_len);
    break;

  case SO_SELECT_ZC_DEVICE:
    if(optlen != sizeof(zc_dev_mapping))
      return(-EINVAL);

    if(copy_from_sockptr(&mapping, optval, optlen))
      return(-EFAULT);

    debug_printk(2, "SO_SELECT_ZC_DEVICE %s\n", mapping.device_name);

    if(mapping.operation == add_device_mapping)
      ret = pfring_select_zc_dev(pfr, &mapping);
    else
      ret = pfring_release_zc_dev(pfr);

    if(copy_to_sockptr(optval, &mapping, optlen)) /* returning device_model*/
      return(-EFAULT);

    break;

  case SO_SET_MASTER_RING:
    /* Avoid using master sockets with bound rings */
    if(pfr->ring_dev == &none_device_element)
      return(-EFAULT);

    if(optlen != sizeof(ring_id))
      return(-EINVAL);

    if(copy_from_sockptr(&ring_id, optval, sizeof(ring_id)))
      return(-EFAULT);

    write_lock_bh(&pfr->ring_rules_lock);
    ret = set_master_ring(sock->sk, pfr, ring_id);
    write_unlock_bh(&pfr->ring_rules_lock);
    break;

  case SO_ADD_HW_FILTERING_RULE:
    if(optlen != sizeof(hw_filtering_rule))
      return(-EINVAL);

    if(copy_from_sockptr(&hw_rule, optval, sizeof(hw_rule)))
      return(-EFAULT);

    /* Check if a rule with the same id exists */
    list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
      hw_filtering_rule_element *rule = list_entry(ptr, hw_filtering_rule_element, list);

      if(rule->rule.rule_id == hw_rule.rule_id) {
	/* There's already a rule with the same id: failure */
	printk("[PF_RING] Warning: duplicated hw rule id %d\n", hw_rule.rule_id);
	return(-EINVAL);
      }
    }

    ret = handle_hw_filtering_rule(pfr, &hw_rule, add_hw_rule);

    if(ret != -1) {
      hw_filtering_rule_element *rule;

      debug_printk(2, "New hw filtering rule [id=%d]\n", hw_rule.rule_id);

      /* Add the hw rule to the socket hw rule list */
      rule = kmalloc(sizeof(hw_filtering_rule_element), GFP_ATOMIC);
      if(rule != NULL) {
	INIT_LIST_HEAD(&rule->list);
	memcpy(&rule->rule, &hw_rule, sizeof(hw_rule));
	list_add(&rule->list, &pfr->hw_filtering_rules); /* Add as first entry */
	pfr->num_hw_filtering_rules++;
      } else
	printk("[PF_RING] Out of memory\n");

      /* Increase the number of device hw rules */
      pfr->ring_dev->hw_filters.num_filters++;
    }
    break;

  case SO_DEL_HW_FILTERING_RULE:
    if(optlen != sizeof(u_int16_t))
      return(-EINVAL);

    if(copy_from_sockptr(&rule_id, optval, sizeof(u_int16_t)))
      return(-EFAULT);

    /* Check if the rule we want to remove exists */
    found = 0;
    list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
      hw_filtering_rule_element *rule = list_entry(ptr, hw_filtering_rule_element, list);

      if(rule->rule.rule_id == rule_id) {
	/* There's already a rule with the same id: good */
	memcpy(&hw_rule, &rule->rule, sizeof(hw_filtering_rule));
	list_del(ptr);
        kfree(rule);
	found = 1;
	break;
      }
    }

    if(!found) return(-EINVAL);

    ret = handle_hw_filtering_rule(pfr, &hw_rule, remove_hw_rule);

    if(ret != -1) {

      pfr->num_hw_filtering_rules--;

      if(pfr->ring_dev->hw_filters.num_filters > 0)
        pfr->ring_dev->hw_filters.num_filters--;
    }
    break;

  case SO_SET_VIRTUAL_FILTERING_DEVICE:
    {
      virtual_filtering_device_info elem;

      if(optlen != sizeof(elem))
	return(-EINVAL);

      if(copy_from_sockptr(&elem, optval, sizeof(elem)))
	return(-EFAULT);

      if((pfr->v_filtering_dev = add_virtual_filtering_device(pfr, &elem)) == NULL)
	return(-EFAULT);
    }
    break;

  case SO_REHASH_RSS_PACKET:
    debug_printk(2, "* SO_REHASH_RSS_PACKET *\n");

    pfr->rehash_rss = default_rehash_rss_func;
    break;

  case SO_CREATE_CLUSTER_REFEREE:
    {
      struct create_cluster_referee_info ccri;

      if(optlen < sizeof(ccri))
        return(-EINVAL);

      if(copy_from_sockptr(&ccri, optval, sizeof(ccri)))
	return(-EFAULT);

      if(create_cluster_referee(pfr, ccri.cluster_id, &ccri.recovered) < 0)
        return(-EINVAL);

      /* copying back the structure (actually we need ccri.recovered only) */
      if(copy_to_sockptr(optval, &ccri, sizeof(ccri))) {
        remove_cluster_referee(pfr);
        return(-EFAULT);
      }

      debug_printk(2, "SO_CREATE_CLUSTER_REFEREE done [%u]\n", ccri.cluster_id);
    }
    break;

  case SO_PUBLISH_CLUSTER_OBJECT:
    {
      struct public_cluster_object_info pcoi;

      if(copy_from_sockptr(&pcoi, optval, sizeof(pcoi)))
	return(-EFAULT);

      if(publish_cluster_object(pfr, pcoi.cluster_id, pcoi.object_type, pcoi.object_id) < 0)
        return(-EINVAL);

      debug_printk(2, "SO_PUBLISH_CLUSTER_OBJECT done [%u.%u@%u]\n", pcoi.object_type, pcoi.object_id, pcoi.cluster_id);
    }
    break;

  case SO_LOCK_CLUSTER_OBJECT:
    {
      struct lock_cluster_object_info lcoi;

      if(copy_from_sockptr(&lcoi, optval, sizeof(lcoi)))
	return(-EFAULT);

      if(lock_cluster_object(pfr, lcoi.cluster_id, lcoi.object_type, lcoi.object_id, lcoi.lock_mask) < 0)
        return(-EINVAL);

      debug_printk(2, "SO_LOCK_CLUSTER_OBJECT done [%u.%u@%u]\n", lcoi.object_type, lcoi.object_id, lcoi.cluster_id);
    }
    break;

  case SO_UNLOCK_CLUSTER_OBJECT:
    {
      struct lock_cluster_object_info lcoi;

      if(copy_from_sockptr(&lcoi, optval, sizeof(lcoi)))
	return(-EFAULT);

      if(unlock_cluster_object(pfr, lcoi.cluster_id, lcoi.object_type, lcoi.object_id, lcoi.lock_mask) < 0)
        return(-EINVAL);

      debug_printk(2, "SO_UNLOCK_CLUSTER_OBJECT done [%u.%u@%u]\n", lcoi.object_type, lcoi.object_id, lcoi.cluster_id);
    }
    break;

  case SO_SET_CUSTOM_BOUND_DEV_NAME:
    /* Names should not be too long */
    if(optlen > (sizeof(pfr->custom_bound_device_name)-1))
      optlen = sizeof(pfr->custom_bound_device_name)-1;

    if(copy_from_sockptr(&pfr->custom_bound_device_name, optval, optlen)) {
      pfr->custom_bound_device_name[0] = '\0';
      return(-EFAULT);
    } else
      pfr->custom_bound_device_name[optlen] = '\0';
    break;

  case SO_SHUTDOWN_RING:
    pfr->ring_active = 0, pfr->ring_shutdown = 1;
    wake_up_interruptible(&pfr->ring_slots_waitqueue);
    break;

  case SO_USE_SHORT_PKT_HEADER:
    pfr->header_len = short_pkt_header;
    break;

  case SO_ENABLE_RX_PACKET_BOUNCE:
    pfr->tx.enable_tx_with_bounce = 1;
    break;

  case SO_SET_APPL_STATS:
    /* Names should not be too long */
    if(optlen > (sizeof(pfr->statsString)-1))
      optlen = sizeof(pfr->statsString)-1;

    if(copy_from_sockptr(&pfr->statsString, optval, optlen)) {
      pfr->statsString[0] = '\0';
      return(-EFAULT);
    }

    pfr->statsString[optlen] = '\0';

    ret = setSocketStats(pfr);
    break;

  case SO_SET_STACK_INJECTION_MODE:
    pfr->stack_injection_mode = 1;
    break;

  case SO_SET_IFF_PROMISC:
    {
      u_int32_t enable_promisc;

      if(optlen != sizeof(u_int32_t))
        return (-EINVAL);

      if(copy_from_sockptr(&enable_promisc, optval, optlen))
        return (-EFAULT);

      if(!pfr->ring_dev || pfr->ring_dev == &none_device_element || pfr->ring_dev == &any_device_element) {
        debug_printk(1, "SO_SET_IFF_PROMISC: not a real device\n");
      } else {
        if(enable_promisc)
          set_socket_promisc(pfr);
        else
          unset_socket_promisc(pfr);
      }

    }
    break;

  case SO_SET_VLAN_ID:
    /*
      Weak check as the direction is set via pfring_set_direction()
      and not when a ring is open
     */
    if(pfr->direction == tx_only_direction)
      return (-EINVAL);

    if(optlen != sizeof(vlan_id))
      return(-EINVAL);

    if(copy_from_sockptr(&vlan_id, optval, sizeof(vlan_id)))
      return(-EFAULT);

    pfr->vlan_id = vlan_id;
    break;

  default:
    found = 0;
    break;
  }

  if(found)
    return(ret);

  return(sock_setsockopt(sock, level, optname, optval, optlen));
}

/* ************************************* */

static int ring_getsockopt(struct socket *sock,
			   int level, int optname,
			   char __user *optval,
			   int __user *optlen)
{
  int len;
  struct pf_ring_socket *pfr = ring_sk(sock->sk);

  if(pfr == NULL)
    return(-EINVAL);

  if(get_user(len, optlen))
    return(-EFAULT);

  if(len < 0)
    return(-EINVAL);

  debug_printk(2, "--> getsockopt(%d)\n", optname);

  switch (optname) {
  case SO_GET_RING_VERSION:
    {
      u_int32_t version = RING_VERSION_NUM;

      if(len < sizeof(u_int32_t))
	return(-EINVAL);
      else if(copy_to_user(optval, &version, sizeof(version)))
	return(-EFAULT);
    }
    break;

  case PACKET_STATISTICS:
    {
      struct tpacket_stats st;

      if(len < sizeof(struct tpacket_stats))
	return(-EINVAL);

      st.tp_packets = pfr->slots_info->tot_insert;
      st.tp_drops = pfr->slots_info->tot_lost;

      if(copy_to_user(optval, &st, sizeof(struct tpacket_stats)))
	return(-EFAULT);

      break;
    }

  case SO_GET_HASH_FILTERING_RULE_STATS:
    {
      int rc = -EFAULT;

      if(len >= sizeof(hash_filtering_rule)) {
	hash_filtering_rule rule;
	u_int32_t hash_idx;

	if(pfr->sw_filtering_hash == NULL) {
	  printk("[PF_RING] SO_GET_HASH_FILTERING_RULE_STATS: no hash failure\n");
	  return(-EFAULT);
	}

	if(copy_from_user(&rule, optval, sizeof(rule))) {
	  printk("[PF_RING] SO_GET_HASH_FILTERING_RULE_STATS: copy_from_user() failure\n");
	  return(-EFAULT);
	}

	debug_printk_rule_info(2, &rule, "SO_GET_HASH_FILTERING_RULE_STATS rule_id=%u\n", rule.rule_id);

	hash_idx = hash_pkt(rule.vlan_id, zeromac, zeromac,
	                    rule.ip_version, rule.proto,
	                    rule.host_peer_a, rule.host_peer_b,
	                    rule.port_peer_a, rule.port_peer_b)
	  % perfect_rules_hash_size;

	if(pfr->sw_filtering_hash[hash_idx] != NULL) {
	  sw_filtering_hash_bucket *bucket;

	  read_lock_bh(&pfr->ring_rules_lock);
	  bucket = pfr->sw_filtering_hash[hash_idx];

	  debug_printk(2, "SO_GET_HASH_FILTERING_RULE_STATS: bucket=%p\n",
		   bucket);

	  while(bucket != NULL) {
	    if(hash_bucket_match_rule(bucket, &rule)) {

              hash_filtering_rule_stats hfrs;
              hfrs.match = bucket->match;
              hfrs.filtered = bucket->filtered;
              hfrs.match_forward = bucket->match_forward;
              hfrs.inactivity = (u_int32_t) (jiffies_to_msecs(jiffies - bucket->rule.internals.jiffies_last_match) / 1000);
              rc = sizeof(hash_filtering_rule_stats);
              if(copy_to_user(optval, &hfrs, rc)) {
              	printk("[PF_RING] SO_GET_HASH_FILTERING_RULE_STATS: copy_to_user() failure\n");
              	rc = -EFAULT;
              }

	      break;
	    }

	    bucket = bucket->next;
	  } /* while */

	  read_unlock_bh(&pfr->ring_rules_lock);

	} else {
	  debug_printk(2, "SO_GET_HASH_FILTERING_RULE_STATS: entry not found [hash_idx=%u]\n",
		   hash_idx);
	}
      }

      return(rc);
      break;
    }

  case SO_GET_FILTERING_RULE_STATS:
    {
      int rc = -EFAULT;
      struct list_head *ptr, *tmp_ptr;
      u_int16_t rule_id;

      if(len < sizeof(rule_id))
	return(-EINVAL);

      if(copy_from_user(&rule_id, optval, sizeof(rule_id)))
	return(-EFAULT);

      debug_printk(2, "SO_GET_FILTERING_RULE_STATS: rule_id=%d\n",
	       rule_id);

      read_lock_bh(&pfr->ring_rules_lock);
      list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
	sw_filtering_rule_element *rule;

	rule = list_entry(ptr, sw_filtering_rule_element, list);

	if(rule->rule.rule_id == rule_id) {

          //TODO copy to user filtering stats
	  rc = -EFAULT;

	  break;
	}
      }
      read_unlock_bh(&pfr->ring_rules_lock);

      return(rc);
      break;
    }

  case SO_GET_ZC_DEVICE_INFO:
    {
      if(!pfr->zc_mapping.device_name[0] || len < sizeof(zc_memory_info))
	return(-EFAULT);

      if(pfring_get_zc_dev(pfr) < 0)
        return(-EFAULT);

      if(copy_to_user(optval, &pfr->zc_dev->mem_info, sizeof(zc_memory_info)))
	return(-EFAULT);

      break;
    }

  case SO_GET_EXTRA_DMA_MEMORY:
    {
      struct dma_memory_info *extra_dma_memory;
      u_int64_t num_slots, slot_len, chunk_len;

      if(pfr->zc_dev == NULL || pfr->zc_dev->hwdev == NULL)
        return(-EINVAL);

      if(len < (3 * sizeof(u_int64_t)))
        return(-EINVAL);

      if(copy_from_user(&num_slots, optval, sizeof(num_slots)))
        return(-EFAULT);

      if(copy_from_user(&slot_len, optval+sizeof(num_slots), sizeof(slot_len)))
        return(-EFAULT);

      if(copy_from_user(&chunk_len, optval+sizeof(num_slots)+sizeof(slot_len), sizeof(chunk_len)))
        return(-EFAULT);

      if(len < (sizeof(u_int64_t) * num_slots))
        return(-EINVAL);

      mutex_lock(&pfr->ring_config_lock);

      if(pfr->extra_dma_memory) { /* already called */
        mutex_unlock(&pfr->ring_config_lock);
        return(-EINVAL);
      }

      if((extra_dma_memory = allocate_extra_dma_memory(pfr->zc_dev->hwdev,
                                    num_slots, slot_len, chunk_len)) == NULL) {
        mutex_unlock(&pfr->ring_config_lock);
        return(-EFAULT);
      }

      if(copy_to_user(optval, extra_dma_memory->dma_addr, (sizeof(u_int64_t) * num_slots))) {
        free_extra_dma_memory(extra_dma_memory);
        mutex_unlock(&pfr->ring_config_lock);
        return(-EFAULT);
      }

      pfr->extra_dma_memory = extra_dma_memory;

      mutex_unlock(&pfr->ring_config_lock);

      break;
    }

  case SO_GET_NUM_RX_CHANNELS:
    {
      u_int8_t num_rx_channels;

      if(pfr->ring_dev == &none_device_element) /* Device not yet bound */
	num_rx_channels = UNKNOWN_NUM_RX_CHANNELS;
      else if(pfr->ring_dev->is_zc_device)
	num_rx_channels = pfr->ring_dev->num_zc_dev_rx_queues;
      else
        num_rx_channels = max_val(pfr->num_rx_channels, get_num_rx_queues(pfr->ring_dev->dev));

      debug_printk(2, "--> SO_GET_NUM_RX_CHANNELS[%s]=%d [zc=%d/rx_channels=%d][%p]\n",
	       pfr->ring_dev->dev->name, num_rx_channels,
	       pfr->ring_dev->is_zc_device,
	       pfr->ring_dev->num_zc_dev_rx_queues,
	       pfr->ring_dev);

      if(copy_to_user(optval, &num_rx_channels, sizeof(num_rx_channels)))
	return(-EFAULT);
    }
    break;

  case SO_GET_RING_ID:
    if(len < sizeof(pfr->ring_id))
      return(-EINVAL);

    debug_printk(2, "--> SO_GET_RING_ID=%d\n", pfr->ring_id);

    if(copy_to_user(optval, &pfr->ring_id, sizeof(pfr->ring_id)))
      return(-EFAULT);
    break;

  case SO_GET_BPF_EXTENSIONS:
    {
      int bpf_ext = SKF_AD_MAX; /* bpf_tell_extensions() on kernels >= 3.14 */

      if(len < sizeof(bpf_ext))
        return -EINVAL;

      if(copy_to_user(optval, &bpf_ext, sizeof(bpf_ext)))
        return -EFAULT;
    }
    break;

  case SO_GET_BOUND_DEVICE_ADDRESS:
    if(len < ETH_ALEN) return(-EINVAL);

    if(pfr->zc_dev != NULL) {
      if(copy_to_user(optval, pfr->zc_dev->device_address, 6))
	return(-EFAULT);
    } else if((pfr->ring_dev != NULL)
	      && (pfr->ring_dev->dev != NULL)) {
      char empty_mac[ETH_ALEN] = { 0 };
      char lowest_if_mac[ETH_ALEN] = { 0 };
      char magic_if_mac[ETH_ALEN];
      memset(magic_if_mac, RING_MAGIC_VALUE, sizeof(magic_if_mac));

      /* Read input buffer */
      if(copy_from_user(&lowest_if_mac, optval, ETH_ALEN))
	return(-EFAULT);

      if(!memcmp(lowest_if_mac, magic_if_mac, ETH_ALEN)) {
	struct list_head *ptr, *tmp_ptr;
	long lowest_id = -1;

	/* Return the MAC address of the lowest X of ethX */

	list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
	  pf_ring_device *entry = list_entry(ptr, pf_ring_device, device_list);
	  char *eptr;
	  long id = simple_strtol(&entry->dev->name[3], &eptr, 10);

	  if((lowest_id == -1) || (id < lowest_id)) {
	    lowest_id = id, memcpy(lowest_if_mac, entry->dev->perm_addr, ETH_ALEN);
	  }
	}

	if(copy_to_user(optval, lowest_if_mac, ETH_ALEN))
	  return(-EFAULT);
      } else {
        char *dev_addr = pfr->ring_dev->dev->dev_addr;

        if (dev_addr == NULL) /* e.g. 'any' device */
          dev_addr = empty_mac;

	if(copy_to_user(optval, dev_addr, ETH_ALEN))
	  return(-EFAULT);
      }
    } else
      return(-EFAULT);
    break;

  case SO_GET_BOUND_DEVICE_IFINDEX:
    if((len < sizeof(int))
       || (pfr->ring_dev == NULL))
      return(-EINVAL);

    if(copy_to_user(optval, &pfr->ring_dev->dev->ifindex, sizeof(int)))
      return(-EFAULT);
    break;

  case SO_GET_NUM_QUEUED_PKTS:
    {
      u_int32_t num_queued = num_queued_pkts(pfr);

      if(len < sizeof(num_queued))
	return(-EINVAL);

      if(copy_to_user(optval, &num_queued, sizeof(num_queued)))
	return(-EFAULT);
    }
    break;

  case SO_GET_PKT_HEADER_LEN:
    if(len < sizeof(pfr->slot_header_len))
      return(-EINVAL);

    if(copy_to_user(optval, &pfr->slot_header_len, sizeof(pfr->slot_header_len)))
      return(-EFAULT);
    break;

  case SO_GET_BUCKET_LEN:
    if(len < sizeof(pfr->bucket_len))
      return(-EINVAL);

    if(copy_to_user(optval, &pfr->bucket_len, sizeof(pfr->bucket_len)))
      return(-EFAULT);
    break;

  case SO_GET_LOOPBACK_TEST:
    /* Used for testing purposes only */
    {
      /* printk("SO_GET_LOOPBACK_TEST (len=%d)\n", len); */

      if(len > 0) {
	if(len > loobpack_test_buffer_len) return(-EFAULT);

	if(loobpack_test_buffer == NULL) {
	  loobpack_test_buffer = kmalloc(loobpack_test_buffer_len, GFP_ATOMIC);

	  if(loobpack_test_buffer == NULL)
	    return(-EFAULT); /* Not enough memory */
	}

	{
	  u_int i;

	  for(i=0; i<len; i++) loobpack_test_buffer[i] = i;
	}

	if(copy_to_user(optval, loobpack_test_buffer, len))
	  return(-EFAULT);
      }
    }
    break;

  case SO_GET_DEVICE_TYPE:
    if(len < sizeof(pfring_device_type))
      return(-EINVAL);

    if(pfr->ring_dev == NULL)
      return(-EFAULT);

    if(copy_to_user(optval, &pfr->ring_dev->device_type, sizeof(pfring_device_type)))
      return(-EFAULT);
    break;

  case SO_GET_DEVICE_IFINDEX:
    {
      char dev_name[32];
      pf_ring_device *dev_ptr;

      if(len < sizeof(int) || len > sizeof(dev_name))
        return(-EINVAL);

      if(copy_from_user(&dev_name, optval, len))
        return(-EFAULT);
      dev_name[sizeof(dev_name)-1] = 0;

      dev_ptr = pf_ring_device_name_lookup(sock_net(sock->sk), dev_name);

      if(dev_ptr != NULL) {
        if(copy_to_user(optval, &dev_ptr->dev->ifindex, sizeof(int)))
          return -EFAULT;
      } else {
        return -EINVAL;
      }
    }
    break;

  case SO_GET_APPL_STATS_FILE_NAME:
    {
      char path[255];
      u_int slen;

      snprintf(path, sizeof(path)-1,
	       "/proc/net/pf_ring/stats/%s", pfr->sock_proc_stats_name);
      slen = strlen(path);

      if(len < (slen+1))
	return(-EINVAL);

      if(copy_to_user(optval, path, slen))
	return(-EFAULT);
    }
    break;

  case SO_GET_LINK_STATUS:
    {
      int link_up;

      if(len < sizeof(int) || pfr->ring_dev == NULL)
        return(-EINVAL);

      link_up = netif_carrier_ok(pfr->ring_dev->dev);

      if(copy_to_user(optval, &link_up, sizeof(int)))
        return(-EFAULT);
    }
    break;

  default:
    return -ENOPROTOOPT;
  }

  if(put_user(len, optlen))
    return(-EFAULT);
  else
    return(0);
}

/* ************************************* */

void pf_ring_zc_dev_handler(zc_dev_operation operation,
			   mem_ring_info *rx_info,
			   mem_ring_info *tx_info,
			   void          *rx_descr_packet_memory,
			   void          *tx_descr_packet_memory,
			   void          *phys_card_memory,
			   u_int          phys_card_memory_len,
			   u_int channel_id,
			   struct net_device *dev,
			   struct device *hwdev,
			   zc_dev_model device_model,
			   u_char *device_address,
			   wait_queue_head_t *packet_waitqueue,
			   u_int8_t *interrupt_received,
			   void *rx_adapter_ptr, void *tx_adapter_ptr,
			   zc_dev_wait_packet wait_packet_function_ptr,
			   zc_dev_notify dev_notify_function_ptr)
{
  pf_ring_device *dev_ptr;

  printk("[PF_RING] %s ZC device %s@%u\n",
	 operation == add_device_mapping ? "Registering" : "Removing",
	 dev->name, channel_id);

  if(strlen(dev->name) == 0)
    printk("[PF_RING] %s:%d %s ZC device with empty name!\n", __FUNCTION__, __LINE__,
           operation == add_device_mapping ? "registering" : "removing");

  if(operation == add_device_mapping) {
    zc_dev_list *next;

    next = kmalloc(sizeof(zc_dev_list), GFP_ATOMIC);
    if(next != NULL) {
      memset(next, 0, sizeof(zc_dev_list));

      spin_lock_init(&next->lock);
      next->num_bound_sockets = 0;

      /* RX */
      if(rx_info != NULL)
        memcpy(&next->zc_dev.mem_info.rx, rx_info, sizeof(next->zc_dev.mem_info.rx));
      next->zc_dev.rx_descr_packet_memory = rx_descr_packet_memory;

      /* TX */
      if(tx_info != NULL)
        memcpy(&next->zc_dev.mem_info.tx, tx_info, sizeof(next->zc_dev.mem_info.tx));
      next->zc_dev.tx_descr_packet_memory = tx_descr_packet_memory;

      /* PHYS */
      next->zc_dev.phys_card_memory = phys_card_memory;
      next->zc_dev.mem_info.phys_card_memory_len = phys_card_memory_len;

      next->zc_dev.channel_id = channel_id;
      next->zc_dev.dev = dev;
      next->zc_dev.hwdev = hwdev;
      next->zc_dev.mem_info.device_model = device_model;
      memcpy(next->zc_dev.device_address, device_address, 6);
      next->zc_dev.packet_waitqueue = packet_waitqueue;
      next->zc_dev.interrupt_received = interrupt_received;
      next->zc_dev.rx_adapter_ptr = rx_adapter_ptr;
      next->zc_dev.tx_adapter_ptr = tx_adapter_ptr;
      next->zc_dev.wait_packet_function_ptr = wait_packet_function_ptr;
      next->zc_dev.usage_notification = dev_notify_function_ptr;
      list_add(&next->list, &zc_devices_list);
      zc_devices_list_size++;
      /* Increment usage count - avoid unloading it while ZC drivers are in use */
      try_module_get(THIS_MODULE);

      /* We now have to update the device list */
      dev_ptr = pf_ring_device_name_lookup(dev_net(dev), dev->name);

      if(dev_ptr != NULL) {
        dev_ptr->is_zc_device = 1;
        dev_ptr->zc_dev_model = device_model;
        dev_ptr->num_zc_dev_rx_queues = (rx_info != NULL) ? rx_info->num_queues : UNKNOWN_NUM_RX_CHANNELS;
#if(defined(RHEL_MAJOR) && (RHEL_MAJOR == 6) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32))) && defined(CONFIG_RPS)
        netif_set_real_num_rx_queues(dev_ptr->dev, dev_ptr->num_zc_dev_rx_queues); /* This is a workround for Centos 6 reporting a wrong number of queues */
#endif
        if(rx_info != NULL) dev_ptr->num_zc_rx_slots = rx_info->packet_memory_num_slots;
        if(tx_info != NULL) dev_ptr->num_zc_tx_slots = tx_info->packet_memory_num_slots;

        debug_printk(2, "updating ZC device %s queues=%d\n",
                     dev_ptr->device_name, dev_ptr->num_zc_dev_rx_queues);
      }
    } else {
      printk("[PF_RING] Could not kmalloc slot!!\n");
    }
  } else {
    zc_dev_list *entry;
    int i;

    entry = pf_ring_zc_dev_net_device_lookup(dev, channel_id);

    if (entry) {
      /* driver detach - checking if there is an application running */
      for (i = 0; i < MAX_NUM_ZC_BOUND_SOCKETS; i++) {
        if(entry->bound_sockets[i] != NULL) {
          printk("[PF_RING] Unloading ZC driver while the device is in use from userspace!!\n");
          break;
        }
      }

      list_del(&entry->list);
      kfree(entry);
      zc_devices_list_size--;
      /* Decrement usage count */
      module_put(THIS_MODULE);
    }
  }

  debug_printk(2, "%d registered ZC devices/queues\n", zc_devices_list_size);
}
EXPORT_SYMBOL(pf_ring_zc_dev_handler);

/* ************************************* */

static int ring_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  switch (cmd) {
#ifdef CONFIG_INET
  case SIOCGIFFLAGS:
  case SIOCSIFFLAGS:
  case SIOCGIFCONF:
  case SIOCGIFMETRIC:
  case SIOCSIFMETRIC:
  case SIOCGIFMEM:
  case SIOCSIFMEM:
  case SIOCGIFMTU:
  case SIOCSIFMTU:
  case SIOCSIFLINK:
  case SIOCGIFHWADDR:
  case SIOCSIFHWADDR:
  case SIOCSIFMAP:
  case SIOCGIFMAP:
  case SIOCSIFSLAVE:
  case SIOCGIFSLAVE:
  case SIOCGIFINDEX:
  case SIOCGIFNAME:
  case SIOCGIFCOUNT:
  case SIOCSIFHWBROADCAST:
    return(inet_dgram_ops.ioctl(sock, cmd, arg));
#endif

  default:
    return -ENOIOCTLCMD;
  }

  return 0;
}

/* ************************************* */

static struct proto_ops ring_ops = {
  .family = PF_RING,
  .owner = THIS_MODULE,

  /* Operations that make no sense on ring sockets. */
  .connect = sock_no_connect,
  .socketpair = sock_no_socketpair,
  .accept = sock_no_accept,
  .getname = sock_no_getname,
  .listen = sock_no_listen,
  .shutdown = sock_no_shutdown,
  .sendpage = sock_no_sendpage,

  /* Now the operations that really occur. */
  .release = ring_release,
  .bind = ring_bind,
  .mmap = ring_mmap,
  .poll = ring_poll,
  .setsockopt = ring_setsockopt,
  .getsockopt = ring_getsockopt,
  .ioctl = ring_ioctl,
  .recvmsg = ring_recvmsg,
  .sendmsg = ring_sendmsg,
};

/* ************************************ */

static struct net_proto_family ring_family_ops = {
  .family = PF_RING,
  .create = ring_create,
  .owner = THIS_MODULE,
};

static struct proto ring_proto = {
  .name = "PF_RING",
  .owner = THIS_MODULE,
  .obj_size = sizeof(struct ring_sock),
};

/* ************************************ */

void remove_device_from_proc(pf_ring_net *netns, pf_ring_device *dev_ptr) {
  if(dev_ptr->proc_entry == NULL)
    return;

  /*
   * What about using proc_remove(struct proc_dir_entry *e))
   * that is calling remove_proc_subtree(const char *name, struct proc_dir_entry *parent)
   */

#ifdef ENABLE_PROC_WRITE_RULE
  if(dev_ptr->device_type != standard_nic_family)
    remove_proc_entry(PROC_RULES, dev_ptr->proc_entry);
#endif

  if(dev_ptr->proc_info_entry != NULL) {
    debug_printk(1, "removing %s/%s from /proc [net=%pK] [entry=%pK]\n",
      dev_ptr->device_name, PROC_INFO, netns->net, dev_ptr->proc_info_entry);

    remove_proc_entry(PROC_INFO, dev_ptr->proc_entry);

    dev_ptr->proc_info_entry = NULL;
  }

  if(netns->proc_dev_dir != NULL) {
    debug_printk(1, "removing %s from /proc [net=%pK] [entry=%pK]\n",
      dev_ptr->device_name, netns->net, dev_ptr->proc_entry);
    /* Note: we are not using dev_ptr->dev->name below in case it is changed and has not been updated */
    remove_proc_entry(dev_ptr->device_name, netns->proc_dev_dir);
  }

  dev_ptr->proc_entry = NULL;
}

/* ************************************ */

void remove_device_from_ring_list(struct net_device *dev)
{
  struct list_head *ptr, *tmp_ptr;
  u_int32_t last_list_idx;
  struct sock *sk;
  pf_ring_net *netns;

  netns = netns_lookup(dev_net(dev));

  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    pf_ring_device *dev_ptr = list_entry(ptr, pf_ring_device, device_list);
    if(device_net_eq(dev_ptr, netns->net) &&
        dev_ptr->dev->ifindex == dev->ifindex) {

      if(netns != NULL) {
        debug_printk(1, "removing dev=%s ifindex=%d (1)\n", dev->name, dev->ifindex);
        remove_device_from_proc(netns, dev_ptr);
      }

      /* We now have to "un-bind" existing sockets */
      sk = (struct sock*)lockless_list_get_first(&ring_table, &last_list_idx);

      while(sk != NULL) {
        struct pf_ring_socket *pfr;

        pfr = ring_sk(sk);

        if(pfr->ring_dev == dev_ptr)
          pfr->ring_dev = &none_device_element; /* Unbinding socket */

        sk = (struct sock*)lockless_list_get_next(&ring_table, &last_list_idx);
      }

      list_del(ptr);
      kfree(dev_ptr);

      break;
    }
  }
}

/* ********************************** */

static int ring_proc_dev_open(struct inode *inode, struct file *file)
{
  return single_open(file, ring_proc_dev_get_info, PDE_DATA(inode));
}

#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
static const struct file_operations ring_proc_dev_fops = {
  .owner = THIS_MODULE,
  .open = ring_proc_dev_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};
#else
static const struct proc_ops ring_proc_dev_fops = {
  .proc_open = ring_proc_dev_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};
#endif

/* ************************************ */

void add_device_to_proc(pf_ring_net *netns, pf_ring_device *dev_ptr) {

  dev_ptr->proc_entry = proc_mkdir(dev_ptr->device_name, netns->proc_dev_dir);

  if(dev_ptr->proc_entry == NULL) {
    printk("[PF_RING] failure creating %s in /proc [net=%pK]\n",
      dev_ptr->device_name, netns->net);
    return;
  }

  debug_printk(1, "created %s in /proc [net=%pK] [entry=%pK]\n",
    dev_ptr->device_name, netns->net, dev_ptr->proc_entry);

  dev_ptr->proc_info_entry = proc_create_data(PROC_INFO, 0 /* read-only */,
    dev_ptr->proc_entry,
    &ring_proc_dev_fops /* read */,
    dev_ptr);

  if(dev_ptr->proc_info_entry == NULL) {
    printk("[PF_RING] failure creating %s/%s in /proc [net=%pK]\n",
      dev_ptr->device_name, PROC_INFO, netns->net);
    return;
  }

  debug_printk(1, "created %s/%s in /proc [net=%pK] [entry=%pK]\n",
    dev_ptr->device_name, PROC_INFO, netns->net, dev_ptr->proc_info_entry);
}

/* ************************************ */

int add_device_to_ring_list(struct net_device *dev, int32_t dev_index)
{
  pf_ring_device *dev_ptr;
  pf_ring_net *netns;

  if((dev_ptr = kmalloc(sizeof(pf_ring_device), GFP_KERNEL)) == NULL)
    return(-ENOMEM);

  netns = netns_lookup(dev_net(dev));

  memset(dev_ptr, 0, sizeof(pf_ring_device));
  atomic_set(&dev_ptr->promisc_users, 0);
  INIT_LIST_HEAD(&dev_ptr->device_list);
  dev_ptr->dev = dev;
  strcpy(dev_ptr->device_name, dev->name);
  dev_ptr->device_type = standard_nic_family; /* Default */
  dev_ptr->dev_index = dev_index;

  if(netns != NULL) {
    debug_printk(1, "adding dev=%s ifindex=%d (1)\n", dev->name, dev->ifindex);
    add_device_to_proc(netns, dev_ptr);
  }

  /* Dirty trick to fix at some point used to discover Intel 82599 interfaces: FIXME */
  if((dev_ptr->dev->ethtool_ops != NULL) && (dev_ptr->dev->ethtool_ops->set_rxnfc != NULL)) {
    struct ethtool_rxnfc cmd;
    int rc;

    cmd.cmd = ETHTOOL_PFRING_SRXFTCHECK /* check */;

    rc = dev_ptr->dev->ethtool_ops->set_rxnfc(dev_ptr->dev, &cmd);

    if(rc == RING_MAGIC_VALUE) {
      /* This device supports hardware filtering */
      dev_ptr->device_type = intel_82599_family;

      /* Setup handlers */
      dev_ptr->hw_filters.filter_handlers.five_tuple_handler = i82599_generic_handler;
      dev_ptr->hw_filters.filter_handlers.perfect_filter_handler = i82599_generic_handler;

#ifdef ENABLE_PROC_WRITE_RULE
      entry = create_proc_read_entry(PROC_RULES, 0666 /* rw */,
				     dev_ptr->proc_entry,
				     ring_proc_dev_rule_read, dev_ptr);
      if(entry) {
	entry->write_proc = ring_proc_dev_rule_write;
	debug_printk(2, "Device %s (Intel 82599) DOES support hardware packet filtering\n", dev->name);
      } else {
	debug_printk(2, "Error while creating /proc entry 'rules' for device %s\n", dev->name);
      }
#endif
    } else {
      debug_printk(2, "Device %s does NOT support hardware packet filtering (1)\n", dev->name);
    }
  } else {
    debug_printk(2, "Device %s does NOT support hardware packet filtering (2)\n", dev->name);
  }

  list_add(&dev_ptr->device_list, &ring_aware_device_list);

  return(0);
}

/* ********************************** */

#ifdef ENABLE_PROC_WRITE_RULE
static int ring_proc_dev_ruleopen(struct inode *inode, struct file *file)
{
  return single_open(file, ring_proc_dev_rule_read, PDE_DATA(inode));
}

#if(LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
static const struct file_operations ring_proc_dev_rulefops = {
  .owner = THIS_MODULE,
  .open = ring_proc_dev_ruleopen,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};
#else
static const struct proc_ops ring_proc_dev_rulefops = {
  .proc_open = ring_proc_dev_ruleopen,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};
#endif
#endif

/* ************************************ */

static int ring_notifier(struct notifier_block *this, unsigned long msg, void *data)
{
  struct net_device *dev = netdev_notifier_info_to_dev(data);
  pf_ring_device *dev_ptr;
  struct list_head *ptr, *tmp_ptr;
  int if_name_clash = 0;
  int32_t dev_index;

  if(debug_on(2)) {
    char _what[32], *what = _what;

    switch(msg) {
      case NETDEV_UP:               what = "NETDEV_UP"; break;
      case NETDEV_DOWN:             what = "NETDEV_DOWN"; break;
      case NETDEV_REBOOT:           what = "NETDEV_REBOOT"; break;
      case NETDEV_CHANGE:           what = "NETDEV_CHANGE"; break;
      case NETDEV_REGISTER:         what = "NETDEV_REGISTER"; break;
      case NETDEV_UNREGISTER:       what = "NETDEV_UNREGISTER"; break;
      case NETDEV_CHANGEMTU:        what = "NETDEV_CHANGEMTU"; break;
      case NETDEV_CHANGEADDR:       what = "NETDEV_CHANGEADDR"; break;
      case NETDEV_GOING_DOWN:       what = "NETDEV_GOING_DOWN"; break;
      case NETDEV_CHANGENAME:       what = "NETDEV_CHANGENAME"; break;
      case NETDEV_FEAT_CHANGE:      what = "NETDEV_FEAT_CHANGE"; break;
      case NETDEV_BONDING_FAILOVER: what = "NETDEV_BONDING_FAILOVER"; break;
      case NETDEV_PRE_UP:           what = "NETDEV_PRE_UP"; break;
#ifdef NETDEV_PRE_TYPE_CHANGE
      case NETDEV_PRE_TYPE_CHANGE:  what = "NETDEV_PRE_TYPE_CHANGE"; break;
      case NETDEV_POST_TYPE_CHANGE: what = "NETDEV_POST_TYPE_CHANGE"; break;
#endif
      case NETDEV_POST_INIT:        what = "NETDEV_POST_INIT"; break;
#ifdef NETDEV_UNREGISTER_FINAL
      case NETDEV_UNREGISTER_FINAL: what = "NETDEV_UNREGISTER_FINAL"; break;
#endif
#ifdef NETDEV_UNREGISTER_BATCH
      case NETDEV_UNREGISTER_BATCH: what = "NETDEV_UNREGISTER_BATCH"; break;
#endif
      case NETDEV_RELEASE:          what = "NETDEV_RELEASE"; break;
      case NETDEV_NOTIFY_PEERS:     what = "NETDEV_NOTIFY_PEERS"; break;
      case NETDEV_JOIN:             what = "NETDEV_JOIN"; break;
#ifdef NETDEV_CHANGEUPPER
      case NETDEV_CHANGEUPPER:      what = "NETDEV_CHANGEUPPER"; break;
      case NETDEV_RESEND_IGMP:      what = "NETDEV_RESEND_IGMP"; break;
#ifdef NETDEV_PRECHANGEMTU
      case NETDEV_PRECHANGEMTU:     what = "NETDEV_PRECHANGEMTU"; break;
#endif
#ifdef NETDEV_CHANGEINFODATA
      case NETDEV_CHANGEINFODATA:   what = "NETDEV_CHANGEINFODATA"; break;
#endif
#ifdef NETDEV_BONDING_INFO
      case NETDEV_BONDING_INFO:     what = "NETDEV_BONDING_INFO"; break;
#endif
#endif
#ifdef NETDEV_PRECHANGEUPPER
      case NETDEV_PRECHANGEUPPER:   what = "NETDEV_PRECHANGEUPPER"; break;
#endif
      default:
	snprintf(_what, sizeof(_what), "Unknown msg %lu", msg);
	break;
    }

    if(dev != NULL) {
      char addr[MAX_ADDR_LEN*2+1];
      int i;
      for (i = 0; i < dev->addr_len; i++)
        sprintf(&addr[i*2], "%02X", dev->perm_addr[i]);
      addr[dev->addr_len*2] = '\0';
      printk("[PF_RING] %s: %s Type=%d IfIndex=%d Ptr=%p Namespace=%p Addr=%s\n", dev->name, what, dev->type, dev->ifindex, dev, dev_net(dev), addr);
    } else {
      printk("[PF_RING] %s\n", what);
    }
  }

  if(dev == NULL)
    return NOTIFY_DONE;

  /* Skip non ethernet interfaces */
  if(
      (dev->type != ARPHRD_ETHER) /* Ethernet */
      && (dev->type != ARPHRD_LOOPBACK) /* Loopback */
      /* Wifi */
      && (dev->type != ARPHRD_IEEE80211)
      && (dev->type != ARPHRD_IEEE80211_PRISM)
      && (dev->type != ARPHRD_IEEE80211_RADIOTAP)
      && strncmp(dev->name, "bond", 4)) {
    debug_printk(2, "%s: skipping non ethernet device\n", dev->name);
    return NOTIFY_DONE;
  }

  switch (msg) {
    case NETDEV_POST_INIT:
    case NETDEV_PRE_UP:
    case NETDEV_UP:
    case NETDEV_DOWN:
      break;
    case NETDEV_REGISTER:
      debug_printk(2, "%s: [REGISTER][ifindex: %u]\n", dev->name, dev->ifindex);

      dev_index = map_ifindex(netns_lookup(dev_net(dev)), dev->ifindex);
      if(dev_index < 0) {
        printk("[PF_RING] %s %s: unable to map interface index %d\n", __FUNCTION__,
               dev->name, dev->ifindex);
        return NOTIFY_DONE;
      }

      /* safety check */
      list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
        dev_ptr = list_entry(ptr, pf_ring_device, device_list);
        if(dev_ptr->dev != dev && strcmp(dev_ptr->dev->name, dev->name) == 0 &&
           device_net_eq(dev_ptr, dev_net(dev))) {
          printk("[PF_RING] WARNING: multiple devices with the same name (name: %s ifindex: %u already-registered-as: %u)\n",
            dev->name, dev->ifindex, dev_ptr->dev->ifindex);
          if_name_clash = 1;
        }
      }

      if(!if_name_clash) {
	if(add_device_to_ring_list(dev, dev_index) != 0) {
	  printk("[PF_RING] Error in add_device_to_ring_list(%s)\n", dev->name);
	}
      }
      break;

    case NETDEV_UNREGISTER:
      debug_printk(2, "%s: [UNREGISTER][ifindex: %u]\n", dev->name, dev->ifindex);

      remove_device_from_ring_list(dev);
      /* We don't have to worry updating rules that might have used this
	 device (just removed) as reflection device. This because whenever
	 we set a rule with reflection, we do dev_put() so such device is
	 busy until we remove the rule
      */

      unmap_ifindex(netns_lookup(dev_net(dev)), dev->ifindex);
      break;

    case NETDEV_CHANGE:     /* Interface state change */
      /* Example testing link loss: if(test_bit(__LINK_STATE_NOCARRIER, &dev->state)) */
    case NETDEV_CHANGEADDR: /* Interface address changed (e.g. during device probing) */
      break;

    case NETDEV_CHANGENAME: /* Rename interface ethX -> ethY */
      debug_printk(2, "Device changed name to %s [ifindex: %u]\n", dev->name, dev->ifindex);

      /* safety check (name clash) */
      list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
        dev_ptr = list_entry(ptr, pf_ring_device, device_list);
        if(dev_ptr->dev != dev && strcmp(dev_ptr->dev->name, dev->name) == 0 &&
           device_net_eq(dev_ptr, dev_net(dev))) {
          printk("[PF_RING] WARNING: different devices (ifindex: %u found-ifindex: %u) with the same name detected during name change to %s\n",
                 dev->ifindex, dev_ptr->dev->ifindex, dev->name);
          if_name_clash = 1;
        }
      }

      dev_ptr = pf_ring_device_ifindex_lookup(dev_net(dev), dev->ifindex);

      if(dev_ptr != NULL) {
        pf_ring_net *netns;

        debug_printk(2, "Updating device name %s to %s\n", dev_ptr->device_name, dev->name);

        netns = netns_lookup(dev_net(dev));

	/* Remove old entry */
        if(netns != NULL) {
          printk("[PF_RING] removing dev=%s ifindex=%d (it changed name to %s)\n",
            dev_ptr->device_name, dev->ifindex, dev->name);
          remove_device_from_proc(netns, dev_ptr);
        }

        if(!if_name_clash) { /* do not add in case of name clash */
	  strcpy(dev_ptr->device_name, dev_ptr->dev->name);

	  /* Add new entry */
          if(netns != NULL) {
            debug_printk(1, "adding dev=%s ifindex=%d (2)\n", dev->name, dev->ifindex);
            add_device_to_proc(netns, dev_ptr);
          }

#ifdef ENABLE_PROC_WRITE_RULE
	  if(dev_ptr->device_type != standard_nic_family) {
	    struct proc_dir_entry *entry;

	    entry = proc_create_data(PROC_RULES, 0666 /* rw */,
				     dev_ptr->proc_entry,
				     &ring_proc_dev_rulefops,
				     dev_ptr);
	    if(entry)
	      entry->write_proc = ring_proc_dev_rule_write;
	  }
#endif
        }
      }

      break;

    default:
      break;
  }

  return NOTIFY_DONE;
}

/* ************************************ */

static struct notifier_block ring_netdev_notifier = {
  .notifier_call = ring_notifier,
};

/* ************************************ */

static int __net_init ring_net_init(struct net *net)
{
  debug_printk(1, "init network namespace [net=%pK]\n", net);
  netns_add(net);
  return 0;
}

/* ************************************ */

static void __net_exit ring_net_exit(struct net *net)
{
  debug_printk(1, "exit network namespace [net=%pK]\n", net);
  netns_remove(net);
}

/* ************************************ */

static struct pernet_operations ring_net_ops = {
  .init = ring_net_init,
  .exit = ring_net_exit,
  .id = &pf_ring_net_id,
  .size = sizeof(pf_ring_net),
};

/* ************************************ */

static void __exit ring_exit(void)
{
  struct list_head *ptr, *tmp_ptr;
  pf_ring_net *netns;

  pfring_enabled = 0;

  unregister_device_handler();

  list_del(&any_device_element.device_list);
  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    pf_ring_device *dev_ptr = list_entry(ptr, pf_ring_device, device_list);

    netns = netns_lookup(dev_net(dev_ptr->dev));
    remove_device_from_proc(netns, dev_ptr);

    list_del(ptr);
    kfree(dev_ptr);
  }

  if(enable_frag_coherence && num_cluster_fragments > 0) {
    int i;

    for(i=0; i<NUM_FRAGMENTS_HASH_SLOTS; i++) {
      list_for_each_safe(ptr, tmp_ptr, &cluster_fragment_hash[i]) {
        struct hash_fragment_node *frag = list_entry(ptr, struct hash_fragment_node, frag_list);
	list_del(ptr);
	kfree(frag);
      }
    }
  }

  term_lockless_list(&ring_table, 1 /* free memory */);
  term_lockless_list(&ring_cluster_list, 1 /* free memory */);
  term_lockless_list(&delayed_memory_table, 1 /* free memory */);

  list_for_each_safe(ptr, tmp_ptr, &zc_devices_list) {
    zc_dev_list *elem;

    elem = list_entry(ptr, zc_dev_list, list);

    list_del(ptr);
    kfree(elem);
  }

  unregister_netdevice_notifier(&ring_netdev_notifier);
  unregister_pernet_subsys(&ring_net_ops);
  sock_unregister(PF_RING);
  proto_unregister(&ring_proto);

  if(loobpack_test_buffer != NULL)
    kfree(loobpack_test_buffer);

  printk("[PF_RING] Module unloaded\n");
}

/* ************************************ */

static int __init ring_init(void)
{
  static struct net_device any_dev, none_dev;
  int i;
  int rc;

  printk("[PF_RING] Welcome to PF_RING %s ($Revision: %s$)\n"
	 "(C) 2004-21 ntop.org\n",
	 RING_VERSION, GIT_REV);

  printk("LINUX_VERSION_CODE %08X\n", LINUX_VERSION_CODE);

  /* Sanity check */
  if(transparent_mode != 0)
    printk("[PF_RING] Warning: transparent_mode is deprecated!\n");

  printk("[PF_RING] Min # ring slots %d\n", min_num_slots);
  printk("[PF_RING] Slot version     %d\n",
	 RING_FLOWSLOT_VERSION);
  printk("[PF_RING] Capture TX       %s\n",
	 enable_tx_capture ? "Yes [RX+TX]" : "No [RX only]");
  printk("[PF_RING] IP Defragment    %s\n",
	 enable_ip_defrag ? "Yes" : "No");

  if((rc = proto_register(&ring_proto, 0)) != 0)
    return(rc);

  init_lockless_list(&ring_table);
  init_lockless_list(&ring_cluster_list);
  init_lockless_list(&delayed_memory_table);

  INIT_LIST_HEAD(&virtual_filtering_devices_list);
  INIT_LIST_HEAD(&ring_aware_device_list);
  INIT_LIST_HEAD(&zc_devices_list);
  INIT_LIST_HEAD(&cluster_referee_list);

  for(i = 0; i < NUM_FRAGMENTS_HASH_SLOTS; i++)
    INIT_LIST_HEAD(&cluster_fragment_hash[i]);

  memset(&any_dev, 0, sizeof(any_dev));
  strcpy(any_dev.name, "any");
  any_dev.ifindex = MAX_NUM_IFINDEX-1;
  any_dev.type = ARPHRD_ETHER;
  memset(&any_device_element, 0, sizeof(any_device_element));
  any_device_element.dev = &any_dev;
  any_device_element.device_type = standard_nic_family;
  any_device_element.dev_index = MAX_NUM_DEV_IDX-1;
  strcpy(any_device_element.device_name, "any");

  INIT_LIST_HEAD(&any_device_element.device_list);
  list_add(&any_device_element.device_list, &ring_aware_device_list);

  memset(&none_dev, 0, sizeof(none_dev));
  strcpy(none_dev.name, "none");
  none_dev.ifindex = MAX_NUM_IFINDEX-2;
  none_dev.type = ARPHRD_ETHER;
  memset(&none_device_element, 0, sizeof(none_device_element));
  none_device_element.dev = &none_dev;
  none_device_element.device_type = standard_nic_family;
  none_device_element.dev_index = MAX_NUM_DEV_IDX-2;
  strcpy(none_device_element.device_name, "none");

  sock_register(&ring_family_ops);
  register_pernet_subsys(&ring_net_ops);
  register_netdevice_notifier(&ring_netdev_notifier);

  register_device_handler();

  printk("[PF_RING] pf_ring initialized correctly\n");

  pfring_enabled = 1;
  return 0;
}

module_init(ring_init);
module_exit(ring_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ntop.org");
MODULE_DESCRIPTION("Packet capture acceleration and analysis");
MODULE_VERSION(RING_VERSION);

MODULE_ALIAS_NETPROTO(PF_RING);
