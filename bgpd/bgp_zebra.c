/* zebra client
   Copyright (C) 1997, 98, 99 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <zebra.h>

#include "command.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "log.h"
#include "sockunion.h"
#include "zclient.h"
#include "routemap.h"
#include "thread.h"
#include "linklist.h"
#include "bfd.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_debug.h"

/* All information about zebra. */
struct zclient *zclient = NULL;
struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
static int
bgp_router_id_update (int command, struct zclient *zclient, zebra_size_t length)
{
  struct prefix router_id;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  zebra_router_id_update_read(zclient->ibuf,&router_id);

  if (BGP_DEBUG(zebra, ZEBRA))
    {
      char buf[128];
      prefix2str(&router_id, buf, sizeof(buf));
      zlog_debug("Zebra rcvd: router id update %s", buf);
    }

  router_id_zebra = router_id.u.prefix4;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      if (!bgp->router_id_static.s_addr)
        bgp_router_id_set (bgp, &router_id.u.prefix4);
    }

  return 0;
}

/* Inteface addition message from zebra. */
static int
bgp_interface_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

  if (BGP_DEBUG(zebra, ZEBRA) && ifp)
    zlog_debug("Zebra rcvd: interface add %s", ifp->name);

  return 0;
}

static int
bgp_interface_delete (int command, struct zclient *zclient,
		      zebra_size_t length)
{
  struct stream *s;
  struct interface *ifp;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s);
  ifp->ifindex = IFINDEX_INTERNAL;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: interface delete %s", ifp->name);

  return 0;
}

static int
bgp_interface_up (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct interface *ifp;
  struct connected *c;
  struct listnode *node, *nnode;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s);

  if (! ifp)
    return 0;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: interface %s up", ifp->name);

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, c))
    bgp_connected_add (c);

  return 0;
}

static int
bgp_interface_down (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct interface *ifp;
  struct connected *c;
  struct listnode *node, *nnode;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s);
  if (! ifp)
    return 0;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: interface %s down", ifp->name);

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, c))
    bgp_connected_delete (c);

  /* Fast external-failover (Currently IPv4 only) */
  {
    struct listnode *mnode;
    struct bgp *bgp;
    struct peer *peer;
    struct interface *peer_if;

    for (ALL_LIST_ELEMENTS_RO (bm->bgp, mnode, bgp))
      {
	if (CHECK_FLAG (bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER))
	  continue;

	for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
	  {
	    if (peer->ttl != 1)
	      continue;

	    if (peer->su.sa.sa_family == AF_INET)
	      peer_if = if_lookup_by_ipv4 (&peer->su.sin.sin_addr);
	    else
	      continue;

	    if (ifp == peer_if)
	      BGP_EVENT_ADD (peer, BGP_Stop);
	  }
      }
  }

  return 0;
}

/* Update information about preferred mode i.e. single hop or multihop
   if necessary */
int
bgp_bfd_mhop(struct peer *peer)
{
  /* if there is a mismatch between BFD mode 
     send update to zebra/bfd to correct it*/
  if( ( CHECK_FLAG(peer->flags, PEER_FLAG_MULTIHOP)            &&
       !CHECK_FLAG(peer->bfd_flags,BFD_CNEIGH_FLAGS_MULTIHOP)) || 
      (!CHECK_FLAG(peer->flags, PEER_FLAG_MULTIHOP)            &&
        CHECK_FLAG(peer->bfd_flags, BFD_CNEIGH_FLAGS_MULTIHOP)) )
  {
    if (BGP_DEBUG(bfd, BFD)) 
      zlog_debug("BFD multihop mode change detected");

      /* If previous candidate has been registered, we have to delete
         previous reservation first, in order to register new */
      if(peer->bfd_status 
	 && peer->bfd_status != PEER_BFD_STATUS_NEW)
      {
	bgp_bfd_neigh_del(peer);
	peer->bfd_flags = 0;
	peer->bfd_ifindex = 0;
      }
      bgp_bfd_neigh_add(peer);
  }

  return 0;
}

/* Called when BGP's FSM reaches Established state*/
void 
bgp_bfd_estab(struct peer *peer)
{
  /* Check if we have local(src) address ready */
  if (peer->bfd_su_local) 
  {
    /* We BGP is using different addrees than before 
       remove and add neighbor(session) to reflect
       address change */
    if(!sockunion_same(peer->bfd_su_local, peer->su_local))
    {
      bgp_bfd_neigh_del(peer);
      //peer->bfd_flags = 0;
      //peer->bfd_ifindex = 0;
      bgp_bfd_neigh_add(peer);
    }
  } 
  /* We do not have local addrees - this is the first run */
  else
    bgp_bfd_neigh_add(peer);
}

/* Add BFD neighbor to zebra/bfd to start the session */
int
bgp_bfd_neigh_add(struct peer *peer)
{
  peer->bfd_flags = 0;
  peer->bfd_ifindex = 0;
  if(CHECK_FLAG(peer->flags,PEER_FLAG_MULTIHOP))
    SET_FLAG(peer->bfd_flags, BFD_CNEIGH_FLAGS_MULTIHOP);

  if(peer->status == Established)
  {
    struct interface *ifp;
    peer->bfd_su_local = sockunion_dup(peer->su_local);
    ifp = if_lookup_by_sockunion_exact(peer->bfd_su_local);
    peer->bfd_ifindex = ifp->ifindex;

    if (BGP_DEBUG(zebra, ZEBRA)) 
      zlog_debug("Zebra send: bfd cneigh add "
		 "<raddr=%s, laddr=%s, ifindex=%d, flags=%d>",
		 sockunion_su2str(&peer->su), sockunion_su2str(peer->bfd_su_local),
		 peer->bfd_ifindex, peer->bfd_flags);

    if(sockunion_family(&peer->su) == AF_INET)
      zapi_ipv4_bfd_cneigh_add(zclient,
	  (struct prefix_ipv4*)sockunion2hostprefix(&peer->su),
	  (struct prefix_ipv4*)sockunion2hostprefix(peer->bfd_su_local),
	  peer->bfd_ifindex,
	  peer->bfd_flags);
#ifdef HAVE_IPV6
    else 
      zapi_ipv6_bfd_cneigh_add(zclient,
	  (struct prefix_ipv6*)sockunion2hostprefix(&peer->su),
	  (struct prefix_ipv6*)sockunion2hostprefix(peer->bfd_su_local),
	  peer->bfd_ifindex,
	  peer->bfd_flags);
#endif /* HAVE_IPV6 */
    peer->bfd_status = PEER_BFD_STATUS_ADDED;
  }
  else
    peer->bfd_status = PEER_BFD_STATUS_NEW;
  return 0;
}

int
bgp_bfd_neigh_del(struct peer *peer)
{
  if(peer->bfd_status != PEER_BFD_STATUS_NEW 
     && peer->bfd_status !=  PEER_BFD_STATUS_DELETED)
  {
    
    if (BGP_DEBUG(zebra, ZEBRA)) 
      zlog_debug("Zebra send: bfd cneigh del "
		 "<raddr=%s, laddr=%s, ifindex=%d, flags=%d>",
		 sockunion_su2str(&peer->su), sockunion_su2str(peer->bfd_su_local),
		 peer->bfd_ifindex, peer->bfd_flags);


    if(sockunion_family(&peer->su) == AF_INET)
      zapi_ipv4_bfd_cneigh_del(zclient,
	  (struct prefix_ipv4*)sockunion2hostprefix(&peer->su),
	  (struct prefix_ipv4*)sockunion2hostprefix(peer->bfd_su_local),
	  peer->bfd_ifindex,
	  peer->bfd_flags);
#ifdef HAVE_IPV6
    else 
      zapi_ipv6_bfd_cneigh_del(zclient,
	  (struct prefix_ipv6*)sockunion2hostprefix(&peer->su),
	  (struct prefix_ipv6*)sockunion2hostprefix(peer->bfd_su_local),
	  peer->bfd_ifindex,
	  peer->bfd_flags);
#endif /* HAVE_IPV6 */
    sockunion_free(peer->bfd_su_local);
    peer->bfd_status = PEER_BFD_STATUS_DELETED;
  }
  return 0;
}

static int
bgp_bfd_neigh_up(struct bfd_cneigh *cneighp)
{
  struct bgp *bgp;
  struct peer *peer;
  struct listnode *node;
  union sockunion *su;

  if(!cneighp)
    return -1;

  if (BGP_DEBUG(zebra, ZEBRA))
  { 
    char rpbuf[BUFSIZ];
    char lpbuf[BUFSIZ];
    prefix2str(&cneighp->raddr,rpbuf,sizeof(rpbuf));
    prefix2str(&cneighp->laddr,lpbuf,sizeof(lpbuf));
    zlog_debug("Zebra rcvd: bfd neigh up "
	       "<raddr=%s, laddr=%s, ifindex=%d, flags=%d>",
	       rpbuf, lpbuf, cneighp->ifindex, cneighp->flags);
  }
  
  su = hostprefix2sockunion (&cneighp->raddr);

  for (ALL_LIST_ELEMENTS_RO (bm->bgp, node, bgp))
  {
    peer = peer_lookup (bgp, su);
    if (!peer)
      continue;

    /* Check if peer uses BFD - if not return */
    if(!CHECK_FLAG (peer->flags, PEER_FLAG_BFD))
      return 0;

    /* Ignore UP message when we are in UP state. We also don't want
       to receive anything when we are just about to be deleted */
    if(peer->bfd_status ==  PEER_BFD_STATUS_UP 
       || peer->bfd_status == PEER_BFD_STATUS_DELETED) 
      return 0;

    if(peer->bfd_status == PEER_BFD_STATUS_DOWN)
    {
      /* start BGP */
      if(peer->status == Idle)
	 BGP_EVENT_ADD (peer, BGP_Start);
    }
    /* Change peer status to UP */
    peer->bfd_status = PEER_BFD_STATUS_UP;
  }
  return 0;
}

static int
bgp_bfd_neigh_down(struct bfd_cneigh *cneighp)
{
  struct bgp *bgp;
  struct peer *peer;
  struct listnode *node;
  union sockunion *su;

  if(!cneighp)
    return -1;

  if (BGP_DEBUG(zebra, ZEBRA) && cneighp)
  { 
    char rpbuf[BUFSIZ];
    char lpbuf[BUFSIZ];
    prefix2str(&cneighp->raddr,rpbuf,sizeof(rpbuf));
    prefix2str(&cneighp->laddr,lpbuf,sizeof(lpbuf));
    zlog_debug("Zebra rcvd: bfd neigh down "
	       "<raddr=%s, laddr=%s, ifindex=%d, flags=%d>",
	       rpbuf, lpbuf, cneighp->ifindex, cneighp->flags);
  }
  
  su = hostprefix2sockunion (&cneighp->raddr);

  for(ALL_LIST_ELEMENTS_RO (bm->bgp, node, bgp))
  {
    peer = peer_lookup (bgp, su);
    if (!peer)
      continue;
    
    /* Check if peer uses BFD - if not return */
    if(!CHECK_FLAG (peer->flags, PEER_FLAG_BFD))
      return 0;

    /* Ignore DOWN message when we are in DOWN state. We also don't want
       to receive anything when we are just about to be deleted */
    if(peer->bfd_status ==  PEER_BFD_STATUS_DOWN 
       || peer->bfd_status == PEER_BFD_STATUS_DELETED) 
      return 0;

    /* If we were in UP state, stop BGP */
    if(peer->bfd_status == PEER_BFD_STATUS_UP)
      BGP_EVENT_ADD (peer, BGP_Stop);
    /* Change peer status to DOWN */
    peer->bfd_status = PEER_BFD_STATUS_DOWN;
  }

  return 0;
}

static int
bgp_ipv4_bfd_neigh_up (int command, struct zclient *zclient, zebra_size_t length)
{
  return bgp_bfd_neigh_up(ipv4_bfd_neigh_updown_read (zclient->ibuf));
}

static int
bgp_ipv4_bfd_neigh_down (int command, struct zclient *zclient, zebra_size_t length)
{
  return bgp_bfd_neigh_down(ipv4_bfd_neigh_updown_read (zclient->ibuf));
}

#ifdef HAVE_IPV6
static int
bgp_ipv6_bfd_neigh_up (int command, struct zclient *zclient, zebra_size_t length)
{
  return bgp_bfd_neigh_up(ipv6_bfd_neigh_updown_read (zclient->ibuf));
}

static int
bgp_ipv6_bfd_neigh_down (int command, struct zclient *zclient, zebra_size_t length)
{
  return bgp_bfd_neigh_down(ipv6_bfd_neigh_updown_read (zclient->ibuf));
}
#endif /* HAVE_IPV6 */


static int
bgp_interface_address_add (int command, struct zclient *zclient,
			   zebra_size_t length)
{
  struct connected *ifc;

  ifc = zebra_interface_address_read (command, zclient->ibuf);

  if (ifc == NULL)
    return 0;

  if (BGP_DEBUG(zebra, ZEBRA))
    {
      char buf[128];
      prefix2str(ifc->address, buf, sizeof(buf));
      zlog_debug("Zebra rcvd: interface %s address add %s",
		 ifc->ifp->name, buf);
    }

  if (if_is_operative (ifc->ifp))
    bgp_connected_add (ifc);

  return 0;
}

static int
bgp_interface_address_delete (int command, struct zclient *zclient,
			      zebra_size_t length)
{
  struct connected *ifc;

  ifc = zebra_interface_address_read (command, zclient->ibuf);

  if (ifc == NULL)
    return 0;

  if (BGP_DEBUG(zebra, ZEBRA))
    {
      char buf[128];
      prefix2str(ifc->address, buf, sizeof(buf));
      zlog_debug("Zebra rcvd: interface %s address delete %s",
		 ifc->ifp->name, buf);
    }

  if (if_is_operative (ifc->ifp))
    bgp_connected_delete (ifc);

  connected_free (ifc);

  return 0;
}

/* Zebra route add and delete treatment. */
static int
zebra_read_ipv4 (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct zapi_ipv4 api;
  unsigned long ifindex;
  struct in_addr nexthop;
  struct prefix_ipv4 p;

  s = zclient->ibuf;
  ifindex = 0;
  nexthop.s_addr = 0;

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv4 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      nexthop.s_addr = stream_get_ipv4 (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      ifindex = stream_getl (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  if (command == ZEBRA_IPV4_ROUTE_ADD)
    {
      if (BGP_DEBUG(zebra, ZEBRA))
	{
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_debug("Zebra rcvd: IPv4 route add %s %s/%d nexthop %s metric %u",
		     zebra_route_string(api.type),
		     inet_ntop(AF_INET, &p.prefix, buf[0], sizeof(buf[0])),
		     p.prefixlen,
		     inet_ntop(AF_INET, &nexthop, buf[1], sizeof(buf[1])),
		     api.metric);
	}
      bgp_redistribute_add((struct prefix *)&p, &nexthop, api.metric, api.type);
    }
  else
    {
      if (BGP_DEBUG(zebra, ZEBRA))
	{
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_debug("Zebra rcvd: IPv4 route delete %s %s/%d "
		     "nexthop %s metric %u",
		     zebra_route_string(api.type),
		     inet_ntop(AF_INET, &p.prefix, buf[0], sizeof(buf[0])),
		     p.prefixlen,
		     inet_ntop(AF_INET, &nexthop, buf[1], sizeof(buf[1])),
		     api.metric);
	}
      bgp_redistribute_delete((struct prefix *)&p, api.type);
    }

  return 0;
}

#ifdef HAVE_IPV6
/* Zebra route add and delete treatment. */
static int
zebra_read_ipv6 (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct zapi_ipv6 api;
  unsigned long ifindex;
  struct in6_addr nexthop;
  struct prefix_ipv6 p;

  s = zclient->ibuf;
  ifindex = 0;
  memset (&nexthop, 0, sizeof (struct in6_addr));

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv6 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      stream_get (&nexthop, s, 16);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      ifindex = stream_getl (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  else
    api.distance = 0;
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  /* Simply ignore link-local address. */
  if (IN6_IS_ADDR_LINKLOCAL (&p.prefix))
    return 0;

  if (command == ZEBRA_IPV6_ROUTE_ADD)
    {
      if (BGP_DEBUG(zebra, ZEBRA))
	{
	  char buf[INET6_ADDRSTRLEN];
	  zlog_debug("Zebra rcvd: IPv6 route add %s %s/%d metric %u",
		     zebra_route_string(api.type),
		     inet_ntop(AF_INET6, &p.prefix, buf, sizeof(buf)),
		     p.prefixlen, api.metric);
	}
      bgp_redistribute_add ((struct prefix *)&p, NULL, api.metric, api.type);
    }
  else
    {
      if (BGP_DEBUG(zebra, ZEBRA))
	{
	  char buf[INET6_ADDRSTRLEN];
	  zlog_debug("Zebra rcvd: IPv6 route delete %s %s/%d metric %u",
		     zebra_route_string(api.type),
		     inet_ntop(AF_INET6, &p.prefix, buf, sizeof(buf)),
		     p.prefixlen, api.metric);
	}
      bgp_redistribute_delete ((struct prefix *) &p, api.type);
    }
  
  return 0;
}
#endif /* HAVE_IPV6 */

struct interface *
if_lookup_by_ipv4 (struct in_addr *addr)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv4 p;
  struct prefix *cp; 
  
  p.family = AF_INET;
  p.prefix = *addr;
  p.prefixlen = IPV4_MAX_BITLEN;

  for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
	{
	  cp = connected->address;
	    
	  if (cp->family == AF_INET)
	    if (prefix_match (cp, (struct prefix *)&p))
	      return ifp;
	}
    }
  return NULL;
}

struct interface *
if_lookup_by_ipv4_exact (struct in_addr *addr)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix *cp; 
  
  for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
	{
	  cp = connected->address;
	    
	  if (cp->family == AF_INET)
	    if (IPV4_ADDR_SAME (&cp->u.prefix4, addr))
	      return ifp;
	}
    }
  return NULL;
}

#ifdef HAVE_IPV6
struct interface *
if_lookup_by_ipv6 (struct in6_addr *addr)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv6 p;
  struct prefix *cp; 
  
  p.family = AF_INET6;
  p.prefix = *addr;
  p.prefixlen = IPV6_MAX_BITLEN;

  for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
	{
	  cp = connected->address;
	    
	  if (cp->family == AF_INET6)
	    if (prefix_match (cp, (struct prefix *)&p))
	      return ifp;
	}
    }
  return NULL;
}

struct interface *
if_lookup_by_ipv6_exact (struct in6_addr *addr)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix *cp; 

  for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
	{
	  cp = connected->address;
	    
	  if (cp->family == AF_INET6)
	    if (IPV6_ADDR_SAME (&cp->u.prefix6, addr))
	      return ifp;
	}
    }
  return NULL;
}

static int
if_get_ipv6_global (struct interface *ifp, struct in6_addr *addr)
{
  struct listnode *cnode;
  struct connected *connected;
  struct prefix *cp; 
  
  for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
    {
      cp = connected->address;
	    
      if (cp->family == AF_INET6)
	if (! IN6_IS_ADDR_LINKLOCAL (&cp->u.prefix6))
	  {
	    memcpy (addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
	    return 1;
	  }
    }
  return 0;
}

static int
if_get_ipv6_local (struct interface *ifp, struct in6_addr *addr)
{
  struct listnode *cnode;
  struct connected *connected;
  struct prefix *cp; 
  
  for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
    {
      cp = connected->address;
	    
      if (cp->family == AF_INET6)
	if (IN6_IS_ADDR_LINKLOCAL (&cp->u.prefix6))
	  {
	    memcpy (addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
	    return 1;
	  }
    }
  return 0;
}
#endif /* HAVE_IPV6 */

int
bgp_nexthop_set (union sockunion *local, union sockunion *remote, 
		 struct bgp_nexthop *nexthop, struct peer *peer)
{
  int ret = 0;
  struct interface *ifp = NULL;

  memset (nexthop, 0, sizeof (struct bgp_nexthop));

  if (!local)
    return -1;
  if (!remote)
    return -1;

  if (local->sa.sa_family == AF_INET)
    {
      nexthop->v4 = local->sin.sin_addr;
      ifp = if_lookup_by_ipv4 (&local->sin.sin_addr);
    }
#ifdef HAVE_IPV6
  if (local->sa.sa_family == AF_INET6)
    {
      if (IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr))
	{
	  if (peer->ifname)
	    ifp = if_lookup_by_index (if_nametoindex (peer->ifname));
	}
      else
	ifp = if_lookup_by_ipv6 (&local->sin6.sin6_addr);
    }
#endif /* HAVE_IPV6 */

  if (!ifp)
    return -1;

  nexthop->ifp = ifp;

  /* IPv4 connection. */
  if (local->sa.sa_family == AF_INET)
    {
#ifdef HAVE_IPV6
      /* IPv6 nexthop*/
      ret = if_get_ipv6_global (ifp, &nexthop->v6_global);

      /* There is no global nexthop. */
      if (!ret)
	if_get_ipv6_local (ifp, &nexthop->v6_global);
      else
	if_get_ipv6_local (ifp, &nexthop->v6_local);
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  /* IPv6 connection. */
  if (local->sa.sa_family == AF_INET6)
    {
      struct interface *direct = NULL;

      /* IPv4 nexthop.  I don't care about it. */
      if (peer->local_id.s_addr)
	nexthop->v4 = peer->local_id;

      /* Global address*/
      if (! IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr))
	{
	  memcpy (&nexthop->v6_global, &local->sin6.sin6_addr, 
		  IPV6_MAX_BYTELEN);

	  /* If directory connected set link-local address. */
	  direct = if_lookup_by_ipv6 (&remote->sin6.sin6_addr);
	  if (direct)
	    if_get_ipv6_local (ifp, &nexthop->v6_local);
	}
      else
	/* Link-local address. */
	{
	  ret = if_get_ipv6_global (ifp, &nexthop->v6_global);

	  /* If there is no global address.  Set link-local address as
             global.  I know this break RFC specification... */
	  if (!ret)
	    memcpy (&nexthop->v6_global, &local->sin6.sin6_addr, 
		    IPV6_MAX_BYTELEN);
	  else
	    memcpy (&nexthop->v6_local, &local->sin6.sin6_addr, 
		    IPV6_MAX_BYTELEN);
	}
    }

  if (IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr) ||
      if_lookup_by_ipv6 (&remote->sin6.sin6_addr))
    peer->shared_network = 1;
  else
    peer->shared_network = 0;

  /* KAME stack specific treatment.  */
#ifdef KAME
  if (IN6_IS_ADDR_LINKLOCAL (&nexthop->v6_global)
      && IN6_LINKLOCAL_IFINDEX (nexthop->v6_global))
    {
      SET_IN6_LINKLOCAL_IFINDEX (nexthop->v6_global, 0);
    }
  if (IN6_IS_ADDR_LINKLOCAL (&nexthop->v6_local)
      && IN6_LINKLOCAL_IFINDEX (nexthop->v6_local))
    {
      SET_IN6_LINKLOCAL_IFINDEX (nexthop->v6_local, 0);
    }
#endif /* KAME */
#endif /* HAVE_IPV6 */
  return ret;
}

void
bgp_zebra_announce (struct prefix *p, struct bgp_info *info, struct bgp *bgp)
{
  int flags;
  u_char distance;
  struct peer *peer;

  if (zclient->sock < 0)
    return;

  if (! zclient->redist[ZEBRA_ROUTE_BGP])
    return;

  flags = 0;
  peer = info->peer;

  if (peer_sort (peer) == BGP_PEER_IBGP || peer_sort (peer) == BGP_PEER_CONFED)
    {
      SET_FLAG (flags, ZEBRA_FLAG_IBGP);
      SET_FLAG (flags, ZEBRA_FLAG_INTERNAL);
    }

  if ((peer_sort (peer) == BGP_PEER_EBGP && peer->ttl != 1)
      || CHECK_FLAG (peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK))
    SET_FLAG (flags, ZEBRA_FLAG_INTERNAL);

  if (p->family == AF_INET)
    {
      struct zapi_ipv4 api;
      struct in_addr *nexthop;

      api.flags = flags;
      nexthop = &info->attr->nexthop;

      api.type = ZEBRA_ROUTE_BGP;
      api.message = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      api.nexthop_num = 1;
      api.nexthop = &nexthop;
      api.ifindex_num = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = info->attr->med;

      distance = bgp_distance_apply (p, info, bgp);

      if (distance)
	{
	  SET_FLAG (api.message, ZAPI_MESSAGE_DISTANCE);
	  api.distance = distance;
	}

      if (BGP_DEBUG(zebra, ZEBRA))
	{
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_debug("Zebra send: IPv4 route add %s/%d nexthop %s metric %u",
		     inet_ntop(AF_INET, &p->u.prefix4, buf[0], sizeof(buf[0])),
		     p->prefixlen,
		     inet_ntop(AF_INET, nexthop, buf[1], sizeof(buf[1])),
		     api.metric);
	}

      zapi_ipv4_route (ZEBRA_IPV4_ROUTE_ADD, zclient, 
                       (struct prefix_ipv4 *) p, &api);
    }
#ifdef HAVE_IPV6
  /* We have to think about a IPv6 link-local address curse. */
  if (p->family == AF_INET6)
    {
      unsigned int ifindex;
      struct in6_addr *nexthop;
      struct zapi_ipv6 api;

      ifindex = 0;
      nexthop = NULL;
      
      assert (info->attr->extra);
      
      /* Only global address nexthop exists. */
      if (info->attr->extra->mp_nexthop_len == 16)
	nexthop = &info->attr->extra->mp_nexthop_global;
      
      /* If both global and link-local address present. */
      if (info->attr->extra->mp_nexthop_len == 32)
	{
	  /* Workaround for Cisco's nexthop bug.  */
	  if (IN6_IS_ADDR_UNSPECIFIED (&info->attr->extra->mp_nexthop_global)
	      && peer->su_remote->sa.sa_family == AF_INET6)
	    nexthop = &peer->su_remote->sin6.sin6_addr;
	  else
	    nexthop = &info->attr->extra->mp_nexthop_local;

	  if (info->peer->nexthop.ifp)
	    ifindex = info->peer->nexthop.ifp->ifindex;
	}

      if (nexthop == NULL)
	return;

      if (IN6_IS_ADDR_LINKLOCAL (nexthop) && ! ifindex)
	{
	  if (info->peer->ifname)
	    ifindex = if_nametoindex (info->peer->ifname);
	  else if (info->peer->nexthop.ifp)
	    ifindex = info->peer->nexthop.ifp->ifindex;
	}

      /* Make Zebra API structure. */
      api.flags = flags;
      api.type = ZEBRA_ROUTE_BGP;
      api.message = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      api.nexthop_num = 1;
      api.nexthop = &nexthop;
      SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
      api.ifindex_num = 1;
      api.ifindex = &ifindex;
      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = info->attr->med;

      if (BGP_DEBUG(zebra, ZEBRA))
	{
	  char buf[2][INET6_ADDRSTRLEN];
	  zlog_debug("Zebra send: IPv6 route add %s/%d nexthop %s metric %u",
		     inet_ntop(AF_INET6, &p->u.prefix6, buf[0], sizeof(buf[0])),
		     p->prefixlen,
		     inet_ntop(AF_INET6, nexthop, buf[1], sizeof(buf[1])),
		     api.metric);
	}

      zapi_ipv6_route (ZEBRA_IPV6_ROUTE_ADD, zclient, 
                       (struct prefix_ipv6 *) p, &api);
    }
#endif /* HAVE_IPV6 */
}

void
bgp_zebra_withdraw (struct prefix *p, struct bgp_info *info)
{
  int flags;
  struct peer *peer;

  if (zclient->sock < 0)
    return;

  if (! zclient->redist[ZEBRA_ROUTE_BGP])
    return;

  peer = info->peer;
  flags = 0;

  if (peer_sort (peer) == BGP_PEER_IBGP)
    {
      SET_FLAG (flags, ZEBRA_FLAG_INTERNAL);
      SET_FLAG (flags, ZEBRA_FLAG_IBGP);
    }

  if ((peer_sort (peer) == BGP_PEER_EBGP && peer->ttl != 1)
      || CHECK_FLAG (peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK))
    SET_FLAG (flags, ZEBRA_FLAG_INTERNAL);

  if (p->family == AF_INET)
    {
      struct zapi_ipv4 api;
      struct in_addr *nexthop;

      api.flags = flags;
      nexthop = &info->attr->nexthop;

      api.type = ZEBRA_ROUTE_BGP;
      api.message = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      api.nexthop_num = 1;
      api.nexthop = &nexthop;
      api.ifindex_num = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = info->attr->med;

      if (BGP_DEBUG(zebra, ZEBRA))
	{
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_debug("Zebra send: IPv4 route delete %s/%d nexthop %s metric %u",
		     inet_ntop(AF_INET, &p->u.prefix4, buf[0], sizeof(buf[0])),
		     p->prefixlen,
		     inet_ntop(AF_INET, nexthop, buf[1], sizeof(buf[1])),
		     api.metric);
	}

      zapi_ipv4_route (ZEBRA_IPV4_ROUTE_DELETE, zclient, 
                       (struct prefix_ipv4 *) p, &api);
    }
#ifdef HAVE_IPV6
  /* We have to think about a IPv6 link-local address curse. */
  if (p->family == AF_INET6)
    {
      struct zapi_ipv6 api;
      unsigned int ifindex;
      struct in6_addr *nexthop;
      
      assert (info->attr->extra);
      
      ifindex = 0;
      nexthop = NULL;

      /* Only global address nexthop exists. */
      if (info->attr->extra->mp_nexthop_len == 16)
	nexthop = &info->attr->extra->mp_nexthop_global;

      /* If both global and link-local address present. */
      if (info->attr->extra->mp_nexthop_len == 32)
	{
	  nexthop = &info->attr->extra->mp_nexthop_local;
	  if (info->peer->nexthop.ifp)
	    ifindex = info->peer->nexthop.ifp->ifindex;
	}

      if (nexthop == NULL)
	return;

      if (IN6_IS_ADDR_LINKLOCAL (nexthop) && ! ifindex)
	if (info->peer->ifname)
	  ifindex = if_nametoindex (info->peer->ifname);

      api.flags = flags;
      api.type = ZEBRA_ROUTE_BGP;
      api.message = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      api.nexthop_num = 1;
      api.nexthop = &nexthop;
      SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
      api.ifindex_num = 1;
      api.ifindex = &ifindex;
      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = info->attr->med;

      if (BGP_DEBUG(zebra, ZEBRA))
	{
	  char buf[2][INET6_ADDRSTRLEN];
	  zlog_debug("Zebra send: IPv6 route delete %s/%d nexthop %s metric %u",
		     inet_ntop(AF_INET6, &p->u.prefix6, buf[0], sizeof(buf[0])),
		     p->prefixlen,
		     inet_ntop(AF_INET6, nexthop, buf[1], sizeof(buf[1])),
		     api.metric);
	}

      zapi_ipv6_route (ZEBRA_IPV6_ROUTE_DELETE, zclient, 
                       (struct prefix_ipv6 *) p, &api);
    }
#endif /* HAVE_IPV6 */
}

/* Other routes redistribution into BGP. */
int
bgp_redistribute_set (struct bgp *bgp, afi_t afi, int type)
{
  /* Set flag to BGP instance. */
  bgp->redist[afi][type] = 1;

  /* Return if already redistribute flag is set. */
  if (zclient->redist[type])
    return CMD_WARNING;

  zclient->redist[type] = 1;

  /* Return if zebra connection is not established. */
  if (zclient->sock < 0)
    return CMD_WARNING;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra send: redistribute add %s", zebra_route_string(type));
    
  /* Send distribute add message to zebra. */
  zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient, type);

  return CMD_SUCCESS;
}

/* Redistribute with route-map specification.  */
int
bgp_redistribute_rmap_set (struct bgp *bgp, afi_t afi, int type, 
                           const char *name)
{
  if (bgp->rmap[afi][type].name
      && (strcmp (bgp->rmap[afi][type].name, name) == 0))
    return 0;

  if (bgp->rmap[afi][type].name)
    free (bgp->rmap[afi][type].name);
  bgp->rmap[afi][type].name = strdup (name);
  bgp->rmap[afi][type].map = route_map_lookup_by_name (name);

  return 1;
}

/* Redistribute with metric specification.  */
int
bgp_redistribute_metric_set (struct bgp *bgp, afi_t afi, int type,
			     u_int32_t metric)
{
  if (bgp->redist_metric_flag[afi][type]
      && bgp->redist_metric[afi][type] == metric)
    return 0;

  bgp->redist_metric_flag[afi][type] = 1;
  bgp->redist_metric[afi][type] = metric;

  return 1;
}

/* Unset redistribution.  */
int
bgp_redistribute_unset (struct bgp *bgp, afi_t afi, int type)
{
  /* Unset flag from BGP instance. */
  bgp->redist[afi][type] = 0;

  /* Unset route-map. */
  if (bgp->rmap[afi][type].name)
    free (bgp->rmap[afi][type].name);
  bgp->rmap[afi][type].name = NULL;
  bgp->rmap[afi][type].map = NULL;

  /* Unset metric. */
  bgp->redist_metric_flag[afi][type] = 0;
  bgp->redist_metric[afi][type] = 0;

  /* Return if zebra connection is disabled. */
  if (! zclient->redist[type])
    return CMD_WARNING;
  zclient->redist[type] = 0;

  if (bgp->redist[AFI_IP][type] == 0 
      && bgp->redist[AFI_IP6][type] == 0 
      && zclient->sock >= 0)
    {
      /* Send distribute delete message to zebra. */
      if (BGP_DEBUG(zebra, ZEBRA))
	zlog_debug("Zebra send: redistribute delete %s",
		   zebra_route_string(type));
      zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient, type);
    }
  
  /* Withdraw redistributed routes from current BGP's routing table. */
  bgp_redistribute_withdraw (bgp, afi, type);

  return CMD_SUCCESS;
}

/* Unset redistribution route-map configuration.  */
int
bgp_redistribute_routemap_unset (struct bgp *bgp, afi_t afi, int type)
{
  if (! bgp->rmap[afi][type].name)
    return 0;

  /* Unset route-map. */
  free (bgp->rmap[afi][type].name);
  bgp->rmap[afi][type].name = NULL;
  bgp->rmap[afi][type].map = NULL;

  return 1;
}

/* Unset redistribution metric configuration.  */
int
bgp_redistribute_metric_unset (struct bgp *bgp, afi_t afi, int type)
{
  if (! bgp->redist_metric_flag[afi][type])
    return 0;

  /* Unset metric. */
  bgp->redist_metric_flag[afi][type] = 0;
  bgp->redist_metric[afi][type] = 0;

  return 1;
}

void
bgp_zclient_reset (void)
{
  zclient_reset (zclient);
}

void
bgp_zebra_init (void)
{
  /* Set default values. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_BGP);
  zclient->router_id_update = bgp_router_id_update;
  zclient->interface_add = bgp_interface_add;
  zclient->interface_delete = bgp_interface_delete;
  zclient->interface_address_add = bgp_interface_address_add;
  zclient->interface_address_delete = bgp_interface_address_delete;
  zclient->ipv4_route_add = zebra_read_ipv4;
  zclient->ipv4_route_delete = zebra_read_ipv4;
  zclient->interface_up = bgp_interface_up;
  zclient->interface_down = bgp_interface_down;
  zclient->ipv4_bfd_neigh_up = bgp_ipv4_bfd_neigh_up;
  zclient->ipv4_bfd_neigh_down = bgp_ipv4_bfd_neigh_down;
#ifdef HAVE_IPV6
  zclient->ipv6_route_add = zebra_read_ipv6;
  zclient->ipv6_route_delete = zebra_read_ipv6;
  zclient->ipv6_bfd_neigh_up = bgp_ipv6_bfd_neigh_up;
  zclient->ipv6_bfd_neigh_down = bgp_ipv6_bfd_neigh_down;
#endif /* HAVE_IPV6 */

  /* Interface related init. */
  if_init ();
}
