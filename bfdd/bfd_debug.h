/*
 * BFDD - bfd_debug.h   
 *
 * Copyright (C) 2007   Jaroslaw Adam Gralak
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifndef _QUAGGA_BFD_DEBUG_H
#define _QUAGGA_BFD_DEBUG_H

#include <zebra.h>
#include "table.h"
#include "vty.h"
#include "hash.h"

extern char *bfd_state_str[];
extern char *bfd_neigh_cmd_str[];

#define BFD_IF_DEBUG_ZEBRA (bfd->debug & BFD_DEBUG_ZEBRA)
#define BFD_IF_DEBUG_FSM (bfd->debug & BFD_DEBUG_FSM)
#define BFD_IF_DEBUG_NET (bfd->debug & BFD_DEBUG_NET)


#define BFD_LOG_DEBUG_NEIGH_NOARG(format) \
     zlog_debug(format \
     " <local IP:%s disc:0x%08x(%d)<==>remote IP:%s disc:0x%08x(%d)>",        \
     sockunion_su2str(neighp->su_local), neighp->ldisc, neighp->ldisc,        \
     sockunion_su2str(neighp->su_remote), neighp->rdisc,neighp->rdisc);

#define BFD_LOG_DEBUG_NEIGH_ARG(format, args...) \
     zlog_debug(format \
     " <local IP:%s disc:0x%08x(%d)<==>remote IP:%s disc:0x%08x(%d)>", ##args,\
     sockunion_su2str(neighp->su_local), neighp->ldisc, neighp->ldisc,        \
     sockunion_su2str(neighp->su_remote), neighp->rdisc,neighp->rdisc);

#define BFD_ZEBRA_LOG_DEBUG_NOARG(format) \
     { \
       char rpbuf[BUFSIZ]; \
       char lpbuf[BUFSIZ]; \
       prefix2str(&cneighp->raddr,rpbuf,sizeof(rpbuf)); \
       prefix2str(&cneighp->laddr,lpbuf,sizeof(lpbuf)); \
       zlog_debug("[ZEBRA] " format \
       " <raddr=%s, laddr=%s, ifindex=%d, flags=%d>", \
        rpbuf, lpbuf, cneighp->ifindex, cneighp->flags);\
     }

#define BFD_ZEBRA_LOG_DEBUG_ARG(format, args...) \
     { \
     char rpbuf[BUFSIZ]; \
     char lpbuf[BUFSIZ]; \
     prefix2str(&cneighp->raddr,rpbuf,sizeof(rpbuf)); \
     prefix2str(&cneighp->laddr,lpbuf,sizeof(lpbuf)); \
     zlog_debug("[ZEBRA] " format \
     " <raddr=%s, laddr=%s, ifindex=%d, flags=%d>", ##args,\
      rpbuf, lpbuf, cneighp->ifindex, cneighp->flags); \
     }

#define BFD_FSM_LOG_DEBUG(format, args...) \
     zlog_debug("[FSM] " format \
     " <local IP:%s disc:0x%08x(%d)<==>remote IP:%s disc:0x%08x(%d)>", ##args,\
     sockunion_su2str(neighp->su_local), neighp->ldisc, neighp->ldisc,        \
     sockunion_su2str(neighp->su_remote), neighp->rdisc,neighp->rdisc);

#define BFD_FSM_LOG_DEBUG_NOARG(format) \
     zlog_debug("[FSM] " format \
     " <local IP:%s disc:0x%08x(%d)<==>remote IP:%s disc:0x%08x(%d)>",        \
     sockunion_su2str(neighp->su_local), neighp->ldisc, neighp->ldisc,        \
     sockunion_su2str(neighp->su_remote), neighp->rdisc,neighp->rdisc);

void bfd_vty_debug_init (void);

#endif /* _QUAGGA_BFD_DEBUG_H */
