/*
 * udpipencap.{cc,hh} -- element encapsulates packet in UDP/IP header
 * Benjie Chen, Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology.
 *
 * This software is being provided by the copyright holders under the GNU
 * General Public License, either version 2 or, at your discretion, any later
 * version. For more information, see the `COPYRIGHT' file in the source
 * distribution.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include "click_ip.h"
#include "udpipencap.hh"
#include "confparse.hh"
#include "error.hh"
#include "glue.hh"
#include "elements/standard/alignmentinfo.hh"
#ifdef __KERNEL__
# include <net/checksum.h>
#endif

UDPIPEncap::UDPIPEncap()
{
  add_input();
  add_output();
}

UDPIPEncap::~UDPIPEncap()
{
}

UDPIPEncap *
UDPIPEncap::clone() const
{
  return new UDPIPEncap;
}

int
UDPIPEncap::configure(const Vector<String> &conf, ErrorHandler *errh)
{
  bool do_cksum = true;
  unsigned sp, dp;
  if (cp_va_parse(conf, this, errh,
		  cpIPAddress, "source address", &_saddr,
		  cpUnsigned, "source port", &sp,
		  cpIPAddress, "destination address", &_daddr,
		  cpUnsigned, "destination port", &dp,
		  cpOptional,
		  cpBool, "do UDP checksum?", &do_cksum,
		  0) < 0)
    return -1;
  if (sp >= 0x10000 || dp >= 0x10000)
    return errh->error("source or destination port too large");
  
  _sport = sp;
  _dport = dp;
  _id = 0;
  _cksum = do_cksum;

#ifdef __KERNEL__
  // check alignment
  {
    int ans, c, o;
    ans = AlignmentInfo::query(this, 0, c, o);
    _aligned = (ans && c == 4 && o == 0);
    if (!_aligned)
      errh->warning("IP header unaligned, cannot use fast IP checksum");
    if (!ans)
      errh->message("(Try passing the configuration through `click-align'.)");
  }
#endif
  
  return 0;
}

Packet *
UDPIPEncap::simple_action(Packet *p)
{
  p = p->uniqueify();
  p = p->push(sizeof(click_udp) + sizeof(click_ip));
  click_ip *ip = (click_ip *)p->data();
  click_udp *udp = (click_udp *)(ip + 1);

  // set up IP header
  ip->ip_v = IPVERSION;
  ip->ip_hl = sizeof(click_ip) >> 2;
  ip->ip_len = htons(p->length());
  ip->ip_id = htons(_id++);
  ip->ip_p = IP_PROTO_UDP;
  ip->ip_src = _saddr;
  ip->ip_dst = _daddr;

  if (p->ip_ttl_anno()) {
    ip->ip_tos = p->ip_tos_anno();
    /* We want to preserve the DF flag if set */
    ip->ip_off = htons(p->ip_off_anno() & IP_RF);
    ip->ip_ttl = p->ip_ttl_anno();
  } else {
    ip->ip_tos = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 250; //rtm
  }

  ip->ip_sum = 0;
#ifdef __KERNEL__
  if (_aligned) {
    ip->ip_sum = ip_fast_csum((unsigned char *)ip, sizeof(click_ip) >> 2);
  } else {
#endif
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(click_ip));
#ifdef __KERNEL__
  }
#endif
  
  p->set_dst_ip_anno(IPAddress(_daddr));
  p->set_ip_header(ip, sizeof(click_ip));

  // set up UDP header
  udp->uh_sport = htons(_sport);
  udp->uh_dport = htons(_dport);
  unsigned short len = p->length() - sizeof(click_ip);
  udp->uh_ulen = htons(len);
  if (_cksum) {
    unsigned csum = ~in_cksum((unsigned char *)udp, len) & 0xFFFF;
#ifdef __KERNEL__
    udp->uh_sum = csum_tcpudp_magic(_saddr.s_addr, _daddr.s_addr,
				    len, IP_PROTO_UDP, csum);
#else
    unsigned short *words = (unsigned short *)&ip->ip_src;
    csum += words[0];
    csum += words[1];
    csum += words[2];
    csum += words[3];
    csum += htons(IP_PROTO_UDP);
    csum += htons(len);
    while (csum >> 16)
      csum = (csum & 0xFFFF) + (csum >> 16);
    udp->uh_sum = ~csum & 0xFFFF;
#endif
  } else
    udp->uh_sum = 0;
  
  return p;
}

EXPORT_ELEMENT(UDPIPEncap)
