"""
An OpenFlow 1.0 L2 NAT implementation.
"""
import logging
from ryu.lib.packet import ether_types
from ryu.ofproto import inet
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.controller import dpset
from netaddr import *
from collections import namedtuple
from time import time
import random

"""
preinstalled MAC addr
"""
MAC_ADDR = {'10.0.0.1': '00:00:00:00:01:01', 
            '10.0.0.2': '00:00:00:00:01:02', 
            '10.0.0.3': '00:00:00:00:01:03', 
            '10.0.0.4': '00:00:00:00:01:04'}


"""
Make ARP reply packet
"""
def arp_reply(src_mac, src_ip, target_mac, target_ip):
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=target_mac, src=src_mac))
    pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=target_mac, dst_ip=target_ip))
    pkt.serialize()
    data = pkt.data
    return data


class NAT(app_manager.RyuApp):
    global Ipv4_addr
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    Ipv4_addr = namedtuple('Ipv4_addr', ['addr', 'port'])

    def __init__(self, *args, **kwargs):
        global wan_ip_subnet
        super(NAT, self).__init__(*args, **kwargs)
        wan_ip_subnet = '10.0.0.0/24'
        self.wan_ip = {}
        self.wan_mac = {}
        self.lan_ip = {}
        self.lan_mac = {}
        self.lan_ip_subnet = {}
        self.maps = {}
        self.ports = {}
        self.ip_mac_table = {}
        self.mac_port_table = {}
        self.timeout = {}

    """
    add new flow
    """
    def add_flow(self, datapath, match, actions, priority=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, actions=actions, hard_timeout=hard_timeout, cookie=0, command=ofproto.OFPFC_ADD)
        datapath.send_msg(mod)
        self.logger.debug('add_flow:' + str(mod))

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def _event_switch_enter_handler(self, ev):
        dl_type_arp = ether_types.ETH_TYPE_ARP
        dl_type_ipv4 = ether_types.ETH_TYPE_IP
        dl_type_ipv6 = ether_types.ETH_TYPE_IPV6
        dp = ev.dp
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        self.logger.info('switch connected %s', dp.id)

        if dp.id < 16:
            self.wan_ip[dp.id] = '10.0.0.' + str(dp.id)
            self.wan_mac[dp.id] = '00:00:00:00:01:0' + str(dp.id)
            self.lan_ip[dp.id] = '192.168.' + str(dp.id) + '.1'
            self.lan_mac[dp.id] = '00:00:00:00:00:0' + str(dp.id)
            self.lan_ip_subnet[dp.id] = '192.168.' + str(dp.id) + '.0/24'
        else:
            self.wan_ip[dp.id] = '10.1.0.' + str(dp.id)
            self.wan_mac[dp.id] = '00:00:00:00:02:' + str(dp.id)
            self.lan_ip[dp.id] = '10.0.0.' + str(dp.id)
            self.lan_mac[dp.id] = '00:00:00:00:01:' + str(dp.id)
            self.lan_ip_subnet[dp.id] = '10.0.0.0/24'
        self.maps[dp.id] = {}
        self.ports[dp.id] = range(50000, 60000)
        self.ip_mac_table[dp.id] = {}
        self.mac_port_table[dp.id] = {}
        self.timeout[dp.id] = {}

        
        """
        We handle ipv6, ipv4, arp packet like switch l2/3
        """
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

        match = parser.OFPMatch(dl_type=dl_type_ipv6)
        self.add_flow(dp, match, actions)

        match = parser.OFPMatch(dl_type=dl_type_ipv4, nw_proto=inet.IPPROTO_IGMP)
        self.add_flow(dp, match, actions)

        match = parser.OFPMatch(dl_type=dl_type_arp)
        self.add_flow(dp, match, actions)

        """
        We will handled these type of packet in controller
        """

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        match = parser.OFPMatch(dl_type=dl_type_ipv4, nw_proto=inet.IPPROTO_ICMP)
        self.add_flow(dp, match, actions)

        match = parser.OFPMatch(dl_type=dl_type_ipv4, nw_proto=inet.IPPROTO_TCP)
        self.add_flow(dp, match, actions)

        match = parser.OFPMatch(dl_type=dl_type_ipv4, nw_proto=inet.IPPROTO_UDP)
        self.add_flow(dp, match, actions)

        """
        handling special kind of ARP packet
        """
        match = parser.OFPMatch(dl_type=dl_type_arp, nw_dst=IPAddress(self.lan_ip[dp.id]))
        self.add_flow(dp, match, actions, priority=10)

        match = parser.OFPMatch(dl_type=dl_type_arp, nw_dst=IPAddress(self.wan_ip[dp.id]))
        self.add_flow(dp, match, actions, priority=10)

    """
    PORT assigning
    """
    def _port_assign(self, dpid, ipv4_addr):
        port = self.ports[dpid].pop(random.randrange(len(self.ports[dpid])))
        self.timeout[dpid][port] = time() + 30
        self.maps[dpid][ipv4_addr] = port
        self.maps[dpid][port] = ipv4_addr
        print 'Created mapping: %s %s to %s %s' % (ipv4_addr.addr, ipv4_addr.port, self.wan_ip[dpid], port)
        return port

    def _timeout_checker(self, dpid, ipv4_addr, port):
        if self.timeout[dpid][port] < time():
            print 'outdated!'
            self.maps[dpid].pop(ipv4_addr)
            self.maps[dpid].pop(port)
            self.timeout[dpid].pop(port)
            self.ports[dpid].append(port)
            return True
        else:
            self.timeout[dpid][port] = time() + 30
            return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print 'msg in'
        message = ev.msg
        datapath = message.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(message.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        bitmask = str(24)


        src_match = IPNetwork(self.lan_ip_subnet[dpid])
        dst_match = self.wan_ip[dpid]

        if message.in_port != 1:
            out_port = 1
        else:
            out_port = ofproto.OFPP_NORMAL

        
        """
        Handling ARP against router
        """
        if arp_pkt:
            if arp_pkt.dst_ip == str(self.lan_ip[dpid]):
                data = arp_reply(src_mac=self.lan_mac[dpid], src_ip=self.lan_ip[dpid], target_mac=arp_pkt.src_mac, target_ip=arp_pkt.src_ip)
                self.ip_mac_table[dpid][arp_pkt.src_ip] = arp_pkt.src_mac
                self.mac_port_table[dpid][arp_pkt.src_mac] = message.in_port
            elif arp_pkt.dst_ip == str(self.wan_ip[dpid]):
                data = arp_reply(src_mac=self.wan_mac[dpid], src_ip=self.wan_ip[dpid], target_mac=arp_pkt.src_mac, target_ip=arp_pkt.src_ip)
            action = [parser.OFPActionOutput(port=message.in_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data, in_port=ofproto.OFPP_CONTROLLER, actions=action)
            datapath.send_msg(out)
            return
        else:
            """
            Handling local to local packet
            """
            if IPAddress(ip.src) in IPNetwork(self.lan_ip_subnet[dpid]) and IPAddress(ip.dst) in IPNetwork(self.lan_ip_subnet[dpid]):
                print 'local to local'
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                data = None

                if message.buffer_id == 0xFFFFFFFF:
                    data = message.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data, in_port=message.in_port, actions=actions)
                datapath.send_msg(out)

            else:
                """
                Handling loopback packet
                """
                if IPAddress(ip.src) in IPNetwork(self.lan_ip_subnet[dpid]) and ip.dst == self.wan_ip[dpid]:
                    print 'loopback'
                    t = pkt.get_protocol(tcp.tcp)
                    u = pkt.get_protocol(udp.udp)
                    src_port = t.src_port if t else u.src_port
                    dst_port = t.dst_port if t else u.dst_port

                    """
                    Find port mapping
                    """
                    if dst_port in self.maps[dpid]:
                        ipv4_addr = self.maps[dpid][dst_port]
                        if self._timeout_checker(dpid, ipv4_addr, dst_port):
                            print 'This port is outdated, msg dropped'
                            return
                    else:
                        print 'Dropping msg as dst is not understood'
                        return

                    src_ipv4_addr = Ipv4_addr(addr=ip.src, port=src_port)
                    """
                    Check port and mapping
                    """
                    if src_ipv4_addr in self.maps[dpid]:
                        port = self.maps[dpid][src_ipv4_addr]
                        if self._timeout_checker(dpid, src_ipv4_addr, port):
                            port = self._port_assign(dpid, src_ipv4_addr)
                    else:
                        port = self._port_assign(dpid, src_ipv4_addr)

                    """
                    passing data with router ip source
                    """
                    actions = [parser.OFPActionSetNwSrc(self.ipv4_to_int(self.wan_ip[dpid])),
                                parser.OFPActionSetTpSrc(port),
                                parser.OFPActionSetNwDst(self.ipv4_to_int(ipv4_addr.addr)),
                                parser.OFPActionSetTpDst(ipv4_addr.port),
                                parser.OFPActionSetDlSrc(self.wan_mac[dpid]),
                                parser.OFPActionSetDlDst(self.ip_mac_table[dpid][ipv4_addr.addr]),
                                parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                    data = None

                    if message.buffer_id == 0xFFFFFFFF:
                        data = message.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data, in_port=message.in_port, actions=actions)
                    datapath.send_msg(out)
                    return
                
                """
                Handling TCP or UDP
                """
                if ip.proto == inet.IPPROTO_TCP or ip.proto == inet.IPPROTO_UDP:
                    print 'handling TCP or UDP'
                    t = pkt.get_protocol(tcp.tcp)
                    u = pkt.get_protocol(udp.udp)
                    if IPNetwork(ip.src + '/' + bitmask) == src_match:  #LAN to WAN
                        src_port = t.src_port if t else u.src_port  #get source port
                        ipv4_addr = Ipv4_addr(addr=ip.src, port=src_port)

                        if ipv4_addr in self.maps[dpid]:    #if it is not new port
                            port = self.maps[dpid][ipv4_addr]
                            if self._timeout_checker(dpid, ipv4_addr, port):    #if it is timedout
                                port = self._port_assign(dpid, ipv4_addr)
                        else:   #if it is new port
                            port = self._port_assign(dpid, ipv4_addr)

                        """
                        passing data with Router's WAN IP and MAC address
                        """
                        actions = [
                                parser.OFPActionSetNwSrc(self.ipv4_to_int(self.wan_ip[dpid])),
                                parser.OFPActionSetTpSrc(port),
                                parser.OFPActionSetDlSrc(self.wan_mac[dpid]),
                                parser.OFPActionSetDlDst(MAC_ADDR[ip.dst]),
                                parser.OFPActionOutput(out_port)]

                        data = None
                        if message.buffer_id == 0xFFFFFFFF:
                            data = message.data
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data, in_port=message.in_port, actions=actions)
                        datapath.send_msg(out)
                        return
                    if ip.dst == dst_match: #WAN to LAN
                        print 'convert dst'
                        dst_port = t.dst_port if t else u.dst_port

                        """
                        Find corresponding port from map
                        """
                        if dst_port in self.maps[dpid]:
                            ipv4_addr = self.maps[dpid][dst_port]
                            if self._timeout_checker(dpid, ipv4_addr, dst_port):
                                print 'This port is outdated, msg dropped'
                                return
                        else:
                            print 'Dropping msg as dst is not understood'
                            return

                        """
                        passing packet to private network host with Router's WAN MAC
                        """
                        actions = [parser.OFPActionSetNwDst(self.ipv4_to_int(ipv4_addr.addr)),
                                parser.OFPActionSetTpDst(ipv4_addr.port),
                                parser.OFPActionSetDlSrc(self.lan_mac[dpid]),
                                parser.OFPActionSetDlDst(self.ip_mac_table[dpid][ipv4_addr.addr]),
                                parser.OFPActionOutput(out_port)]
                        data = None
                        if message.buffer_id == 0xFFFFFFFF:
                            data = message.data
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data, in_port=message.in_port, actions=actions)
                        datapath.send_msg(out)
                        return

                elif ip.proto == inet.IPPROTO_ICMP:
                    """
                    Handling ICMP
                    """
                    ping = pkt.get_protocol(icmp.icmp)
                    if IPNetwork(ip.src + '/' + bitmask) == src_match:  #LAN to WAN
                        icmp_id = ping.data.id
                        if icmp_id not in self.maps[dpid]:
                            self.maps[dpid][icmp_id] = ip.src
                        actions = [
                                parser.OFPActionSetDlSrc(self.wan_mac[dpid]),
                                parser.OFPActionSetDlDst(MAC_ADDR[ip.dst]),
                                parser.OFPActionSetNwSrc(self.ipv4_to_int(self.wan_ip[dpid])),
                                parser.OFPActionOutput(out_port)]
                        data = None
                        if message.buffer_id == 0xFFFFFFFF:
                            data = message.data
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data, in_port=message.in_port, actions=actions)
                        datapath.send_msg(out)
                        return
                    if ip.dst == dst_match:     #WAN to LAN
                        icmp_id = ping.data.id
                        if icmp_id in self.maps[dpid]:
                            dst_addr = self.maps[dpid][icmp_id]
                        else:
                            print 'Dropping msg as dst is not understood'
                            return
                        actions = [
                                parser.OFPActionSetDlSrc(self.lan_mac[dpid]),
                                parser.OFPActionSetDlDst(self.ip_mac_table[dpid][dst_addr]),
                                parser.OFPActionSetNwDst(self.ipv4_to_int(dst_addr)),
                                parser.OFPActionOutput(out_port)]
                        data = None
                        if message.buffer_id == 0xFFFFFFFF:
                            data = message.data
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data, in_port=message.in_port, actions=actions)
                        datapath.send_msg(out)
                        return

                else:
                    """
                    Other packet
                    """
                    actions = [parser.OFPActionOutput(out_port)]
                    data = None
                    if message.buffer_id == 0xFFFFFFFF:
                        data = message.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=message.buffer_id, data=data, in_port=message.in_port, actions=actions)
                    datapath.send_msg(out)
            return

    def ipv4_to_str(self, integre):
        ip_list = [ str(integre >> 24 - n * 8 & 255) for n in range(4) ]
        return ('.').join(ip_list)

    def ipv4_to_int(self, string):
        ip = string.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            b = int(b)
            i = i << 8 | b

        return i
