# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link, get_switch, get_link
from ryu.lib import dpid as dpid_lib
from ryu.controller import dpset
import copy
UP = 1
DOWN = 0


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # USed for learning switch functioning
        self.mac_to_port = {}
        # Holds the topology data and structure
        self.topo_shape = TopoStructure()

    # The state transition: HANDSHAKE -> CONFIG -> MAIN
    #
    # HANDSHAKE: if it receives HELLO message with the valid OFP version,
    # sends Features Request message, and moves to CONFIG.
    #
    # CONFIG: it receives Features Reply message and moves to MAIN
    #
    # MAIN: it does nothing. Applications are expected to register their
    # own handlers.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPSwitchFeatures received: '
                         '\n\tdatapath_id=0x%016x n_buffers=%d '
                         '\n\tn_tables=%d auxiliary_id=%d '
                         '\n\tcapabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    """
    This is called when Ryu receives an OpenFlow packet_in message. The trick is set_ev_cls decorator. This decorator
    tells Ryu when the decorated function should be called.
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("\tpacket in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    ###################################################################################
    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        self.topo_shape.topo_raw_switches = copy.copy(get_switch(self,None))
        self.topo_shape.topo_raw_links = copy.copy(get_link(self,None))

        self.topo_shape.print_links("EventSwitchEnter")
        self.topo_shape.print_switches("EventSwitchEnter")


    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")

    """
    This function determines the links and switches currently in the topology
    """
    def get_topology_data(self):
        # Call get_switch() to get the list of objects Switch.
        self.topo_shape.topo_raw_switches = copy.copy(get_all_switch(self))

        # Call get_link() to get the list of objects Link.
        self.topo_shape.topo_raw_links = copy.copy(get_all_link(self))

        self.topo_shape.print_links("get_topology_data")
        self.topo_shape.print_switches("get_topology_data")

    ###################################################################################
    """
    EventOFPPortStatus: An event class for switch port status notification.
    The bellow handles the event.
    """
    @set_ev_cls(dpset.EventPortModify, MAIN_DISPATCHER)
    def port_modify_handler(self, ev):
        dp = ev.dp
        port_attr = ev.port
        dp_str = dpid_lib.dpid_to_str(dp.id)
        self.logger.info("\t ***switch dpid=%s"
                         "\n \t port_no=%d hw_addr=%s name=%s config=0x%08x "
                         "\n \t state=0x%08x curr=0x%08x advertised=0x%08x "
                         "\n \t supported=0x%08x peer=0x%08x curr_speed=%d max_speed=%d" %
                         (dp_str, port_attr.port_no, port_attr.hw_addr,
                          port_attr.name, port_attr.config,
                          port_attr.state, port_attr.curr, port_attr.advertised,
                          port_attr.supported, port_attr.peer, port_attr.curr_speed,
                          port_attr.max_speed))
        if port_attr.state == 1:
            self.topo_shape.print_links("Link Down")
            out = self.topo_shape.link_with_src_port(port_attr.port_no, dp.id)
            print "out"+str(out)
            if out is not None:
                print(self.topo_shape.find_shortest_path(out.src.dpid))
        elif port_attr.state == 0:
            self.topo_shape.print_links("Link Up")



    ###################################################################################
    ###################################################################################

"""
This class holds the list of links and switches in the topology and it provides some useful functions
"""
class TopoStructure():
    def __init__(self, *args, **kwargs):
        self.topo_raw_switches = []
        self.topo_raw_links = []
        self.topo_links = []

    def print_links(self, func_str=None):
        # Convert the raw link to list so that it is printed easily
        print(" \t"+str(func_str)+": Current Links:")
        for l in self.topo_raw_links:
            print (" \t\t"+str(l))

    def print_switches(self, func_str=None):
        print(" \t"+str(func_str)+": Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t"+str(s))

    def switches_count(self):
        return len(self.topo_raw_switches)

    def convert_raw_links_to_list(self):
        # Build a  list with all the links [((srcNode,port), (dstNode, port))].
        # The list is easier for printing.
        self.lock.acquire()
        self.topo_links = [((link.src.dpid, link.src.port_no),
                            (link.dst.dpid, link.dst.port_no))
                           for link in self.topo_raw_links]
        self.lock.release()

    def convert_raw_switch_to_list(self):
        # Build a list with all the switches ([switches])
        self.lock.acquire()
        self.topo_switches = [(switch.dp.id, UP) for switch in self.topo_raw_switches]
        self.lock.release()

    """
    Adds the link to list of raw links
    """
    def bring_up_link(self, link):
        self.topo_raw_links.append(link)

    """
    Check if a link with specific nodes exists.
    """
    def check_link(self,sdpid, sport, ddpid, dport):
        for i, link in self.topo_raw_links:
            if ((sdpid, sport), (ddpid, dport)) == ((link.src.dpid, link.src.port_no), (link.dst.dpid, link.dst.port_no)):
                return True
        return False

    """
    Finds the shortest path from source s to destination d.
    Both s and d are switches.
    """
    def find_shortest_path(self, s):
        s_count = self.switches_count()
        s_temp = s
        visited = []
        shortest_path = {}

        while s_count > len(visited):
            print "visited in: " + str(visited)
            visited.append(s_temp)

            print ("s_temp in: " + str(s_temp))
            for l in self.find_links_with_src(s_temp):
                print "\t"+str(l)
                if l.dst.dpid not in visited:
                    print ("\t\tDPID dst: "+ str(l.dst.dpid))
                    if l.dst.dpid in shortest_path:
                        shortest_path[l.dst.dpid] = shortest_path[l.dst.dpid] + 1
                        print("\t\t\tdpid found. Count: "+str(shortest_path[l.dst.dpid]))
                    else:
                        print("\t\t\tdpid not found.")
                        shortest_path[l.dst.dpid] = 1
            print ("shortest_path: " + str(shortest_path))
            min_val = min(shortest_path.itervalues())
            t_dpid = [k for k,v in shortest_path.iteritems() if v == min_val]
            print ("t_dpid: "+str(t_dpid))
            for dpid_index in t_dpid:
                if dpid_index not in visited:
                    s_temp = dpid_index
                    break
                else:
                    print(str(dpid_index)+" DPID not in visisted")
            print  "s_temp out: " + str(s_temp)
            print "visited out: " + str(visited)+"\n"
        return shortest_path

    """
    Finds the dpids of destinations where the links' source is s_dpid
    """
    def find_dst_with_src(self, s_dpid):
        d = []
        for l in self.topo_raw_links:
            if l.src.dpid == s_dpid:
                d.append(l.dst.dpid)
        return d

    """
    Finds the list of link objects where links' src dpid is s_dpid
    """
    def find_links_with_src(self, s_dpid):
        d_links = []
        for l in self.topo_raw_links:
            if l.src.dpid == s_dpid:
                d_links.append(l)
        return d_links

    """
    Returns a link object that has in_dpid and in_port as either source or destination dpid and port.
    """
    def link_with_src_dst_port(self, in_port, in_dpid):
        for l in self.topo_raw_links:
            if (l.src.dpid == in_dpid and l.src.port_no == in_port) or (l.dst.dpid == in_dpid and l.src.port_no == in_port):
                return l
        return None
    """
    Returns a link object that has in_dpid and in_port as either source dpid and port.
    """
    def link_with_src_port(self, in_port, in_dpid):
        for l in self.topo_raw_links:
            if (l.src.dpid == in_dpid and l.src.port_no == in_port) or (l.dst.dpid == in_dpid and l.src.port_no == in_port):
                return l
        return None
