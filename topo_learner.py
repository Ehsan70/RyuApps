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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link
from ryu.lib import dpid as dpid_lib
from threading import Lock
from ryu.controller import dpset

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

        self.logger.info("\tpacket in %s %s %s %s", dpid, src, dst, in_port)

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
    @set_ev_cls(event.EventSwitchEnter, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def handler_get_topology_data(self, ev):
        self.get_topology_data()

    """
    This function determines the links and switches currently in the topology
    """
    def get_topology_data(self):
        # Call get_switch() to get the list of objects Switch.
        self.topo_shape.topo_raw_switches = get_all_switch(self)

        # Call get_link() to get the list of objects Link.
        self.topo_shape.topo_raw_links = get_all_link(self)

        self.topo_shape.print_links("get_topology_data")
        self.topo_shape.print_switches()

    ###################################################################################
    """
    EventOFPPortStatus: An event class for switch port status notification.
    The bellow handles the event.
    """
    @set_ev_cls(dpset.EventPortModify, MAIN_DISPATCHER)
    def _port_modify_handler(self, ev):
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
        self.logger.info("\t[Ehsan] Sending send_port_desc_stats_request to datapath id : " + dp_str)
        self.send_port_desc_stats_request(dp)

    ###################################################################################
    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    """
    EventOFPPortDescStatsReply: an event where it is fired when Port description reply message
    The bellow handles the event.
    """
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):

        dp_str = dpid_lib.dpid_to_str(ev.msg.datapath.id)
        for p in ev.msg.body:
            self.logger.info("\t ***switch dpid=%s"
                             "\n \t port_no=%d hw_addr=%s name=%s config=0x%08x "
                             "\n \t state=0x%08x curr=0x%08x advertised=0x%08x "
                             "\n \t supported=0x%08x peer=0x%08x curr_speed=%d "
                             "max_speed=%d" %
                             (dp_str, p.port_no, p.hw_addr,
                              p.name, p.config,
                              p.state, p.curr, p.advertised,
                              p.supported, p.peer, p.curr_speed,
                              p.max_speed))

            if p.state == 1:
                print("Bringing the port %d on switch %s down",p.port_no,dp_str)
                self.topo_shape.bring_down_link(switch_dpid=ev.msg.datapath, port=p.port_no)
                self.topo_shape.print_links("port_desc_stats_reply_handler")

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
        # contains tuples of switches and their state. The state is either up (1) or down (2)
        self.topo_switches = []
        self.lock = Lock()

    def print_links(self, func_str=None):
        # Convert the raw link to list so that it is printed easily
        self.convert_raw_links_to_list()
        print("\t"+func_str+": Current Links:")
        for l in self.topo_links:
            print ("\t"+str(l))

    def print_switches(self):
        # Todo:  do the same thing you did to print_links()
        self.convert_raw_switch_to_list()
        print("Current Switches")
        for s in self.topo_switches:
            print (s)

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

    def bring_down_link(self, switch_dpid, port):
        if port < 1 or switch_dpid < 0:
            raise ValueError
        # if a port goes down, remove all the links that have the port as their src or dst.
        self.lock.acquire()
        for i, link in enumerate(self.topo_raw_links):
            if link.src.dpid == switch_dpid and link.src.port_no == port and not self.topo_raw_links:
                print "The link is in here"
                del (self.topo_raw_links[i])
            elif link.dst.dpid == switch_dpid and link.dst.port_no == port and not self.topo_raw_links:
                print "The link is in here2"
                del (self.topo_raw_links[i])
        self.lock.release()
    """
    def bring_down_link(self, del_link):
        # if a port goes down, remove all the links that have the port as their src or dst.
        if del_link in self.topo_raw_links:
            print "The link is in here"
            self.topo_raw_links.remove(del_link)
    """
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
        for i, ((d1, q1), (d2, q2)) in enumerate(self.topo_links):
            if (d1 == switch_dpid and q1 == port) or (d2 == switch_dpid and q2 == port):
                del(self.topo_links[i])
"""