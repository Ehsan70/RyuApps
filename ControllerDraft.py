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
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import packet

from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.icmp import icmp
from ryu.lib.packet.ipv6 import ipv6
from ryu.lib.packet.arp import arp

from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link, get_switch, get_link
from ryu.lib import dpid as dpid_lib
from ryu.controller import dpset
import copy
from threading import Lock

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

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

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
        msg = ev.msg
        print "#############################################"
        datapath = msg.datapath
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)

        # Uncomment the blow if you want the msg printed.
        #self.logger.info("packet-in: %s" % (pkt,))

        pkt_arp_list = pkt.get_protocols(arp)
        if pkt_arp_list:
            print "datapath id: "+str(dpid)
            print "port: "+str(port)

            pkt_arp = pkt_arp_list[0]
            print ("pkt_arp: " + str(pkt_arp))
            print ("pkt_arp:dst_ip: " + str(pkt_arp.dst_ip))
            print ("pkt_arp:src_ip: " + str(pkt_arp.src_ip))
            print ("pkt_arp:dst_mac: " + str(pkt_arp.dst_mac))
            print ("pkt_arp:src_mac: " + str(pkt_arp.src_mac))

            dst = pkt_arp.dst_mac
            src = pkt_arp.src_mac
            in_port = msg.match['in_port']
            self.mac_to_port[dpid][src] = in_port

            print ("mac_to_port: "+str(self.mac_to_port))
    ###################################################################################
    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        self.topo_shape.topo_raw_switches = copy.copy(get_switch(self, None))
        self.topo_shape.topo_raw_links = copy.copy(get_link(self, None))

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
        print ("\t #######################")
        self.topo_shape.lock.acquire()
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
            tmp_list = []
            first_removed_link = self.topo_shape.link_with_src_and_port(port_attr.port_no, dp.id)
            second_removed_link = self.topo_shape.link_with_dst_and_port(port_attr.port_no, dp.id)

            for i, link in enumerate(self.topo_shape.topo_raw_links):
                if link.src.dpid == dp.id and link.src.port_no == port_attr.port_no:
                    print "\t Removing link " + str(link) + " with index " + str(i)
                elif link.dst.dpid == dp.id and link.dst.port_no == port_attr.port_no:
                    print "\t Removing link " + str(link) + " with index " + str(i)
                else:
                    tmp_list.append(link)

            self.topo_shape.topo_raw_links = copy.copy(tmp_list)

            self.topo_shape.print_links(" Link Down")
            print "\t First removed link: " + str(first_removed_link)
            print "\t Second removed link: " + str(second_removed_link)

            if first_removed_link is not None and second_removed_link is not None:
                # Find shortest path for source with dpid first_removed_link.src.dpid
                shortest_path_hubs, shortest_path_node = self.topo_shape.find_shortest_path(first_removed_link.src.dpid)
                print "\t Shortest Path:"
                print("\t\tNew shortest_path_hubs: {0}"
                      "\n\t\tNew shortest_path_node: {1}".format(shortest_path_hubs, shortest_path_node))

                """
                find_backup_path(): Finds the bakcup path (which contains dpids) for the removed link which is
                    called first_removed_link based on shortest_path_node that is given to find_backup_path()
                convert_dpid_path_to_links(): The functions turns the given list of dpid to list of Link objects.
                revert_link_list(): This reverts the links in the list of objects. This is because all the links in the
                    topo are double directed edge.
                """
                result = self.topo_shape.convert_dpid_path_to_links(self.topo_shape.find_backup_path(
                    link=first_removed_link, shortest_path_node=shortest_path_node))
                self.topo_shape.print_input_links(list_links=result)
                reverted_result = self.topo_shape.revert_link_list(link_list=result)
                self.topo_shape.print_input_links(list_links=reverted_result)

                self.topo_shape.send_flows_for_backup_path(result)
                self.topo_shape.send_flows_for_backup_path(reverted_result)

        elif port_attr.state == 0:
            self.topo_shape.print_links(" Link Up")
        self.topo_shape.lock.release()

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
        self.lock = Lock()

        # This structure
        self.link_backup = {}

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


    def send_flows_for_backup_path(self, bk_path):
        u_dpids = self.find_unique_dpid_inlinklist(bk_path)
        visited_dpids = []
        for temp_dpid in u_dpids:
            ports = self.find_ports_for_dpid(temp_dpid, bk_path)
            if len(ports) == 2:
                visited_dpids.append(temp_dpid)
                match = ofproto_v1_3_parser.OFPMatch(in_port=ports[0])
                actions = [ofproto_v1_3_parser.OFPActionOutput(port=ports[1])]
                self.add_flow(self.get_dp_switch_with_id(temp_dpid), 1, match, actions)
                match = ofproto_v1_3_parser.OFPMatch(in_port=ports[1])
                actions = [ofproto_v1_3_parser.OFPActionOutput(port=ports[0])]
                self.add_flow(self.get_dp_switch_with_id(temp_dpid), 1, match, actions)
            elif len(ports) > 2:
                visited_dpids.append(temp_dpid)
                print("Need to be implemented.")

        end_points = [x for x in u_dpids if x not in visited_dpids]
        if len(end_points) > 2:
            print("There is something wrong. There is two endpoints for a link")

        for temp_dpid_endpoints in end_points:
            other_port = self.find_ports_for_dpid(temp_dpid_endpoints, bk_path)
            match = ofproto_v1_3_parser.OFPMatch(in_port=1)
            actions = [ofproto_v1_3_parser.OFPActionOutput(port=other_port[0])]
            self.add_flow(self.get_dp_switch_with_id(temp_dpid_endpoints), 1, match, actions)
            match = ofproto_v1_3_parser.OFPMatch(in_port=other_port[0])
            actions = [ofproto_v1_3_parser.OFPActionOutput(port=1)]
            self.add_flow(self.get_dp_switch_with_id(temp_dpid_endpoints), 1, match, actions)

    """
    Based on shortest_path_node, the functions finds a backup path for the link object Link.
    """
    def find_backup_path(self, link, shortest_path_node):
        s = link.src.dpid
        d = link.dst.dpid
        if d==s:
            print("Link Error")
        # The bk_path is a list of DPIDs that the path must go through to reach d from s
        bk_path = []
        bk_path.append(d)
        while d != s:
            if d in shortest_path_node:
                d = shortest_path_node[d]
            bk_path.append(d)

        return bk_path

    """
    This reverts the link object in the link list.
    """
    def revert_link_list(self, link_list):
        reverted_list = []
        for l in link_list:
            for ll in self.topo_raw_links:
                if l.dst.dpid == ll.src.dpid and l.src.dpid == ll.dst.dpid:
                    reverted_list.append(ll)
        return reverted_list

    """
    This converts the list of dpids returned from find_backup_path() to a list of link objects.
    """
    def convert_dpid_path_to_links(self, dpid_list):
        dpid_list = list(reversed(dpid_list))
        backup_links = []
        for i, v in enumerate(dpid_list):
            if not i > (len(dpid_list)-1) and not i+1 > (len(dpid_list)-1):
                s = v
                d = dpid_list[i+1]
                for link in self.topo_raw_links:
                    if link.dst.dpid == d and link.src.dpid == s:
                        backup_links.append(link)
        return backup_links

    def print_links(self, func_str=None):
        # Convert the raw link to list so that it is printed easily
        print(" \t" + str(func_str) + ": Current Links:")
        for l in self.topo_raw_links:
            print (" \t\t" + str(l))

    def print_input_links(self, list_links):
        # Convert the raw link to list so that it is printed easily
        print(" \t Given Links:")
        for l in list_links:
            print (" \t\t" + str(l))

    def print_switches(self, func_str=None):
        print(" \t" + str(func_str) + ": Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t" + str(s))

    """
    Returns a datapath with id set to dpid
    """
    def get_dp_switch_with_id(self,dpid):
        for s in self.topo_raw_switches:
            if s.dp.id == dpid:
                return s.dp
        return None

    def switches_count(self):
        return len(self.topo_raw_switches)

    def convert_raw_links_to_list(self):
        # Build a  list with all the links [((srcNode,port), (dstNode, port))].
        # The list is easier for printing.
        self.topo_links = [((link.src.dpid, link.src.port_no),
                            (link.dst.dpid, link.dst.port_no))
                           for link in self.topo_raw_links]

    def convert_raw_switch_to_list(self):
        # Build a list with all the switches ([switches])
        self.topo_switches = [(switch.dp.id, UP) for switch in self.topo_raw_switches]

    """
    Adds the link to list of raw links
    """
    def bring_up_link(self, link):
        self.topo_raw_links.append(link)

    """
    Check if a link with specific two endpoints exists.
    """
    def check_link(self, sdpid, sport, ddpid, dport):
        for i, link in self.topo_raw_links:
            if ((sdpid, sport), (ddpid, dport)) == (
                    (link.src.dpid, link.src.port_no), (link.dst.dpid, link.dst.port_no)):
                return True
        return False

    """
    Returns list of ports in a list of link with dpid
    """
    def find_ports_for_dpid(self,dpid, link_list):
        port_ids = []
        for l in link_list:
            if l.src.dpid == dpid:
                port_ids.append(l.src.port_no)
            elif l.dst.dpid == dpid:
                port_ids.append(l.dst.port_no)
        return port_ids

    """
    Returns list of unique dpids in a list of links
    """
    def find_unique_dpid_inlinklist(self,link_list):
        dp_ids = []
        for l in link_list:
            if l.dst.dpid not in dp_ids:
                dp_ids.append(l.dst.dpid)
            elif l.src.dpid not in dp_ids:
                dp_ids.append(dp_ids.append(dp_ids))
        return dp_ids

    """
    Finds the shortest path from source s to all other nodes.
    Both s and d are switches.
    """
    def find_shortest_path(self, s):
        # I really recommend watching this video: https://www.youtube.com/watch?v=zXfDYaahsNA
        s_count = self.switches_count()
        s_temp = s

        # If you wanna see the prinfs set this to one.
        verbose = 0

        visited = []

        Fereng = []
        Fereng.append(s_temp)

        # Records number of hubs which you can reach the node from specified src
        shortest_path_hubs = {}
        # The last node which you can access the node from. For example: {1,2} means you can reach node 1 from node 2.
        shortest_path_node = {}
        shortest_path_hubs[s_temp] = 0
        shortest_path_node[s_temp] = s_temp
        while s_count > len(visited):
            if verbose == 1: print "visited in: " + str(visited)
            visited.append(s_temp)
            if verbose == 1: print ("Fereng in: " + str(Fereng))
            if verbose == 1: print ("s_temp in: " + str(s_temp))
            for l in self.find_links_with_src(s_temp):
                if verbose == 1: print "\t" + str(l)
                if l.dst.dpid not in visited:
                    Fereng.append(l.dst.dpid)
                if verbose == 1: print ("\tAdded {0} to Fereng: ".format(l.dst.dpid))
                if l.dst.dpid in shortest_path_hubs:
                    # Find the minimum o
                    if shortest_path_hubs[l.src.dpid] + 1 < shortest_path_hubs[l.dst.dpid]:
                        shortest_path_hubs[l.dst.dpid] = shortest_path_hubs[l.src.dpid] + 1
                        shortest_path_node[l.dst.dpid] = l.src.dpid
                    else:
                        shortest_path_hubs[l.dst.dpid] = shortest_path_hubs[l.dst.dpid]

                    if verbose == 1: print(
                        "\t\tdst dpid found in shortest_path. Count: " + str(shortest_path_hubs[l.dst.dpid]))
                elif l.src.dpid in shortest_path_hubs and l.dst.dpid not in shortest_path_hubs:
                    if verbose == 1: print("\t\tdst dpid not found bit src dpid found.")
                    shortest_path_hubs[l.dst.dpid] = shortest_path_hubs[l.src.dpid] + 1
                    shortest_path_node[l.dst.dpid] = l.src.dpid
            if verbose == 1:
                print ("shortest_path Hubs: " + str(shortest_path_hubs))
                print ("shortest_path Node: " + str(shortest_path_node))
            if s_temp in Fereng:
                Fereng.remove(s_temp)
            #min_val = min(Fereng)
            if verbose == 1: print ("Fereng out: " + str(Fereng))
            t_dpid = [k for k in Fereng if k not in visited]
            if verbose == 1: print ("Next possible dpids (t_dpid): " + str(t_dpid))

            if len(t_dpid) != 0:
                s_temp = t_dpid[t_dpid.index(min(t_dpid))]

            if verbose == 1: print "s_temp out: " + str(s_temp)
            if verbose == 1: print "visited out: " + str(visited) + "\n"
        return shortest_path_hubs, shortest_path_node

    """
    Find a path between src and dst based on the shorted path info which is stored on shortest_path_node
    """
    def find_path_from_topo(self,src_dpid, dst_dpid, shortest_path_node):
        path = []
        now_node = dst_dpid
        last_node = None
        while now_node != src_dpid:
            last_node = shortest_path_node.pop(now_node, None)
            if last_node != None:
                l = self.link_from_src_to_dst(now_node, last_node)
                if l is None:
                    print("Link between {0} and {1} was not found in topo.".format(now_node, last_node))
                else:
                    path.append(l)
                    now_node = last_node
            else:
                print "Path could not be found"
        return path
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
            if (l.src.dpid == in_dpid and l.src.port_no == in_port) or (
                            l.dst.dpid == in_dpid and l.src.port_no == in_port):
                return l
        return None
    """
    Returns a link object from src with dpid s to dest with dpid d.
    """
    def link_from_src_to_dst(self, s, d):
        for l in self.topo_raw_links:
            if l.src.dpid == s and l.dst.dpid == d:
                return l
        return None

    """
    Returns a link object that has in_dpid and in_port as source dpid and port.
    """
    def link_with_src_and_port(self, in_port, in_dpid):
        for l in self.topo_raw_links:
            if (l.src.dpid == in_dpid and l.src.port_no == in_port):
                return l
        return None

    """
    Returns a link object that has in_dpid and in_port as destination dpid and port.
    """
    def link_with_dst_and_port(self, in_port, in_dpid):
        for l in self.topo_raw_links:
            if (l.dst.dpid == in_dpid and l.dst.port_no == in_port):
                return l
        return None

    ########## Functions related to Spanning Tree Algorithm ##########
    def find_root_switch(self):
        pass