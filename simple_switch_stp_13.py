# coding=utf-8
"""
Note: s lot of the info is derived from the below link:
http://osrg.github.io/ryu-book/en/html/spanning_tree.html#executing-the-ryu-application
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
"""
stplib.py is a library that provides spanning tree functions such as BPDU packet exchange and management
of rules, and the status of each port.
"""
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

"""
The simple_switch_stp.py is an application program in which the spanning tree function is added to the
switching hub application using the spanning tree library.

Attention simple_switch_stp.py is an application dedicated to OpenFlow 1.0; this section describes
details of the application based on simple_switch_stp_13.py, which supports OpenFlow 1.3, indicated
in “Executing the Ryu Application ”.
"""
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    """
    A Ryu application that inherits ryu.base.app_manager.RyuApp starts other applications using separate threads
    by setting other Ryu applications in the “_CONTEXTS” dictionary. Here, the Stp class of the stplib library
    is set in “_CONTEXTS” in the name of ” stplib”.
    """
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        """
        When the STP library (Stp class instance) detects connection of an OpenFlow switch to the controller, a Bridge
        class instance and Port class instance are generated. After each class instance is generated and started,
            - Notification of the OpenFlow message reception from the Stp class instance
            - STP calculation of the Bridge class instance (loot bridge selection and selection of the role of each port)
            - Status change of the port of the Port class instance and send/receive of BPDU packets
        work together to achieve the spanning tree function.
        """
        self.stp = kwargs['stplib']

        """ Use this API if you want to set up configuration
             of each bridge(switch) and ports.
            Set configuration with 'config' parameter as follows.
             config = {<dpid>: {'bridge': {'priority': <value>,
                                           'sys_ext_id': <value>,
                                           'max_age': <value>,
                                           'hello_time': <value>,
                                           'fwd_delay': <value>}
                                'ports': {<port_no>: {'priority': <value>,
                                                      'path_cost': <value>,
                                                      'enable': <True/False>},
                                          <port_no>: {...},,,}}
                       <dpid>: {...},
                       <dpid>: {...},,,}
             NOTE: You may omit each field.
                    If omitted, a default value is set up.
                   It becomes effective when a bridge starts.
             Default values:
             ------------------------------------------------------------------
             | bridge | priority   | bpdu.DEFAULT_BRIDGE_PRIORITY -> 0x8000   | Bridge priority
             |        | sys_ext_id | 0                                        | Sets VLAN-ID
             |        | max_age    | bpdu.DEFAULT_MAX_AGE         -> 20[sec]  | Timer value to wait to receive BPDU packets
             |        | hello_time | bpdu.DEFAULT_HELLO_TIME      -> 2 [sec]  | Send intervals of BPDU packets
             |        | fwd_delay  | bpdu.DEFAULT_FORWARD_DELAY   -> 15[sec]  | Period that each port stays in LISTEN or LEARN status
             |--------|------------|------------------------------------------|
             | port   | priority   | bpdu.DEFAULT_PORT_PRIORITY -> 0x80       | Port priority
             |        | path_cost  | (Set up automatically                    | Link cost value
             |        |            |   according to link speed.)              |
             |        | enable     | True                                     | Port enable/disable setting
             ------------------------------------------------------------------
        """
        """
        Use the set_config() method of the STP library to set configuration. Here, the following values are set as a sample.

        OpenFlow switch	        Item	            Setting
        dpid=0000000000000001	bridge.priority	    0x8000
        dpid=0000000000000002	bridge.priority	    0x9000
        dpid=0000000000000003	bridge.priority	    0xa000

        Using these settings, the bridge ID of the dpid=0000000000000001 OpenFlow switch is always the smallest
        value and is selected as the root bridge.
        """
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                     {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                     {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                     {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    """
    Deletes a specific flow from a given datapath
    """
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

    """
    By using the stplib.EventPacketIn event defined in the STP library, it is possible to receive packets other
    than BPDU packets
    """
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

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
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    """
    The change notification event (stplib.EventTopologyChange) of the network topology is received and the learned
    MAC address and registered flow entry are initialized.
    """
    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]
    """
    The change notification event (stplib.EventPortStateChange) of the port status is received and the debug log
    of the port status is output.
    """
    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])
