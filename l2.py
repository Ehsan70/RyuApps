

__author__ = 'Ehsan'

""" ryu.base.app_manager:
The central management of Ryu applications.
- Load Ryu applications
- Provide contexts to Ryu applications
- Route messages among Ryu applications
"""
from ryu.base import app_manager

"""ryu.controller.ofp_event:
OpenFlow event definitions.
"""
from ryu.controller import ofp_event

# Version negotiated and sent features-request message
from ryu.controller.handler import CONFIG_DISPATCHER

# Switch-features message received and sent set-config message
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

"""ryu.lib.packet:
Ryu packet library. Decoder/Encoder implementations of popular protocols like TCP/IP.
"""
from ryu.lib.packet import packet

from ryu.lib.mac import haddr_to_bin
import array

class L2Switch(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    """
    The controller sends a feature request to the switch upon session establishment.
    """
    def send_features_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    # The controller sends a get config request to query configuration parameters in the switch.
    def send_get_config_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPSwitchFeatures received: '
        'datapath_id=0x%016x n_buffers=%d '
        'n_tables=%d capabilities=0x%08x ports=%s',
        msg.datapath_id, msg.n_buffers, msg.n_tables,
        msg.capabilities, msg.ports)


    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    """
    This is called when Ryu receives an OpenFlow packet_in message. The trick is set_ev_cls decorator. This decorator
    tells Ryu when the decorated function should be called.

    Arguments of the decorator:
        1. The first argument of the decorator indicates an event that makes function called. As you expect easily, every time
        Ryu gets a packet_in message, this function is called.
        2. The second argument indicates the state of the switch. Probably, you want to ignore packet_in messages before the
        negotiation between Ryu and the switch finishes. Using MAIN_DISPATCHER as the second argument means this function
        is called only after the negotiation completes.
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        pkt = packet.Packet(array.array('B', ev.msg.data))
        for p in pkt.protocols:
            print p
        """
        object that represents a packet_in data structure
        """
        msg = ev.msg

        """
        object that represents a datapath (switch)
        """
        dp = msg.datapath

        """
        dp.ofproto and dp.ofproto_parser are objects that represent the OpenFlow protocol that Ryu and the
        switch negotiated
        """
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        """
        OFPActionOutput class is used with a packet_out message to specify a switch port that you want to send the
        packet out of. This application need a switch to send out of all the ports so OFPP_FLOOD constant is used
        """
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        """
        OFPPacketOut class is used to build a packet_out message
        """
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)

        """
        If you call Datapath class's send_msg method with a OpenFlow message class object, Ryu builds and send the
        on-wire data format to the switch.
        """
        dp.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)