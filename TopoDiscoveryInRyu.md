<b>Goal</b>: This tutorial explains functions needed to perform topo discovery on Ryu. 
Also Some detailed explanations on how `get_switch()` and `get_link()` fucntions work.  


<b>Requirements:</b>
A basic knowlege of Ryu, OpenFlow and linux CLI is required. 

<b>Environment: </b> I have used the VM from sdn hub, I recommond you do the same. Link for installation is provided below: http://sdnhub.org/tutorials/sdn-tutorial-vm/

# Controller with Topo Learning Feature
Your controller should be able to remeber the topo. 
In order to get a topology of your network you need to use two funtions in the [`api.py`](https://github.com/osrg/ryu/blob/master/ryu/topology/api.py).
The two functions have the following signature: 
1. get_switch(app, dpid=None)
2. get_link(app, dpid=None)

By calling them you would get the topology that is currently known to he controller. I would put the two in funtions where a 
switch might enter or leave the topo. Have a look at this section of the code: 

```python
    # ...
    
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        # The Function get_switch(self, None) outputs the list of switches.
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))
        
        # ... rest of the code
```
The function `handler_switch_enter(self, ev)` is a handler for event `EventSwitchEnter`. `set_ev_cls` says use `handler_switch_enter` 
as a handler for event `EventSwitchEnter`. So when ever a switch enters the topo this function is called. 

### Code
You could also have the exact same code in `BasicTopoLearner.py` in this repo. 
```python
__author__ = 'Ehsan'

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.topology import event
# Below is the library used for topo discovery
from ryu.topology.api import get_switch, get_link
import copy

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # USed for learning switch functioning
        self.mac_to_port = {}
        # Holds the topology data and structure
        self.topo_raw_switches = []
        self.topo_raw_links = []


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

    # We are not using this function
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

        # self.logger.info("\tpacket in %s %s %s %s", dpid, src, dst, in_port)

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
        # The Function get_switch(self, None) outputs the list of switches.
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))

        """
        Now you have saved the links and switches of the topo. So you could do all sort of stuf with them. 
        """

        print(" \t" + "Current Links:")
        for l in self.topo_raw_links:
            print (" \t\t" + str(l))

        print(" \t" + "Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t" + str(s))

    """
    This event is fired when a switch leaves the topo. i.e. fails.
    """
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")
```

# Network Topo for Mininet 
Here is the python code that would create mininet topo. Note that the topo has a loop in, therefor none of the pings would work. 
You need to have spanning tree protocol running which breaks the loops in the network. However, 
in case of link down the controller is able to correctly detect and update its structure. 
> If you want know more about loops and STP in the network see [STP.md tutorial](https://github.com/Ehsan70/RyuApps/blob/master/STP.md).

```python
__author__ = 'Ehsan'
from mininet.node import CPULimitedHost
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
"""
Instructions to run the topo:
    1. Go to directory where this fil is.
    2. run: sudo -E python Pkt_Topo_with_loop.py
"""
class Simple3PktSwitch(Topo):
    """Simple topology example."""

    def __init__(self, **opts):
        """Create custom topo."""

        # Initialize topology
        super(Simple3PktSwitch, self).__init__(**opts)
        #Topo.__init__(self)

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        opts = dict(protocols='OpenFlow13')

        # Adding switches
        s1 = self.addSwitch('s1', dpid="0000000000000001")
        s2 = self.addSwitch('s2', dpid="0000000000000002")
        s3 = self.addSwitch('s3', dpid="0000000000000003")
        s4 = self.addSwitch('s4', dpid="0000000000000004")

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s4)

        self.addLink(s2, s4)
        self.addLink(s2, s3)
        self.addLink(s1, s2)
        self.addLink(s3, s4)
        self.addLink(s1, s3)


def installStaticFlows(net):
    for sw in net.switches:
        info('Adding flows to %s...' % sw.name)
        sw.dpctl('add-flow', 'in_port=1,actions=output=2')
        sw.dpctl('add-flow', 'in_port=2,actions=output=1')
        info(sw.dpctl('dump-flows'))


def run():
    c = RemoteController('c', '0.0.0.0', 6633)
    net = Mininet(topo=Simple3PktSwitch(), host=CPULimitedHost, controller=None)
    net.addController(c)
    net.start()

    # installStaticFlows( net )
    CLI(net)
    net.stop()

# if the script is run directly (sudo custom/optical.py):
if __name__ == '__main__':
    setLogLevel('info')
    run()

```
# Let's run it
Open two terminal windows. One for mininet and one for controller. 

## Run controller
Go to the location where you clones this repo. Run these:
 1. `pwd` -> To help you locate the repo
 2. `sudo ryu-manager --observe-links ~/code/RyuApp/BasicTopoLearner.py ` -> Runs the Ryu controller

> Note that you could run `sudo ryu-manager --verbose --observe-links ~/code/RyuApp/BasicTopoLearner.py ` 
for debug messages. However, you will see a lot of messages in your console.  

I receive the following output from above commands: 
```shell
ubuntu@sdnhubvm:~/pox/pox/forwarding[11:14] (eel)$ pwd
/home/ubuntu/pox/pox/forwarding
ubuntu@sdnhubvm:~/pox/pox/forwarding[11:14] (eel)$ sudo ryu-manager --observe-links ~/code/RyuApp/BasicTopoLearner.py 
loading app /home/ubuntu/code/RyuApp/BasicTopoLearner.py
loading app ryu.topology.switches
loading app ryu.controller.ofp_handler
instantiating app ryu.topology.switches of Switches
instantiating app ryu.controller.ofp_handler of OFPHandler
instantiating app /home/ubuntu/code/RyuApp/BasicTopoLearner.py of SimpleSwitch13

```
## Runing Mininet topo
Go to the location where you clones this repo. Run these:
 1. `pwd` -> To help you locate the repo
 2. `sudo mn -c` -> clean the mininet before start it again. Always do this.
 3. `sudo -E python Pkt_Topo_with_loop.py ` -> start the topo

I receive the following output from above commands: 
```shell
KeyboardInterrupt
ubuntu@sdnhubvm:~/code/RyuApp[11:06] (master)$ pwd
/home/ubuntu/code/RyuApp
ubuntu@sdnhubvm:~/code/RyuApp[11:11] (master)$ sudo mn -c
*** Removing excess controllers/ofprotocols/ofdatapaths/pings/noxes
killall controller ofprotocol ofdatapath ping nox_core lt-nox_core ovs-openflowd ovs-controller udpbwtest mnexec ivs 2> /dev/null
killall -9 controller ofprotocol ofdatapath ping nox_core lt-nox_core ovs-openflowd ovs-controller udpbwtest mnexec ivs 2> /dev/null
pkill -9 -f "sudo mnexec"
*** Removing junk from /tmp
rm -f /tmp/vconn* /tmp/vlogs* /tmp/*.out /tmp/*.log
*** Removing old X11 tunnels
*** Removing excess kernel datapaths
ps ax | egrep -o 'dp[0-9]+' | sed 's/dp/nl:/'
***  Removing OVS datapaths
ovs-vsctl --timeout=1 list-br
ovs-vsctl --timeout=1 list-br
*** Removing all links of the pattern foo-ethX
ip link show | egrep -o '([-_.[:alnum:]]+-eth[[:digit:]]+)'
ip link show
*** Killing stale mininet node processes
pkill -9 -f mininet:
*** Shutting down stale tunnels
pkill -9 -f Tunnel=Ethernet
pkill -9 -f .ssh/mn
rm -f ~/.ssh/mn/*
*** Cleanup complete.
ubuntu@sdnhubvm:~/code/RyuApp[11:11] (master)$ sudo -E python Pkt_Topo_with_loop.py 
*** Creating network
*** Adding hosts:
h1 h2 h3 h4 
*** Adding switches:
s1 s2 s3 s4 
*** Adding links:
(h1, s1) (h2, s2) (h3, s3) (h4, s4) (s1, s2) (s1, s3) (s2, s3) (s2, s4) (s3, s4) 
*** Configuring hosts
h1 (cfs -1/100000us) h2 (cfs -1/100000us) h3 (cfs -1/100000us) h4 (cfs -1/100000us) 
*** Starting controller
c 
*** Starting 4 switches
s1 s2 s3 s4 ...
*** Starting CLI:
mininet> 
```

As soon as you run the mininet topo you should receive some messages on the Ryu. Here is the last two prints of what I got: 
```
 	Current Links:
 		Link: Port<dpid=4, port_no=3, LIVE> to Port<dpid=3, port_no=3, LIVE>
 		Link: Port<dpid=2, port_no=3, LIVE> to Port<dpid=3, port_no=2, LIVE>
 		Link: Port<dpid=3, port_no=2, LIVE> to Port<dpid=2, port_no=3, LIVE>
 		Link: Port<dpid=2, port_no=4, LIVE> to Port<dpid=1, port_no=2, LIVE>
 		Link: Port<dpid=1, port_no=3, LIVE> to Port<dpid=3, port_no=4, LIVE>
 		Link: Port<dpid=3, port_no=4, LIVE> to Port<dpid=1, port_no=3, LIVE>
 		Link: Port<dpid=3, port_no=3, LIVE> to Port<dpid=4, port_no=3, LIVE>
 		Link: Port<dpid=4, port_no=2, LIVE> to Port<dpid=2, port_no=2, LIVE>
 		Link: Port<dpid=1, port_no=2, LIVE> to Port<dpid=2, port_no=4, LIVE>
 		Link: Port<dpid=2, port_no=2, LIVE> to Port<dpid=4, port_no=2, LIVE>
 	Current Switches:
 		Switch<dpid=1, Port<dpid=1, port_no=1, DOWN> Port<dpid=1, port_no=2, LIVE> Port<dpid=1, port_no=3, LIVE> >
 		Switch<dpid=2, Port<dpid=2, port_no=1, LIVE> Port<dpid=2, port_no=2, LIVE> Port<dpid=2, port_no=3, LIVE> Port<dpid=2, port_no=4, LIVE> >
 		Switch<dpid=3, Port<dpid=3, port_no=1, LIVE> Port<dpid=3, port_no=2, LIVE> Port<dpid=3, port_no=3, LIVE> Port<dpid=3, port_no=4, LIVE> >
 		Switch<dpid=4, Port<dpid=4, port_no=1, LIVE> Port<dpid=4, port_no=2, LIVE> Port<dpid=4, port_no=3, LIVE> >
```
> Note that you there are 5 links between the switches in the topo yet the outputs show 10. This is because all the edges one directed so inorder to have packets following both directions it needs two edges.
> Example: s1 is connected to s2. There is one directed edge going from `s1` to `s2` and one from `s2` to `s1`. 


# Possible additions to the code: 
Note that the topology is learned only when switches join. What if a link goes down ? To keep track to topo in case of link failures 
you need to keep to track of the links that went down. Have a look at [`Controller.py`](https://github.com/Ehsan70/RyuApps/blob/master/Controller.py). The `Controller.py` contains funcitons that would keep track of failures. It also has a specific data structure for topology which keeps a record of links and switches while contains some useful function.  


# Details of get_switch() and get_link()
The two functions are defined in the [api.py](https://github.com/osrg/ryu/blob/master/ryu/topology/api.py). Their implementation is :

```python 
def get_switch(app, dpid=None):
    rep = app.send_request(event.EventSwitchRequest(dpid))
    return rep.switches

def get_link(app, dpid=None):
    rep = app.send_request(event.EventLinkRequest(dpid))
    return rep.links
```

As you can see, `get_switch()` method calls `EventSwitchRequest` event. The `EventSwitchRequest` and `EventLinkRequest` are defined in [event.py](https://github.com/osrg/ryu/blob/master/ryu/topology/event.py).
After that, `switch_requrest_handler()` in [`switches.py`](https://github.com/osrg/ryu/blob/master/ryu/topology/switches.py) is called and sends the response to the caller. In other words, the caller thread sends
`EventSwitchRequest` then Ryu finds a thread that interested in `EventSwitchRequest` and delivers it to the thread. The thread sends `EventSwitchReply` to the caller.
So to make it short, the actually learning of the topology is done in [`switches.py`](https://github.com/osrg/ryu/blob/master/ryu/topology/switches.py). For example links arelearned in the following [ packet_in_handler(self, ev)](https://github.com/osrg/ryu/blob/master/ryu/topology/switches.py#L682) of `switches.py`. When a packet commes to the switches, the switch does not know what to do with it. So, it sends and `PacketIn` message to controller which also contains the original message that was received by switch. When PacketIn message is received the event `ofp_event.EventOFPPacketIn` is fired. When the event is fired, the handler of that event is called . In this case, it is `packet_in_handler()`. In the `packet_in_handler`, the message is unmarshaled and some info is extracted. Since the message has the source and destination the controller can use that to figure out the links in the topology. 

Have a look at this section of the code: 

```python 
        msg = ev.msg
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
        except LLDPPacket.LLDPUnknownFormat as e:
            return

        dst_dpid = msg.datapath.id
        
        # ...
        
        src = self._get_port(src_dpid, src_port_no)
        if not src or src.dpid == dst_dpid:
            return
        try:
            self.ports.lldp_received(src)
        except KeyError:
            pass

        dst = self._get_port(dst_dpid, dst_port_no)
        if not dst:
            return

        # ... 

        link = Link(src, dst)
        if link not in self.links:
            self.send_event_to_observers(event.EventLinkAdd(link))

        # ... rest of the code 
```
As you can see, the `msg` is extracted from the packet. Then `src_dpid`, `src_port_no and` and `dst_dpid` are extracted from the message. Under some conditions if a Link is added, a Link object is created using `link = Link(src, dst)` and the event `EventLinkAdd` is fire. Find `EventLinkDelete` event in the code and study it.


# Sources: 
[Forum](http://sourceforge.net/p/ryu/mailman/message/32587410/) 

[Topology Discovery with Ryu](http://sdn-lab.com/2014/12/31/topology-discovery-with-ryu/)
