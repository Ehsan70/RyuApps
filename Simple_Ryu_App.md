<b>Goal</b>: Controlling Pakcet network using simple Ryu app. 

<b>Requirements:</b>
A basic knowlege of Ryu and OpenFlow is required. 

<b>Dependencies</b>: This tutorial only uses `l2.py` from the repo.

<b>Environment: </b> I have used the VM from sdn hub, I recommond you do the same. Link for installation is provided below: http://sdnhub.org/tutorials/sdn-tutorial-vm/

<b>Road Map: </b>This document has three sections for setup: 

 1. Setup 
 2. Doing tests </br>
 3. Details on the code

<b>Notations: </b>
 - `>` means the linuc command line <br>
 - `mininet>` means the mininet command line
 
# 1. Setup
 
### a. Run Ryu
Clone this repo. 
```shell
> sudo ryu-manager --verbose --observe-links <Address of l2.py>
```
In my case it is: 
```shell
> sudo ryu-manager --verbose --observe-links ~/code/RyuApp/l2.py
```
### b. Run a simple Mininet network
I'm just using 
```shell
> sudo mn --controller=remote --topo linear,2
```

# 2. Doing some Tests
### Do a pingall
```shell
mininet> pingall
```
You would see of PacketIn messages received on the Ryu terminal. </br>
Because the controller acts as a learning switch it should not fail any of the pings. 
```
mininet> pingall
*** Ping: testing ping reachability
h1 -> h2 
h2 -> h1 
*** Results: 0% dropped (2/2 received)
```
### Fail a link
In mininet run: 
```
link s1 s2 down
```
The above would bring down the link from switch `s1` to switch `s2`. 

</br>You should see some events fired up on the Ryu terminal. 
```
EVENT ofp_event->L2Switch EventOFPPortStatus
	port modified 2
	[Ehsan] Sending send_port_desc_stats_request to datapath id : 0000000000000002
EVENT ofp_event->L2Switch EventOFPPortDescStatsReply
	 port_no=4294967294 hw_addr=fe:75:73:1f:94:4a name=s1 config=0x00000001 
 	 state=0x00000001 curr=0x00000000 advertised=0x00000000 
 	 supported=0x00000000 peer=0x00000000 curr_speed=0 max_speed=0
	 port_no=1 hw_addr=aa:ed:0d:e1:28:89 name=s1-eth1 config=0x00000000 
 	 state=0x00000000 curr=0x00000840 advertised=0x00000000 
 	 supported=0x00000000 peer=0x00000000 curr_speed=10000000 max_speed=0
	 port_no=2 hw_addr=e2:62:5d:b2:dd:38 name=s1-eth2 config=0x00000001 
 	 state=0x00000001 curr=0x00000840 advertised=0x00000000 
 	 supported=0x00000000 peer=0x00000000 curr_speed=10000000 max_speed=0
```
When the link goes down, an `OFPPortStatus` is send to the controller which causes the event `EventOFPPortStatus` to fire. 
The event is handled by function `_port_status_handler` which is epicted below. The message contains a reason field which when a 
link goes down it is set to `ofproto.OFPPR_MODIFY`; meaning port is modified. 
Note that I have removed some of the comments for ease. 
```python
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("\tport added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("\tport deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("\tport modified %s", port_no)
            dp_str = dpid_lib.dpid_to_str(dp.id)
            self.logger.info("\t[Ehsan] Sending send_port_desc_stats_request to datapath id : " + dp_str)
            self.send_port_desc_stats_request(dp)
        else:
            self.logger.info("\tIlleagal port state %s %s", port_no, reason)
```
As you can see in the above code, when a change in a port is modified I immidietly send a `send_port_desc_stats_request` to the switch
with the same datapath id (dpid) to get more information regarding the port.

Switches responds to my request with Port description reply message which upon recieve on controller side `EventOFPPortDescStatsReply` is fired.
That event is handled by `port_desc_stats_reply_handler`. The handler is epicted below with no comment (See the `l2.py` for more comments). 
 ```python
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        for p in ev.msg.body:
            self.logger.info("\t port_no=%d hw_addr=%s name=%s config=0x%08x "
                             "\n \t state=0x%08x curr=0x%08x advertised=0x%08x "
                             "\n \t supported=0x%08x peer=0x%08x curr_speed=%d "
                             "max_speed=%d" %
                             (p.port_no, p.hw_addr,
                              p.name, p.config,
                              p.state, p.curr, p.advertised,
                              p.supported, p.peer, p.curr_speed,
                              p.max_speed))
 ```
 
## Details on code
 
In Ryu you receive Events which coresspond to OF messages and then you would have to define handlers for these events. For example in the below code, the `set_ev_cls` is saying use function `switch_features_handler()` as a handler for event `EventOFPSwitchFeatures`. 

```python
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) # See part 1
    def switch_features_handler(self, ev):
        self.logger.info("[Ehsan] Received EventOFPSwitchFeatures")
        msg = ev.msg
        self.logger.info('OFPSwitchFeatures received: '
                         '\n\tdatapath_id=0x%016x n_buffers=%d '
                         '\n\tn_tables=%d auxiliary_id=%d '
                         '\n\tcapabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)
	
	# See part 2
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
```
#### part 1
To be more precise, the arguments of `set_ev_cls` are: 
 1. The first argument of the decorator indicates an event that makes function called. As you expect easily, every time Ryu gets a EventOFPSwitchFeatures message, this function is called.
 2. The second argument indicates the state of the switch. For example, if you want to ignore EventOFPSwitchFeatures messages before the negotiation between Ryu and the switch finishes, use MAIN_DISPATCHER. Using MAIN_DISPATCHER means this function is called only after the negotiation completes.
 

The seconf argument can have 4 values: 

Definition				    |	Explanation
--------------------------------------------|-------------------------------------------
ryu.controller.handler.HANDSHAKE_DISPATCHER |	Exchange of HELLO message
ryu.controller.handler.CONFIG_DISPATCHER    |	Waiting to receive SwitchFeatures message
ryu.controller.handler.MAIN_DISPATCHER	    |	Normal status
ryu.controller.handler.DEAD_DISPATCHER	    |	Disconnection of connection
 
#### part2
In `ev.msg`, the instance of the OpenFlow message class corresponding to the event is stored. In this case, it is `ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures`.

In `msg.datapath`, the instance of the `ryu.controller.controller.Datapath` class corresponding to the OpenFlow switch that issued this message is stored.


##References: 
http://osrg.github.io/ryu-book/en/html/switching_hub.html#ch-switching-hub 
