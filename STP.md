<b>Goal</b>: This section describes how to use spanning tree of Ryu. 

<b>Requirements:</b>
A basic knowlege of Ryu, STP and OpenFlow is required. 

<b>Dependencies</b>: This tutorial uses the following: 
- [simple_switch_stp_13.py](https://github.com/Ehsan70/RyuApps/blob/master/simple_switch_stp_13.py)
- [spanning_tree.py](https://github.com/Ehsan70/RyuApps/blob/master/spanning_tree.py)

<b>Environment: </b> I have used the VM from sdn hub, I recommond you do the same. Link for installation is provided below: http://sdnhub.org/tutorials/sdn-tutorial-vm/

<b>Road Map: </b>This document has three sections for setup: 

 1. Run STP controller
 2. Create the topo
 3. Details
 
# 1. Run STP controller
 
 From the repo exceute the following in the command line: 
 ```shell
 ryu-manager ./simple_switch_stp_13.py
 ```
 Note that when every thing is up after couple of seconds each port should eventually become FORWARD state or BLOCK state. When this happen all the ping can make it to the destination with out being droped. 
 
# 2. Create the topo
 
 The file STP_topo.py contains a 3 switch topo which create a loop.
 ```shell
 sudo -E python STP_topo.py
 ```
 
# 3. Details
Note most of the information of this section are extracted from the sources in reference section. 
I  really recommand watching these two youtube videos: </br>
1. [STP Exercise](https://www.youtube.com/watch?v=y-SppCHx1Qs) </br>
2. [CCNA3 - Part 5 - Spanning Tree Protocol STP](https://www.youtube.com/watch?v=ihF_78oIaDI)

### Spanning Tree Explanation

Spanning tree is a function that suppresses occurrence of broadcast streams in a network having a loop structure. Also, applying the original function that is preventing the loop, it is used as a means to secure network redundancy to automatically switch the path in case of a network failure.

With STP, Bridge Protocol Data Unit (BPDU) packets are exchanged between bridges to compare the bridge and port information and decide whether or not frame transfer of each port is available.

### Spanning Tree Algorithm
With STP, Bridge Protocol Data Unit (BPDU) packets are exchanged between bridges to compare the bridge and port information and decide whether or not frame transfer of each port is available.

###### 1. Selecting the root bridge
The bridge having the smallest bridge ID is selected as the root bridge through BPDU packet exchange between bridges. After that, only the root bridge sends the original BPDU packet and other bridges transfer BPDU packets received from the root bridge.
> The bridge ID is calculated through a combination of the bridge priority set for each bridge and the MAC address of the specific port.


> Upper 2byte     |  	Lower 6byte
>  ---------------|------------------
> Bridge priority	|   MAC address


###### 2. Deciding the role of ports
Based on the cost of each port to reach the root bridge, decide the role of the ports.
1. Root port: The port having the smallest cost among bridges to reach the root bridge. This port receives BPDU packets from the root bridge.
2. Designated ports: Ports at the side having the small cost to reach the root bridge of each link. These ports sends BPDU packets received from the root bridge. Root bridge ports are all designated ports.
3. Non designated ports: Ports other than the root port and designated port. These ports suppress frame transfer.

> The cost to reach the root bridge is compared as follows based on the setting value of the BPDU packet received by each port. <br/>
> Priority 1: Compares by the root path cost value. When each bridge transfers a BPDU packet, the path cost value set for the output port is added to the root path cost value of the BPDU packet. Because of this, the root path cost value is the total value of the path cost value of each link passed through to reach the root bridge.<br/>
> Priority 2: When the root path cost is the same, compares using the bridge ID of the counterpart bridges.<br/>
> Priority 3: When the bridge ID of the counterpart bridges are the same (in cases in which each port is connected to the same bridge), compare using the port ID of the counterpart ports.<br/>
> Port ID:

> Upper 2byte     |  	Lower 6byte
>  ---------------|------------------
> Port priority	  |   Port number

###### 3. Port state change
After the port role is decided (STP calculation is completed), each port becomes LISTEN state. After that, the state changes as shown below and according to the role of each port, it eventually becomes FORWARD state or BLOCK state. Ports set as disabled ports in the configuration become DISABLE state and after that the change of state does not take place.

Each port decides operations such as frame transfer availability according to the state.


State          |  Operation
---------------|------------------
DISABLE       	|  Disabled port. Ignores all received packets
BLOCK	         |  Receives BPDU only
LISTEN       	 |  Sends and receives BPDU
LEARN       	  |  Sends and receives BPDU, learns MAC
FORWARD	       |  Sends and receives BPDU, learns MAC, transfers frames

# Refrences
Ryu Github: https://github.com/osrg/ryu-book/blob/master/en/source/spanning_tree.rst 
