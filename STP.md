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

### Spanning tree

Spanning tree is a function that suppresses occurrence of broadcast streams in a network having a loop structure. Also, applying the original function that is preventing the loop, it is used as a means to secure network redundancy to automatically switch the path in case of a network failure.

With STP, Bridge Protocol Data Unit (BPDU) packets are exchanged between bridges to compare the bridge and port information and decide whether or not frame transfer of each port is available.

# Refrences
Ryu Github: https://github.com/osrg/ryu-book/blob/master/en/source/spanning_tree.rst 
