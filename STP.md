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
 
 # 2. Create the topo
 
 The file STP_topo.py contains a 3 switch topo which create a loop.
 ```shell
 sudo -E python STP_topo.py
 ```
 
 # 3. Details
