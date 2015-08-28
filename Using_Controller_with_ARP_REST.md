<b>Goal</b>: Seting up RYU app which has the following features.
 1. Host Discovery (IP layer Discovery)
    - The controller needs to know where are the host are connected
 2. Switch and Link Discovery (Layer 2 Discovery)
    - The controller should know the physical links presented in the network
 3. Link Failure Detection
    - In case of failure, need to know which link failed.
 4. Shortest Path Calculation / Link Protection
    - Should calculate the path between two hosts
 5. ARP handling
 6. A small REST interface


<b>Requirements:</b>
A basic knowlege of SDN, OpenFlow, ARP, REST api, and linux CLI is required. 

<b>Environment: </b> I have used the VM from sdn hub, I recommond you do the same. Link for installation is provided below: http://sdnhub.org/tutorials/sdn-tutorial-vm/


<b>Notations: </b>
 - `>` means the linuc command line <br>
 - `mininet>` means the mininet command line

<b>Road Map: </b>This document has two sections for setup: 

 1. setting up the controller 
 2. setting up the topo
 
# 1. setting up/running the iControl #
Run the Ryu controller using the following command. 
```shell
> sudo ryu-manager  --observe-links ~/code/RyuApp/ControllerAdvanced-ARPandRest.py
```

# 2. Run a simple Mininet network #
You could either use the custom 3 switch topology or used the prefined topo created by mininet. 

## a. Custom topo
```shell
> sudo -E python Pkt_Topo_with_loop.py
```

## b. Predefined Topo
```shell
> sudo mn --topo torus,3,3 --controller remote,ip=127.0.0.1
```
This is the topology created by this command: 
![Alt text](resources/TorusTopo.PNG?raw=true  "Topology created by mn --topo torus,3,3 ")

# Some experiments:

Do a pingall on mininet console. You would see that most of the pings would fail.  
When the pingall is done, try it again. Interestingly, all of them pass. 
The first ping was used to learn topology pf the hosts and switches. Flows are installed into the switches after the first ping.



