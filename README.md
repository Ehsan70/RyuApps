             It seems the repo is getting some popularity please let me know if you have any questions. 
             You can contact me via email at a.ehsan70@gmail.com
             
             I have limited time on maintaing this repo. So feel free to create pull requests and add to this repo. Even documenting the 
             errors you had to deal with would be usefull.


# RyuApps
Creates a simple Ryu app using the tutorials and then adds on to it. 

# How topology discovery works?
In order to answer that question read the following [page](http://vlkan.com/blog/post/2013/08/06/sdn-discovery/). 

# Files


### BasicTopoLearner.py
This includes the bone structure of the topology learning mechanisim. It doesn't have any special data structure so it is easier to follow the code. 

### Controller.py
This file has a shortest path function. In case of link failure, Dijikstra algorithm is ran and the new shortest path is then calculated. 

### ControllerAdvanced-ARPandRest.py
This controller has the features explained for `ControllerAdvanced-ARPhandling.py` and `ControllerAdvanced-REST.py` in one file. 

### ControllerAdvanced-ARPhandling.py	
This controller is able to respond to ARP requests. For examle, if A sends a ARP request to B and controller has learned the host B (knows the IP address and MAC address) then controller responds to that ARP as if B is responding. 

### ControllerAdvanced-REST.py
This controller has a WSGI server running as well which responds to http REST api requests.

### ControllerAdvanced.py

### ControllerSTP.py 
This file has additional funcitons which would run the Spanning Tree protocol. The code detects the loops and it breaks them. Also in case of topology change new paths are calculated. 

### Errors.md
This file contains some of the errors and problems I faced during the whole process. So it is worth it to have a look when you face any error.
I might have the solution there. 

### LinearTopo.py
This file creates a topology of k switches, with one host per switch. The shape of the topology is linear. 

### Pkt_Topo_with_loop.py
This file creates a packet topology with a loop inside. 

### STP.md
This file contains instructions on how to use Ryu app to perform Spanning Tree Protocol. 

### STP_pkt_topo.py
This file contains a topo with 3 switches connects in loop. It is used in `STM.md`. Each switch is connected to one host. 

### Simple_Ryu_App.md
This file contains instructions on controlling Pakcet network using simple Ryu app.

### Pkt_Topo_with_loop_taps.py
A  mininet custom topo with taps and arranged in loop.

### TopoDiscoveryInRyu.md
This file contains explanations on how to perform topology discovery in RYU.

### Using_Controller_with_ARP_REST.md
This document contains instructions on how to use `ControllerAdvanced-ARPandRest.py` file.

### l2.py
This file is based on the [simple_switch_13.py](https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py) from [Ryu Github repo](https://github.com/osrg/ryu).
The file captures more events and OF messages.   


### simple_switch_stp_13.py
This file was downloaded from this [link](https://github.com/osrg/ryu-book/blob/master/en/source/sources/simple_switch_stp_13.py). There are explanations in the following [link](http://osrg.github.io/ryu-book/en/html/spanning_tree.html#executing-the-ryu-application). The code contains comment which describe the code. The code illustartes the usage of Ryu STP library in applicaitons. I used this code and integrated it into Controller.py which made up the ControllerSTP.py 

### resources dir

This directory copntains images which are used in the tutorials. 
