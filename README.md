# RyuApps
Creates a simple Ryu app using the tutorials and then adds on to it. 

#Files

### Errors.md
This file contains some of the errors and problems I faced during the whole process. So it is worth it to have a look when you face any error.
I might have the solution there. 

### l2.py
This file is based on the [simple_switch_13.py](https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py) from [Ryu Github repo](https://github.com/osrg/ryu).
The file captures more events and OF messages.   

### STP.md
This file contains instructions on how to use Ryu app to perform Spanning Tree Protocol. 

### Simple_Ryu_App.md
This file contains instructions on controlling Pakcet network using simple Ryu app.

### Controller.py
This file has a shortest path function. In case of link failure, Dijikstra algorithm is ran and the new shortest path is then calculated. 

### ControllerSTP.py 
This file has additional funcitons which would run the Spanning Tree protocol. The code detects the loops and it breaks them. Also in case of topology change new paths are calculated. 

### LinearTopo.py
This file creates a topology of k switches, with one host per switch. The shape of the topology is linear. 

### Pkt_Topo_with_loop.py
This file creates a packet topology with a loop inside. 

### STP_topo.py
This file contains a topo with 3 switches connects in loop. It is used in `STM.md`. Each switch is connected to one host. 

### simple_switch_stp_13.py
This file was downloaded from this [link](https://github.com/osrg/ryu-book/blob/master/en/source/sources/simple_switch_stp_13.py). There are explanations in the following [link](http://osrg.github.io/ryu-book/en/html/spanning_tree.html#executing-the-ryu-application). The code contains comment which describe the code. The code illustartes the usage of Ryu STP library in applicaitons. I used this code and integrated it into Controller.py which made up the ControllerSTP.py 
