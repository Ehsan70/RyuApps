from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.link import Link, Intf
from mininet.cli import CLI

class NullIntf( Intf ):
    "A dummy interface with a blank name that doesn't do any configuration"
    def __init__( self, name, **params ):
        self.name = ''
        self.node ="alaki"

class NullLink( Link ):
    "A dummy link that doesn't touch either interface"
    def makeIntfPair( cls, intf1, intf2, *args, **kwargs ):
        pass
    def delete( self ):
        pass

class ThreePktTopoScratch(Topo):
    def addIntf( self, switch, intfName ):
        "Add intf intfName to switch"
        self.addLink( switch, switch, cls=NullLink,
                      intfName1=intfName, cls2=NullIntf )
    def __init__(self):

        self.NUM_OF_HOSTS = 3 # number of hosts
        self.NUM_OF_PKT_SW = 3 # number of packet swiches 
        self.NUM_OF_OPT_SW = 3 # number of optical swiches 

        # Initialize topology
        Topo.__init__(self)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')

        
        opts =dict(protocols='OpenFlow13')

        # Adding switches
        p1 = self.addSwitch('p1', dpid="0000ffff00000001",opts=opts)
        p2 = self.addSwitch('p2', dpid="0000ffff00000002",opts=opts)
        p3 = self.addSwitch('p3', dpid="0000ffff00000003",opts=opts)

        # Add links from hosts to OVS
        self.addLink(p1, h1)
        self.addLink(p2, h2)
        self.addLink(p3, h3)

        # addding switches to gether
        self.addLink(p2,p3)
        self.addLink(p2,p1)

        # add links from ovs to linc-oe
    	self.addIntf(p1,'tap1')
    	self.addIntf(p2,'tap2')
    	self.addIntf(p3,'tap3')


        # if you use, sudo mn --custom custom/optical.py, then register the topo:
topos = {'optical': ( lambda: ThreePktTopoScratch() )}

def run():
    c = RemoteController('c','0.0.0.0',6633)
    net = Mininet( topo=ThreePktTopoScratch(),controller=None,autoSetMacs=True)
    net.addController(c)
    net.start()

    #installStaticFlows( net )
    CLI( net )
    net.stop()

# if the script is run directly (sudo custom/optical.py):
if __name__ == '__main__':
    setLogLevel('info')
    run()