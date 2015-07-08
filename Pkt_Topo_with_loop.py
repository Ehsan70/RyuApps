__author__ = 'Ehsan'

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.cli import CLI

"""
Instructions to run the topo:
    1. Go to directory where this fil is.
    2. run: sudo -E python Pkt_Topo_with_loop.py
"""

class Simple3PktSwitch(Topo):
    """Simple topology example."""

    def __init__(self):
        """Create custom topo."""

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Adding switches
        p1 = self.addSwitch('p1', dpid="0000000000000001")
        p2 = self.addSwitch('p2', dpid="0000000000000002")
        p3 = self.addSwitch('p3', dpid="0000000000000003")
        p4 = self.addSwitch('p4', dpid="0000000000000004")

        # Add links
        self.addLink(h1, p1)
        self.addLink(h2, p2)
        self.addLink(h3, p3)
        self.addLink(h4, p4)

        self.addLink(p2, p4)
        self.addLink(p1, p2)
        self.addLink(p3, p4)
        self.addLink(p1, p3)


def run():
    c = RemoteController('c', '0.0.0.0', 6633)
    net = Mininet(topo=Simple3PktSwitch(), controller=None, autoSetMacs=True)
    net.addController(c)
    net.start()

    # installStaticFlows( net )
    CLI(net)
    net.stop()

# if the script is run directly (sudo custom/optical.py):
if __name__ == '__main__':
    setLogLevel('info')
    run()
