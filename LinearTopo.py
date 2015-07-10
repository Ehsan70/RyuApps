__author__ = 'Ehsan'
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
class LinearTopo(Topo):
    "Linear topology of k switches, with one host per switch."
    def __init__(self, k=2, **opts):
        """Init.
        k: number of switches (and hosts)
        hconf: host configuration options
        lconf: link configuration options"""
        super(LinearTopo, self).__init__(**opts)
        self.k = k
        lastSwitch = None
        for i in irange(1, k):
            host = self.addHost('h%s' % i, cpu=.5/k)
            switch = self.addSwitch('s%s' % i)
            # 10 Mbps, 5ms delay, 1% loss, 1000 packet queue
            self.addLink( host, switch, bw=10, delay='5ms', loss=1, max_queue_size=1000, use_htb=True)
            if lastSwitch:
                self.addLink(switch, lastSwitch, bw=10, delay='5ms', loss=1, max_queue_size=1000, use_htb=True)
            lastSwitch = switch
def build():
    topo = LinearTopo(k=4)
    c = RemoteController('c', '0.0.0.0', 6633)
    net = Mininet(topo=topo, controller=None, link=TCLink, autoSetMacs=True)
    net.addController(c)
    net.start()

    # installStaticFlows( net )
    CLI(net)
    net.stop()

def perfTest():
    "Create network and run simple performance test"
    topo = LinearTopo(k=4)
    c = RemoteController('c', '0.0.0.0', 6633)
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=None)
    net.addController(c)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    print "Testing bandwidth between h1 and h4"
    h1, h4 = net.get('h1', 'h4')
    net.iperf((h1, h4))
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    # you could either run build() or perfTest() here.
    build()