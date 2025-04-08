#!/usr/bin/env python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


class CustomTopo(Topo):

    def build(self):

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Add hosts and connect them to switches
        # For S1
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        self.addLink(h1, s1, bw=10, delay='1ms')
        self.addLink(h2, s1, bw=10, delay='1ms')
        self.addLink(h3, s1, bw=10, delay='1ms')
        self.addLink(h4, s1, bw=10, delay='1ms')

        # For S2
        h5 = self.addHost('h5', ip='10.0.0.5/24')
        h6 = self.addHost('h6', ip='10.0.0.6/24')
        h7 = self.addHost('h7', ip='10.0.0.7/24')
        h8 = self.addHost('h8', ip='10.0.0.8/24')
        self.addLink(h5, s2, bw=10, delay='1ms')
        self.addLink(h6, s2, bw=10, delay='1ms')
        self.addLink(h7, s2, bw=10, delay='1ms')
        self.addLink(h8, s2, bw=10, delay='1ms')

        # For S3
        h9 = self.addHost('h9', ip='10.0.0.9/24')
        h10 = self.addHost('h10', ip='10.0.0.10/24')
        h11 = self.addHost('h11', ip='10.0.0.11/24')
        h12 = self.addHost('h12', ip='10.0.0.12/24')
        self.addLink(h9, s3, bw=10, delay='1ms')
        self.addLink(h10, s3, bw=10, delay='1ms')
        self.addLink(h11, s3, bw=10, delay='1ms')
        self.addLink(h12, s3, bw=10, delay='1ms')

        # For S4
        h13 = self.addHost('h13', ip='10.0.0.13/24')
        h14 = self.addHost('h14', ip='10.0.0.14/24')
        h15 = self.addHost('h15', ip='10.0.0.15/24')
        h16 = self.addHost('h16', ip='10.0.0.16/24')
        self.addLink(h13, s4, bw=10, delay='1ms')
        self.addLink(h14, s4, bw=10, delay='1ms')
        self.addLink(h15, s4, bw=10, delay='1ms')
        self.addLink(h16, s4, bw=10, delay='1ms')

        # Connect links between switches
        self.addLink(s1, s2, bw=20, delay='2ms')
        self.addLink(s2, s3, bw=20, delay='2ms')
        self.addLink(s3, s4, bw=20, delay='2ms')

def setup_network():

    # Create network
    net = Mininet(topo=CustomTopo(),
                  controller=RemoteController('c0', ip='127.0.0.1', port=6653),
                  link=TCLink,
                  autoSetMacs=True)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    setup_network()