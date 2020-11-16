#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf

import time

def myNetwork():

    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0 = net.addController(name='c0', controller=RemoteController, ip='192.168.56.1', port=6633)

    info( '*** Adding switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)

    info( '*** Adding hosts\n')
    h1 = net.addHost('h1', cls=Host, mac='00:00:00:00:00:01', ip='10.0.1.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, mac='00:00:00:00:00:02', ip='10.0.2.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, mac='00:00:00:00:00:03', ip='10.0.3.3', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, mac='00:00:00:00:00:04', ip='10.0.4.4', defaultRoute=None)
	
	
    info( '*** Adding links\n')
    bw9 = {'bw':9}
    bw7 = {'bw':7}
    bw5 = {'bw':5}
    bw3 = {'bw':3}
    bw1 = {'bw':1}
    net.addLink(h1, s1, cls=TCLink, **bw9)
    net.addLink(h2, s2, cls=TCLink, **bw9)
    net.addLink(h3, s3, cls=TCLink, **bw9)
    net.addLink(h4, s4, cls=TCLink, **bw9)
    net.addLink(s1, s2, cls=TCLink, **bw9)
    net.addLink(s1, s3, cls=TCLink, **bw7)
    net.addLink(s2, s3, cls=TCLink, **bw5)
    net.addLink(s2, s4, cls=TCLink, **bw3)
    net.addLink(s3, s4, cls=TCLink, **bw1)

    info( '\n*** Starting network\n')
    net.build()
	
    info( '*** Starting controller\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')

    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])


    time.sleep(1);


    info( '\n*** Testing\n')

    hostsAll = net.hosts
    outfiles, errfiles = {}, {}
	
    net.iperf((h1, h2))
    net.iperf((h1, h3))
    net.iperf((h1, h4))

    raw_input('!!! Press enter to exit')

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
