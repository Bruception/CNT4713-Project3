#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf

import time

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='192.168.56.1',
                      port=6633)

    info( '*** Add switches\n')


   
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
   
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
  
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
   
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)

    s5 = net.addSwitch('s5', cls=OVSKernelSwitch)
  
    s6 = net.addSwitch('s6', cls=OVSKernelSwitch)
   
    s7 = net.addSwitch('s7', cls=OVSKernelSwitch)


    info( '*** Add hosts\n')
    
    h1 = net.addHost('h1', cls=Host, mac='00:00:00:00:00:01', ip='10.0.1.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, mac='00:00:00:00:00:02', ip='10.0.5.1', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, mac='00:00:00:00:00:03', ip='10.0.2.1', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, mac='00:00:00:00:00:04', ip='10.0.3.1', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, mac='00:00:00:00:00:05', ip='10.0.4.1', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, mac='00:00:00:00:00:06', ip='10.0.4.2', defaultRoute=None)

    

    info( '*** Add links\n')
    linkBW = {'bw':10}
    

    net.addLink(h1, s1, cls=TCLink , **linkBW)
    net.addLink(h2, s5, cls=TCLink , **linkBW)
    net.addLink(h3, s2, cls=TCLink , **linkBW)
    net.addLink(h4, s3, cls=TCLink , **linkBW)
    net.addLink(h5, s4, cls=TCLink , **linkBW)
    net.addLink(h6, s4, cls=TCLink , **linkBW)


    net.addLink(s1, s2, cls=TCLink , **linkBW)
    net.addLink(s2, s3, cls=TCLink , **linkBW)  
    net.addLink(s3, s4, cls=TCLink , **linkBW)
    net.addLink(s1, s5, cls=TCLink , **linkBW)
    net.addLink(s5, s3, cls=TCLink , **linkBW)  
    net.addLink(s5, s6, cls=TCLink , **linkBW)
    net.addLink(s6, s7, cls=TCLink , **linkBW)
    net.addLink(s7, s4, cls=TCLink , **linkBW)





    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
  
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    net.get('s5').start([c0])
    net.get('s6').start([c0])
    net.get('s7').start([c0])


    time.sleep(2);


    info( '*** Configuring switches\n')

    hostsAll = net.hosts
    outfiles, errfiles = {}, {}
    info(h4.cmd('iperf -s -u > /tmp/h4 &'))
    info(h5.cmd('iperf -s -u > /tmp/h5 &'))
    info(h6.cmd('iperf -s -u > /tmp/h6 &'))
	
    info(h1.cmd('iperf -u -c 10.0.3.1 -t 10 -b 2M > /tmp/h1log &'))
    info(h2.cmd('iperf -u -c 10.0.4.2 -t 10 -b 2M > /tmp/h2log &'))
    info(h3.cmd('iperf -u -c 10.0.4.1 -t 10 -b 2M > /tmp/h3log &'))

	
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

