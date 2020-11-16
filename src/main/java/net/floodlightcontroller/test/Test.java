package net.floodlightcontroller.test;
 
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Collection;


import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.routing.BroadcastTree;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.Cluster;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.topology.TopologyInstance;

import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.util.OFMessageDamper;

import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.Set;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFFlowRemoved;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFStatisticsReply;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.statistics.OFPortStatisticsReply;
import org.openflow.protocol.statistics.OFPortStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.openflow.util.HexString;
import org.openflow.util.U16;
import org.openflow.util.U8;
//import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Test implements IOFMessageListener, IFloodlightModule {

	@Override
	public String getName() {
		return Test.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		//devicemanager is called before Test
		return (type.equals(OFType.PACKET_IN)&&(name.equals("devicemanager")||name.equals("topology")));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		//learning switch is called after MACTracker
                return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	protected IFloodlightProviderService floodlightProvider;
	protected ILinkDiscoveryService lds;
	protected static Logger logger;
	protected IDeviceService netDevices;
	protected IStaticFlowEntryPusherService flowPusher;
	protected static int uniqueFlow;
	protected static List<Integer> srcList = new ArrayList<Integer> ();
	
    //ip-mac string to string of host, used for ARP reply
	protected Map<String, String> devAddresses = new HashMap<String, String>();
	//protected Map<Integer, SwitchPort> devOnSwitch = new HashMap<Integer, SwitchPort>();//host_IP, Switch, Port
	protected Map<Long, IOFSwitch> switches;
	protected Map<String, Integer> hostIndex = new HashMap<String, Integer>(); //ip address to index
	
	//for shortest path computation
    public static final int MAX_LINK_WEIGHT = 10000;
    public static final int MAX_PATH_WEIGHT = Integer.MAX_VALUE - MAX_LINK_WEIGHT - 1;
    
    //change these two array based on topology every time
    protected int[] rulespace = {2,2,2,2,2,2,2}; //available rule space of each switch
    protected int[] host = {1,0,1,0,0,0}; // h[i]=1 represent drop the traffic of source host the (i+1)th host
	
    //for link load computation
	protected Timer timer = new Timer();
	protected BandwidthUpdateTask but = new BandwidthUpdateTask();	
	protected Map<Long, Map<Short, LinkBandwidthInfo>> switchesInfo= new HashMap<Long, Map<Short, LinkBandwidthInfo>>();
	protected List<String> sources = new ArrayList<String> ();
	
	
	
	class LinkBandwidthInfo {
		long transmitBytes;
		double trafficIntensity;
		long lastCheckTime;
		
		LinkBandwidthInfo() {
			transmitBytes = 0;
			lastCheckTime = 0;
		}
	}
	
    class BandwidthUpdateTask extends TimerTask {
        public void run() {
        	bandwidthQuery();
        }
    }
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	        new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    l.add(IDeviceService.class);
	    l.add(IRoutingService.class);
	    l.add(IStaticFlowEntryPusherService.class);
	    return l;
	}
	
	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		
		
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class); 
	    lds = context.getServiceImpl(ILinkDiscoveryService.class);
	    flowPusher = context.getServiceImpl(IStaticFlowEntryPusherService.class);

	    logger = LoggerFactory.getLogger(Test.class);
	    
	    sources.add("10.0.1.1");
	    sources.add("10.0.2.1");
	    sources.add("10.0.5.1");

		
		//Import addresses for end devices:
		try{
			Scanner reader = new Scanner(new BufferedReader(new FileReader("/home/mawenrui/Desktop/seven/HostAddresses.txt")));
			while(reader.hasNextLine()){
				String ip_mac = reader.nextLine();
				String[] host = ip_mac.split("\\|");
				String ip = host[0];
				if(ip.length()<3) continue;
				String mac = host[host.length-1];
				devAddresses.put(ip, mac);
			}
			reader.close();
		} catch(Exception e){
			System.out.println(e.getMessage());
			e.printStackTrace();
		}   
		
		
		try{
			Scanner reader = new Scanner(new BufferedReader(new FileReader("/home/mawenrui/Desktop/seven/HostIndex.txt")));
			while(reader.hasNextLine()){
				String ip_index = reader.nextLine();				
				String[] host = ip_index.split("\\|");
				String ip = host[0];
				if(ip.length()<3) continue;
				int index_num = Integer.parseInt(host[host.length-1]);
				hostIndex.put(ip, index_num);
				
			}
			System.out.println("HostIndex is "+hostIndex);
			reader.close();
		} catch(Exception e){
			System.out.println(e.getMessage());
			e.printStackTrace();
		}    
	}
	
	
	@Override
	public void startUp(FloodlightModuleContext context) {
        logger.trace("Starting");
       //switches = floodlightProvider.getAllSwitchMap();

        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);      
        timer.schedule(but,0, 2000);//set to run every 5 seconds task t
      
    }
	
	
	//Handle ARP Request and reply it with destination MAC address

	private void handleARPRequest(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, String ip, String mac) {
		
		//logger.debug("Handle ARP request");
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (! (eth.getPayload() instanceof ARP))
			return;
		ARP arpRequest = (ARP) eth.getPayload();
		
		// generate ARP reply
		IPacket arpReply = new Ethernet()
			.setSourceMACAddress(mac)
			.setDestinationMACAddress(eth.getSourceMACAddress())
			.setEtherType(Ethernet.TYPE_ARP)
			.setPriorityCode(eth.getPriorityCode())
			.setPayload(
				new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setHardwareAddressLength((byte) 6)
				.setProtocolAddressLength((byte) 4)
				.setOpCode(ARP.OP_REPLY)
				.setSenderHardwareAddress(MACAddress.valueOf(mac).toBytes())
				.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(ip))
				.setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())
				.setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));
		
		sendARPReply(arpReply, sw, OFPort.OFPP_NONE.getValue(), pi.getInPort());
	}
		
	// Sends ARP reply out to the switch
	private void sendARPReply(IPacket packet, IOFSwitch sw, short inPort, short outPort) {
		
		
		// Initialize a packet out
		OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.PACKET_OUT);
		po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		po.setInPort(inPort);
		
		// Set output actions
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(new OFActionOutput(outPort, (short) 0xffff));
		po.setActions(actions);
		po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
		
		// Set packet data and length
		byte[] packetData = packet.serialize();
		po.setPacketData(packetData);
		po.setLength((short) (OFPacketOut.MINIMUM_LENGTH + po.getActionsLength() + packetData.length));
		
		// Send packet
		try {
			sw.write(po, null);
			sw.flush();
		} catch (IOException e) {
			//logger.error("Failure writing packet out", e);
		}
	}
	
	
    public void bandwidthQuery() {
	    switches = floodlightProvider.getAllSwitchMap();
	    
    	//Sending OFStatisticsRequest to all switches
    	//Map<Long, Future<List<OFStatistics>>> switchReplies = new HashMap<Long, Future<List<OFStatistics>>>();
    	
    	for(Entry<Long, IOFSwitch> se: switches.entrySet()){
			Map<Short, LinkBandwidthInfo> linksInfo = switchesInfo.get(se.getValue().getId());
   	    	if (linksInfo == null) {
   	    		linksInfo = new HashMap<Short, LinkBandwidthInfo>();
   	    		switchesInfo.put(se.getValue().getId(), linksInfo);
   	    	}
   	    		
    		for (ImmutablePort port: se.getValue().getPorts()) {
    			LinkBandwidthInfo linkInfo = linksInfo.get(port.getPortNumber());
    			if (linkInfo == null) {
    				linkInfo = new LinkBandwidthInfo();
	    			linksInfo.put(port.getPortNumber(), linkInfo);
    				linkInfo.trafficIntensity = 0.0;
    			}
    		}
   	    	
    		
    		//System.out.println( "Request sent to "+ se); 
    		OFStatisticsRequest sr = new OFStatisticsRequest();
    		sr.setStatisticType(OFStatisticsType.PORT);
    		
    		OFPortStatisticsRequest psr = new OFPortStatisticsRequest();
    		psr.setPortNumber(OFPort.OFPP_NONE.getValue());
    		
    		List<OFStatistics> rl = new ArrayList<OFStatistics>();
    		rl.add(psr);
    		sr.setStatistics(rl);
    		sr.setLengthU(sr.getLengthU() + psr.getLength());
    		
    		Future<List<OFStatistics>> future;
    		List<OFStatistics> statsList = null;
    		
    		try {

    			IOFSwitch sw = se.getValue();
    			future = sw.queryStatistics(sr);
    			statsList = future.get(10, TimeUnit.SECONDS);

    			//Map<Short, LinkBandwidthInfo> linksInfo = switchesInfo.get(sw.getId());
    	    	if(statsList != null && !statsList.isEmpty()){

	    	    	// Receive signal from switches
	    	    	for(OFStatistics stats: statsList) { //each port
	    	    		OFPortStatisticsReply portStats = (OFPortStatisticsReply)stats;
	    	    		short portNum = portStats.getPortNumber();
	    	    		if(portNum < 0) continue;
	    	    		LinkBandwidthInfo linkInfo = linksInfo.get(portNum);
	    	    		if (linkInfo == null) {
	    	    			linkInfo = new LinkBandwidthInfo();
	    	    			linksInfo.put(portNum, linkInfo);
	    	    		}
	    	    		
	    	    		long lastlastCheckTime = linkInfo.lastCheckTime;
	    	    		linkInfo.lastCheckTime = System.currentTimeMillis();
	    	    		long lastTransmitBytes = linkInfo.transmitBytes;
	    	    		linkInfo.transmitBytes = portStats.getTransmitBytes();
	    	    		
	    	    		if (lastlastCheckTime != 0) { // not the first reply
		    	    		long interval = linkInfo.lastCheckTime - lastlastCheckTime;
		    	    		if (interval != 0) {
			    	    		long sentBytes = linkInfo.transmitBytes - lastTransmitBytes;
			    	    		//double alpha = 0.25;
			    	    		linkInfo.trafficIntensity = (sentBytes * 8.0) / (interval / 1000.0);
			    	    		if(linkInfo.trafficIntensity!=0.0){
			    	    			if(linkInfo.trafficIntensity>200000.0)
			    	    				System.out.println("sw="+sw.getId()+",port="+portNum+",ti="+linkInfo.trafficIntensity);			    	    			
			    	    		}			    	    	    
		    	    		}
	    	    		}
	    		    }
    	    	}   			
    		} catch (Exception e) {
    			logger.error("Failure sending request", e);
    			e.printStackTrace();
    		}
    	}
    }
    
    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext context) {

    	if (msg instanceof OFPacketIn){
	    	//System.out.println("OFPacketIn");
	        return this.processPacketIn(sw, (OFPacketIn)msg,context);
        }
        else if (msg instanceof OFStatisticsReply){
        	System.out.println("OFStatisticsReply");
            return this.processPortStatsReplyMessage(sw, (OFStatisticsReply)msg);
            }
        else {
        	System.out.println("NOT HANDLED" + msg.getClass());
        	return Command.CONTINUE;
        }
    }
        
    
    private Command processPacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext context) {
		// TODO: add routing processing
	    Ethernet eth = IFloodlightProviderService.bcStore.get(context,
	            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	   
		// Parse the received packet		
	    OFMatch match = new OFMatch();
	    match.loadFromPacket(pi.getPacketData(), pi.getInPort());
	    String srcIP = IPv4.fromIPv4Address(match.getNetworkSource());
	    
	    
	    if(eth.getEtherType() == 0x0806) {
			//generate arp reply
			int dstHost = match.getNetworkDestination();
			
			String dHostIp = IPv4.fromIPv4Address(dstHost);
			String dHostMac = devAddresses.get(dHostIp);
			
			logger.info("Received an ARP request from the client");
	    	handleARPRequest(sw, pi, context, dHostIp, dHostMac);
	    	return Command.STOP;
	    	
	    } else if (eth.getEtherType() == 0x0800 && !srcList.contains(match.getNetworkSource())) {
	    	if (!sources.contains(srcIP)) return Command.STOP;
	    	srcList.add(match.getNetworkSource());
	        Long dstSwitchId = getSwDpid(match.getNetworkDestination());
	        Long srcSwitchId = getSwDpid(match.getNetworkSource());
	        System.out.println("!!!!!!"+IPv4.fromIPv4Address(match.getNetworkDestination())+" "+match.getTransportDestination());
	    	
	    	System.out.println("The (src_sw  to dst_sw "+"(sw "+srcSwitchId+" ,"+ dstSwitchId+")");
	        //get route between srcSw and dstSw
	        Route route = widestRoute(srcSwitchId, dstSwitchId);
	        //System.out.println("The path will be computed ");
	        

	        if (route == null){
	        	return Command.STOP;
	        } else {
	        	//pathNode doesn't contain the src and dst attchment
	        	List<NodePortTuple> pathNode = route.getPath();
	        	
	        	IDevice dstHost = IDeviceService.fcStore.get(context, IDeviceService.CONTEXT_DST_DEVICE);
	        	IDevice srcHost = IDeviceService.fcStore.get(context, IDeviceService.CONTEXT_SRC_DEVICE);            	
	        	
	            SwitchPort[] srcDaps = srcHost.getAttachmentPoints();
	            SwitchPort[] dstDaps = dstHost.getAttachmentPoints();              
	            
	            NodePortTuple srcSwithport = new NodePortTuple(srcDaps[0].getSwitchDPID(),srcDaps[0].getPort());
	            NodePortTuple dstSwithport = new NodePortTuple(dstDaps[0].getSwitchDPID(),dstDaps[0].getPort());
	            
	            pathNode.add(0,srcSwithport);
	            pathNode.add(dstSwithport);
	            
	            System.out.println("The intact path of "+IPv4.fromIPv4Address(match.getNetworkSource())+
	            		" to "+IPv4.fromIPv4Address(match.getNetworkDestination())+" is "+pathNode);	
	            
		        if(host[hostIndex.get(srcIP)-1]==1) {
		        	placeEndRule(pathNode,match);
		        }

				placeRouting(pathNode,match);
				return Command.STOP;
	
	        }
	    }
	    return Command.STOP;        
	}
    
    private void placeEndRule(List<NodePortTuple> pathNode, OFMatch match){


    	int pathsize = pathNode.size();
    	System.out.println("pathNode"+pathNode);
    	System.out.println("pathSize"+pathsize);
    	List<Long> aSw = new ArrayList<Long>(); //switches with availabe rule space
    	
    	for ( int i = 0; i < pathsize ; i = i+2) {
    		if(rulespace[Long.valueOf(pathNode.get(i).getNodeId()).intValue()-1]>0){
    			aSw.add(pathNode.get(i).getNodeId());      			
    		}  		
    	}

    	
    	System.out.println("Available Switches are "+aSw);
    	
    	//Long nodeId = aSw.get(0); // first-fit to install a end rule
    	Long nodeId = aSw.get(aSw.size()-1);  //last-fit to install a end rule 
    	
    	
    	//random placed
    	//Random r=new Random();
    	//Long nodeId = aSw.get(r.nextInt(aSw.size()));
   	    //System.out.println("The last switch id is "+nodeId);
    	
		OFMatch endMatch = new OFMatch();
		endMatch.setDataLayerType(Ethernet.TYPE_IPv4).setNetworkSource(match.getNetworkSource());
		List<OFAction> actions = new ArrayList<OFAction>();
		OFActionOutput dropAction = new OFActionOutput();
		actions.add(dropAction);
		
	
		OFFlowMod endFlow = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		endFlow.setCommand(OFFlowMod.OFPFC_ADD)
				.setIdleTimeout((short) 0)
				.setHardTimeout((short) 0) //infinite
				.setMatch(endMatch)   // (srcIP,dstIp) with mask
				.setPriority((short) 200)
				.setActions(actions)
				.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		
		flowPusher.addFlow("Endflow"+uniqueFlow, endFlow, HexString.toHexString(nodeId));    			
		rulespace[Long.valueOf(nodeId).intValue()-1]--;
		uniqueFlow++;
		
		System.out.println(IPv4.fromIPv4Address(match.getNetworkSource())+
				"----"+IPv4.fromIPv4Address(match.getNetworkDestination())+" endrule placed on sw "+nodeId);

    }

    
    protected static String ipToString(int ip) {
        return Integer.toString(U8.f((byte) ((ip & 0xff000000) >> 24)))
               + "." + Integer.toString((ip & 0x00ff0000) >> 16) + "."
               + Integer.toString((ip & 0x0000ff00) >> 8) + "."
               + Integer.toString(ip & 0x000000ff);
    }
    
    //generate and place routing rules
    private void placeRouting(List<NodePortTuple> pathNode, OFMatch match){
    	OFMatch stoTMatch = new OFMatch();
    	OFMatch dtoSMatch = new OFMatch();
    	
    	stoTMatch.setDataLayerType(Ethernet.TYPE_IPv4)    		        
    				.setNetworkSource(match.getNetworkSource())
    				.setNetworkDestination(match.getNetworkDestination());
  	
    	dtoSMatch.setDataLayerType(Ethernet.TYPE_IPv4)
					.setNetworkSource(match.getNetworkDestination())
					.setNetworkDestination(match.getNetworkSource());

	
    	//System.out.println("?????The size of path is "+pathNode.size());
    	for(int indx = 0; indx<=pathNode.size()-1; indx+=2){
    		//define actions (output port)
    		short inport = pathNode.get(indx).getPortId();
    		stoTMatch.setInputPort(inport);
			List<OFAction> actions = new ArrayList<OFAction>();
			OFActionOutput outport = new OFActionOutput(pathNode.get(indx+1).getPortId()); //set the output port based on the path info
			actions.add(outport);
			
			OFFlowMod stoDst = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			stoDst.setCommand(OFFlowMod.OFPFC_ADD)
						.setIdleTimeout((short) 0)
						.setHardTimeout((short) 0) //infinite
						.setMatch(stoTMatch)   // (srcIP,dstIp) with mask
						.setPriority((short) 105)
						.setActions(actions)
						.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
			flowPusher.addFlow("routeFlow"+uniqueFlow, stoDst, HexString.toHexString(pathNode.get(indx).getNodeId()));
			uniqueFlow++;	
    	}
    	
    	for(int indx = pathNode.size()-1; indx > 0; indx-=2){
    		//define actions (output port)
    		short inport = pathNode.get(indx).getPortId();
    		dtoSMatch.setInputPort(inport);
    		
			List<OFAction> actions = new ArrayList<OFAction>();
			OFActionOutput outport = new OFActionOutput(pathNode.get(indx-1).getPortId()); //set the output port based on the path info
			actions.add(outport);
			
			OFFlowMod dtoSrc = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			dtoSrc.setCommand(OFFlowMod.OFPFC_ADD)
						.setIdleTimeout((short) 0)
						.setHardTimeout((short) 0) //infinite
						.setMatch(dtoSMatch)   // (srcIP,dstIp) with mask
						.setPriority((short) 105)
						.setActions(actions)
						.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
			flowPusher.addFlow("routeFlow"+uniqueFlow, dtoSrc, HexString.toHexString(pathNode.get(indx).getNodeId()));
			uniqueFlow++;	
    	}  	
    }


    
    //Get switch Id(long) based on the host IP address(10.0.5.1) return the third byte
    private Long getSwDpid(int is){  
    	String s =  ipToString(is);
		StringTokenizer st = new StringTokenizer(s,".");
		String des = new String();
		ArrayList<String> a = new ArrayList<String>();
			while(st.hasMoreElements()){
			des = (String) st.nextToken();
			a.add(des);
			}
    	return Long.valueOf(a.get(2));
    }

    
    private Command processPortStatsReplyMessage(IOFSwitch sw, OFStatisticsReply msg) {
    	Map<Short, LinkBandwidthInfo> linksInfo = switchesInfo.get(sw.getId());
    	if (linksInfo == null) {
    		linksInfo = new HashMap<Short, LinkBandwidthInfo>();
    		switchesInfo.put(sw.getId(), linksInfo);
    	}
    	
    	// Receive signal from switches
    	for(OFStatistics stats: msg.getStatistics()) { //each port
    		OFPortStatisticsReply portStats = (OFPortStatisticsReply)stats;
    		short portNum = portStats.getPortNumber();
    		if(portNum < 0) continue;
    		LinkBandwidthInfo linkInfo = linksInfo.get(portNum);
    		if (linkInfo == null) {
    			linkInfo = new LinkBandwidthInfo();
    			linksInfo.put(portNum, linkInfo);
    		}
    		
    		long lastlastCheckTime = linkInfo.lastCheckTime;
    		linkInfo.lastCheckTime = System.currentTimeMillis();
    		long interval = linkInfo.lastCheckTime - lastlastCheckTime;
    		
    		long lastTransmitBytes = linkInfo.transmitBytes;
    		linkInfo.transmitBytes = portStats.getTransmitBytes();
    		long sentBytes = linkInfo.transmitBytes - lastTransmitBytes;
    		
    		linkInfo.trafficIntensity = sentBytes / (interval / 1000.0);
	    }
    	
    	return Command.CONTINUE;
    }

    protected class NodeDist implements Comparable<NodeDist> {
        private final Long node;
        public Long getNode() {
            return node;
        }

        private final int dist;
        public int getDist() {
            return dist;
        }

        public NodeDist(Long node, int dist) {
            this.node = node;
            this.dist = dist;
        }

        @Override
        public int compareTo(NodeDist o) {
            if (o.dist == this.dist) {
                return (int)(this.node - o.node);
            }
            return this.dist - o.dist;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            NodeDist other = (NodeDist) obj;
            if (!getOuterType().equals(other.getOuterType()))
                return false;
            if (node == null) {
                if (other.node != null)
                    return false;
            } else if (!node.equals(other.node))
                return false;
            return true;
        }

        @Override
        public int hashCode() {
            assert false : "hashCode not designed";
            return 42;
        }

        private Test getOuterType() {
            return Test.this;
        }
    }
    
    
    Route shortestRoute(long srcSwitchId, long dstSwitchId) {
    	switches = floodlightProvider.getAllSwitchMap();
		//assert(switches != null);
		
		HashMap<Long, Link> nexthoplinks = new HashMap<Long, Link>();
        //HashMap<Long, Long> nexthopnodes = new HashMap<Long, Long>();
        HashMap<Long, Integer> cost = new HashMap<Long, Integer>();
     
        int w;

        for (Long node: switches.keySet()) {
            nexthoplinks.put(node, null);
            //nexthopnodes.put(node, null);
            cost.put(node, MAX_PATH_WEIGHT);
        }

        HashMap<Long, Boolean> seen = new HashMap<Long, Boolean>();
        PriorityQueue<NodeDist> nodeq = new PriorityQueue<NodeDist>();
        nodeq.add(new NodeDist(srcSwitchId, 0));
        cost.put(srcSwitchId, 0);
        while (nodeq.peek() != null) {
        	
            NodeDist n = nodeq.poll();
            Long cnode = n.getNode();
            int cdist = n.getDist();
            if (cdist >= MAX_PATH_WEIGHT) break;
            if (seen.containsKey(cnode)) continue;
            seen.put(cnode, true);

           
    		for (Link link : lds.getSwitchLinks().get(cnode)) {
    			//if (link.getDst() != cnode) 
    				Long neighbor = link.getDst(); // skip links with cnode as dst
    				
    			
    			// links directed toward cnode will result in this condition
    			if (neighbor.equals(cnode))
    				continue;

    			if (seen.containsKey(neighbor))
    				continue;

    			w = 1;
                
                int ndist = cdist + w; // the weight of the link, always 1 in current version of floodlight.
                if (ndist < cost.get(neighbor)) {
                    cost.put(neighbor, ndist);
                    nexthoplinks.put(neighbor, link);
                    //nexthopnodes.put(neighbor, cnode);
                    nodeq.remove(new NodeDist(neighbor, cost.get(neighbor)));
                    NodeDist ndTemp = new NodeDist(neighbor, ndist);
                    // Remove an object that's already in there.
                    // Note that the comparison is based on only the node id,
                    // and not node id and distance.
                    nodeq.remove(ndTemp);
                    // add the current object to the queue.
                    nodeq.add(ndTemp);
                }
                
            }            
    }
        
/*        for(Long node : nexthoplinks.keySet()) {
        	System.out.println("node number " + node + " " +nexthoplinks.get(node));
        }
        */
        
    	LinkedList<NodePortTuple> switchPorts = new LinkedList<NodePortTuple>();
    	
        //dstSwitchId will be changed in the following loop, use odstSwitchId to store the original data  
    	Long odstSwitchId = dstSwitchId;
    	if ((nexthoplinks!=null) && (nexthoplinks.get(dstSwitchId)!=null)) {
            while (dstSwitchId!= srcSwitchId ) {
                Link l = nexthoplinks.get(dstSwitchId);
                switchPorts.addFirst(new NodePortTuple(l.getDst(), l.getDstPort()));
                switchPorts.addFirst(new NodePortTuple(l.getSrc(), l.getSrcPort()));
                dstSwitchId = nexthoplinks.get(dstSwitchId).getSrc();
            }
        }
    	
    	Route result = null;
        if (switchPorts != null && !switchPorts.isEmpty())
            result = new Route( new RouteId(srcSwitchId, odstSwitchId), switchPorts);
        return result;
    }
    
	
    class NodeBw implements Comparable<NodeBw> {
        Long node;
        double bw;

        public NodeBw(Long node, double bw) {
            this.node = node;
            this.bw = bw;
        }

        @Override
        public int compareTo(NodeBw o) {
            if (o.bw == this.bw) {
                return (int)(this.node - o.node);
            }
            else if (this.bw < o.bw) 
            	return -1;
            else if (this.bw > o.bw) 
            	return 1;
            else 
            	return 0;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            NodeBw other = (NodeBw) obj;
            if (!getOuterType().equals(other.getOuterType()))
                return false;
            if (node == null) {
                if (other.node != null)
                    return false;
            } else if (!node.equals(other.node))
                return false;
            return true;
        }

        @Override
        public int hashCode() {
            assert false : "hashCode not designed";
            return 42;
        }
        
        Test getOuterType() {
            return Test.this;
        }
    }
    
    
	Route widestRoute(long srcSwitchId, long dstSwitchId) {
		
		HashMap<Long, Link> nexthoplinks = new HashMap<Long, Link>();
		HashMap<Long, Double> bws = new HashMap<Long, Double>();

		for (Long node: switches.keySet()) {
			nexthoplinks.put(node, null);
			// nexthopnodes.put(node, null);
			bws.put(node, Double.MAX_VALUE);
		}

		HashMap<Long, Boolean> seen = new HashMap<Long, Boolean>();
		PriorityQueue<NodeBw> nodeq = new PriorityQueue<NodeBw>();
		nodeq.add(new NodeBw(dstSwitchId, 0));
		bws.put(dstSwitchId, 0.0);
		while (nodeq.peek() != null) {
			NodeBw n = nodeq.poll();
			Long cnode = n.node;
			double cbw = n.bw;
			if (cbw >= Double.MAX_VALUE) break;
			if (seen.containsKey(cnode)) continue;
			seen.put(cnode, true);

			
			for (Link link : lds.getSwitchLinks().get(cnode)) {
				if (link.getDst() != cnode) continue; // skip links with cnode as src
				Long neighbor = link.getSrc();
				
				// links directed toward cnode will result in this condition
				if (neighbor.equals(cnode))
					continue;

				if (seen.containsKey(neighbor))
					continue;

				double w; 
				if (switchesInfo.get(neighbor) != null && switchesInfo.get(neighbor).get(link.getSrcPort()) != null) {
					w = switchesInfo.get(neighbor).get(link.getSrcPort()).trafficIntensity;
				}
				else
					break;
				
				double nbw = cbw > w ? cbw : w; // greater traffic intensity, less available bandwidth 
				
				if (nbw < bws.get(neighbor)) {
					bws.put(neighbor, nbw);
					nexthoplinks.put(neighbor, link);
					// nexthopnodes.put(neighbor, cnode);
					NodeBw ndTemp = new NodeBw(neighbor, nbw);
					// Remove an object that's already in there.
					// Note that the comparison is based on only the node id,
					// and not node id and distance.
					nodeq.remove(ndTemp);
					// add the current object to the queue.
					nodeq.add(ndTemp);
				}
			}
		}

		LinkedList<NodePortTuple> switchPorts = new LinkedList<NodePortTuple>();
		NodePortTuple npt;
		
		long osrcSwitchId = srcSwitchId;
		if ((nexthoplinks!=null) && (nexthoplinks.get(srcSwitchId)!=null)) {
            while (srcSwitchId != dstSwitchId) {
                Link l = nexthoplinks.get(srcSwitchId);
                npt = new NodePortTuple(l.getSrc(), l.getSrcPort());
                switchPorts.addLast(npt);
                npt = new NodePortTuple(l.getDst(), l.getDstPort());
                switchPorts.addLast(npt);
                srcSwitchId = nexthoplinks.get(srcSwitchId).getDst();
            }
        }
		
		Route result = null;
        if (switchPorts != null && !switchPorts.isEmpty())
            result = new Route( new RouteId(srcSwitchId, dstSwitchId), switchPorts);

        System.out.println("Route: s="+osrcSwitchId+",d="+dstSwitchId+" r="+ result);

        return result;
	}
        
}