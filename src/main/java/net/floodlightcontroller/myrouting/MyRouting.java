/*******************

Team members and IDs:
Bruce Berrios 6116238

Github link:
https://github.com/xxx/yyy

*******************/

package net.floodlightcontroller.myrouting;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Comparator;
import java.util.Collections;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;

import java.util.ArrayList;
import java.util.Set;
import java.util.TreeSet;
import java.util.HashSet;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.core.IListener.Command;

import org.openflow.util.HexString;
import org.openflow.util.U8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyRouting implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected IDeviceService deviceProvider;
	protected ILinkDiscoveryService linkProvider;

	// protected Map<Long, IOFSwitch> switches;
	// protected Map<Link, LinkInfo> links;
	protected Collection<? extends IDevice> devices;

	protected static int uniqueFlow;
	protected ILinkDiscoveryService lds;
	protected IStaticFlowEntryPusherService flowPusher;
	protected boolean printedTopo = false;

	@Override
	public String getName() {
		return MyRouting.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN)
				&& (name.equals("devicemanager") || name.equals("topology")) || name
					.equals("forwarding"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(ILinkDiscoveryService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		deviceProvider = context.getServiceImpl(IDeviceService.class);
		linkProvider = context.getServiceImpl(ILinkDiscoveryService.class);
		flowPusher = context
				.getServiceImpl(IStaticFlowEntryPusherService.class);
		lds = context.getServiceImpl(ILinkDiscoveryService.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	private String getNeighborTopology(Long switchID, List<Edge> edges) {
		StringBuilder sb = new StringBuilder();
		sb.append("switch ").append(switchID).append(" neighbors: ");
		boolean isFirst = true;
		for (Edge e : edges) {
			if (!isFirst) {
				sb.append(", ");
			}
			sb.append(e.targetID);
			isFirst = false;
		}
		return sb.toString();
	}

	private List<Edge> getSwitchEdges(long switchID, Set<Link> links) {
		List<Edge> edges = new ArrayList<Edge>();
		Set<Long> visitedLinks = new HashSet<Long>();
		long dstID;
		for (Link l : links) {
			dstID = l.getDst();
			if (dstID != switchID && !visitedLinks.contains(dstID)) {
				visitedLinks.add(dstID);
				edges.add(new Edge(switchID, dstID));
			}
		}
		Collections.sort(edges, new Comparator<Edge>() {
			@Override
			public int compare(Edge e, Edge e2) {
				return (int)(e.targetID - e2.targetID);
			}
		});
		return edges;
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (!printedTopo) {
			Map<Long, List<Edge>> nodes = new HashMap<Long, List<Edge>>();
			System.out.println("*** Print topology");
			Map<Long, Set<Link>> linkMap = linkProvider.getSwitchLinks();
			for (Long switchID : linkMap.keySet()) {
				List<Edge> switchEdges = getSwitchEdges(switchID, linkMap.get(switchID));
				nodes.put(switchID, switchEdges);
				String neighborTopology = getNeighborTopology(switchID, switchEdges);
				System.out.println(neighborTopology);
			}
			printedTopo = true;
		}

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (eth.getEtherType() != Ethernet.TYPE_IPv4) {
			return Command.CONTINUE;
		}
		System.out.println(deviceProvider.getAllDevices());
		System.out.println("*** New flow packet");
		// Parse the incoming packet.
		OFPacketIn pi = (OFPacketIn)msg;
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		String sourceIP = IPv4.fromIPv4Address(match.getNetworkSource());
		String destinationIP = IPv4.fromIPv4Address(match.getNetworkDestination());			
		System.out.println("srcIP: " + sourceIP);
		System.out.println("dstIP: " + destinationIP);

		Route route = dijkstra();
		if (route != null) {
			System.out.println("route: " + "1 2 3 ...");
			installRoute(route.getPath(), match);
		}
		return Command.STOP;
	}

	private class Edge implements Comparable<Edge> {
		private long sourceID;
		private long targetID;
		private int cost;

		public Edge(long sourceID, long targetID) {
			this.sourceID = sourceID;
			this.targetID = targetID;
			boolean sourceIDIsOdd = sourceID % 2 == 1;
			boolean targetIDIsOdd = targetID % 2 == 1;
			if (sourceIDIsOdd && targetIDIsOdd) {
				cost = 1;
			} else if (!sourceIDIsOdd && !targetIDIsOdd) {
				cost = 100;
			} else {
				cost = 10;
			}
		}

		@Override
		public int compareTo(Edge e) {
			return this.cost - e.cost;
		}

		@Override
		public String toString() {
			return "( " + sourceID + " -> " + targetID + ", " + cost + " )";
		}
	}

	private Route dijkstra() {
		return null;
	}

	// Install routing rules on switches. 
	private void installRoute(List<NodePortTuple> path, OFMatch match) {

		OFMatch m = new OFMatch();

		m.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkSource(match.getNetworkSource())
				.setNetworkDestination(match.getNetworkDestination());

		for (int i = 0; i <= path.size() - 1; i += 2) {
			short inport = path.get(i).getPortId();
			m.setInputPort(inport);
			List<OFAction> actions = new ArrayList<OFAction>();
			OFActionOutput outport = new OFActionOutput(path.get(i + 1)
					.getPortId());
			actions.add(outport);

			OFFlowMod mod = (OFFlowMod) floodlightProvider
					.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			mod.setCommand(OFFlowMod.OFPFC_ADD)
					.setIdleTimeout((short) 0)
					.setHardTimeout((short) 0)
					.setMatch(m)
					.setPriority((short) 105)
					.setActions(actions)
					.setLength(
							(short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
			flowPusher.addFlow("routeFlow" + uniqueFlow, mod,
					HexString.toHexString(path.get(i).getNodeId()));
			uniqueFlow++;
		}
	}
}
