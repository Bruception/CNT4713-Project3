/*******************

Team members and IDs:
Bruce Berrios 6116238

Github link:
https://github.com/Bruception/CNT4713-Project3

*******************/

package net.floodlightcontroller.myrouting;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
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
import java.util.HashSet;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.ITopologyService;
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
	protected ITopologyService topologyService;

	protected Map<Long, SwitchNode> switchNodes = new HashMap<Long, SwitchNode>();
	protected Map<Long, Set<String>> deviceMap = new HashMap<Long, Set<String>>();
	protected Map<String, Long> deviceSwitches = new HashMap<String, Long>();

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
		l.add(ITopologyService.class);
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
		topologyService = context.getServiceImpl(ITopologyService.class);
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
				edges.add(new Edge(switchID, dstID, l.getSrcPort(), l.getDstPort()));
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

	private long getDeviceSwitchID(SwitchPort[] attachmentPoints) {
		Set<Short> ports;
		long switchID;
		for (SwitchPort attachmentPoint : attachmentPoints) {
			switchID = attachmentPoint.getSwitchDPID();
			ports = topologyService.getPortsWithLinks(switchID);
			if (!ports.contains((short)attachmentPoint.getPort())) {
				return switchID;
			}
		}
		return -1;
	}

	private void addDeviceToPath(FloodlightContext cntx, String key, List<NodePortTuple> path, int index) {
		SwitchPort[] attachmentPoints = IDeviceService.fcStore.get(cntx, key).getAttachmentPoints();
		NodePortTuple device = new NodePortTuple(attachmentPoints[0].getSwitchDPID(), attachmentPoints[0].getPort());
		path.add(index, device);
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (!printedTopo) {
			System.out.println("*** Print topology");
			Map<Long, Set<Link>> linkMap = linkProvider.getSwitchLinks();
			for (Long switchID : linkMap.keySet()) {
				List<Edge> switchEdges = getSwitchEdges(switchID, linkMap.get(switchID));
				switchNodes.put(switchID, new SwitchNode(switchID, switchEdges));
				String neighborTopology = getNeighborTopology(switchID, switchEdges);
				System.out.println(neighborTopology);
			}
			printedTopo = true;
		}

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (eth.getEtherType() != Ethernet.TYPE_IPv4) {
			return Command.CONTINUE;
		}
		devices = deviceProvider.getAllDevices();
		for (IDevice device : devices) {
			long parentSwitchID = getDeviceSwitchID(device.getAttachmentPoints());
			if (parentSwitchID != -1) {
				String deviceIP = IPv4.fromIPv4Address(device.getIPv4Addresses()[0]);
				Set<String> deviceIPs = deviceMap.getOrDefault(parentSwitchID, new HashSet<String>());
				deviceSwitches.put(deviceIP, parentSwitchID);
				deviceIPs.add(deviceIP);
				deviceMap.put(parentSwitchID, deviceIPs);
			}
		}
		System.out.println("*** New flow packet");
		// Parse the incoming packet.
		OFPacketIn pi = (OFPacketIn)msg;
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		String sourceIP = IPv4.fromIPv4Address(match.getNetworkSource());
		String destinationIP = IPv4.fromIPv4Address(match.getNetworkDestination());
		System.out.println("srcIP: " + sourceIP);
		System.out.println("dstIP: " + destinationIP);
		Route route = dijkstra(sourceIP, destinationIP);
		if (route != null) {
			List<NodePortTuple> path = route.getPath();
			addDeviceToPath(cntx, IDeviceService.CONTEXT_SRC_DEVICE, path, 0);
			addDeviceToPath(cntx, IDeviceService.CONTEXT_DST_DEVICE, path, path.size());
			installRoutes(path, match);
		} else {
			System.out.println("route: No route found!");
		}
		return Command.STOP;
	}

	private class Edge {
		private long sourceID;
		private long targetID;
		private short srcPort;
		private short dstPort;
		private int cost;

		public Edge(long sourceID, long targetID, short srcPort, short dstPort) {
			this.sourceID = sourceID;
			this.targetID = targetID;
			this.srcPort = srcPort;
			this.dstPort = dstPort;
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
		public String toString() {
			return "( (" + sourceID + ", PORT: " + srcPort + ") -> (" + targetID + ", PORT: " + dstPort + ") ," + cost + " )";
		}
	}

	private class SwitchNode implements Comparable<SwitchNode> {
		private int cost;
		private SwitchNode parent;
		private long id;
		private List<Edge> edges;
		private Edge edgeFrom;

		public SwitchNode(long switchID, List<Edge> edges) {
			cost = Integer.MAX_VALUE;
			parent = null;
			id = switchID;
			this.edges = edges;
		}

		@Override
		public int compareTo(SwitchNode e) {
			return this.cost - e.cost;
		}

		public void reset() {
			cost = Integer.MAX_VALUE;
			parent = null;
			edgeFrom = null;
		}
	}

	private List<SwitchNode> getPath(SwitchNode target) {
		List<SwitchNode> path = new ArrayList<SwitchNode>();
		while (target != null) {
			path.add(target);
			target = target.parent;
		}
		Collections.reverse(path);
		return path;
	}

	private String getPathAsString(List<SwitchNode> path) {
		StringBuilder sb = new StringBuilder();
		for (SwitchNode node : path) {
			sb.append(node.id).append(' ');
		}
		return sb.toString();
	}

	private Route buildRoute(List<SwitchNode> path) {
		if (path == null) return null;
		List<NodePortTuple> nodePortTuples = new ArrayList<NodePortTuple>();
		for (int i = 1; i < path.size(); ++i) {
			SwitchNode current = path.get(i);
			Edge currentEdge = current.edgeFrom;
			nodePortTuples.add(new NodePortTuple(currentEdge.sourceID, currentEdge.srcPort));
			nodePortTuples.add(new NodePortTuple(currentEdge.targetID, currentEdge.dstPort));
		}
		RouteId routeID = new RouteId(path.get(0).id, path.get(path.size() - 1).id);
		return new Route(routeID, nodePortTuples);
	}

	private Route dijkstra(String sourceIP, String destinationIP) {
		List<SwitchNode> path = null;
		PriorityQueue<SwitchNode> frontier = new PriorityQueue<SwitchNode>();
		Set<Long> explored = new HashSet<Long>();
		SwitchNode root = switchNodes.get(deviceSwitches.get(sourceIP));
		root.cost = 0;
		frontier.offer(root);
		SwitchNode current;
		while (!frontier.isEmpty()) {
			current = frontier.poll();
			if (explored.contains(current.id)) {
				continue;
			}
			explored.add(current.id);
			if (deviceMap.containsKey(current.id)) {
				Iterator<String> deviceIPIterator = deviceMap.get(current.id).iterator();
				while (deviceIPIterator.hasNext()) {
					String deviceIP = deviceIPIterator.next();
					if (destinationIP.equals(deviceIP)) {
						path = getPath(current);
						System.out.println("route: " + getPathAsString(path));
						break;
					}
				}
			}
			for (Edge edge : current.edges) {
				if (edge.targetID == current.id || explored.contains(edge.targetID)) {
					continue;
				}
				SwitchNode target = switchNodes.get(edge.targetID);
				int newCost = edge.cost + current.cost;
				if (newCost < target.cost) {
					frontier.remove(target);
					target.cost = newCost;
					target.parent = current;
					target.edgeFrom = edge;
					frontier.offer(target);
				}
			}
		}
		Route route = buildRoute(path);
		for (long switchID : switchNodes.keySet()) {
			switchNodes.get(switchID).reset();
		}
		return route;
	}

	// Install routing rules on switches. 
	private void installRoutes(List<NodePortTuple> path, OFMatch match) {
		OFMatch sourceToDestinationMatch = new OFMatch();
		OFMatch destinationToSourceMatch = new OFMatch();
		sourceToDestinationMatch.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkSource(match.getNetworkSource())
				.setNetworkDestination(match.getNetworkDestination());
		destinationToSourceMatch.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkSource(match.getNetworkDestination())
				.setNetworkDestination(match.getNetworkSource());
		for (int i = 0; i <= path.size() - 1; i += 2) {
			installRoute(path, sourceToDestinationMatch, i, 1);
		}
		// install another path from the destination back to the source to deliver the acknowledgements
		for (int i = path.size() - 1; i > 0; i -= 2) {
			installRoute(path, destinationToSourceMatch, i, -1);
		}
	}

	private void installRoute(List<NodePortTuple> path, OFMatch match, int i, int next) {
		short inport = path.get(i).getPortId();
		match.setInputPort(inport);
		List<OFAction> actions = new ArrayList<OFAction>();
		OFActionOutput outport = new OFActionOutput(path.get(i + next).getPortId());
		actions.add(outport);
		OFFlowMod mod = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		short length = (short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH);
		mod.setCommand(OFFlowMod.OFPFC_ADD)
				.setIdleTimeout((short) 0)
				.setHardTimeout((short) 0)
				.setMatch(match)
				.setPriority((short) 105)
				.setActions(actions)
				.setLength(length);
		flowPusher.addFlow("routeFlow" + uniqueFlow, mod,
				HexString.toHexString(path.get(i).getNodeId()));
		uniqueFlow++;
	}
}
