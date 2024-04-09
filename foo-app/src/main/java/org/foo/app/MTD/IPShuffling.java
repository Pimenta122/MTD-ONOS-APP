package org.foo.app.MTD;

import com.google.common.collect.Maps;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Path;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.host.HostService;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.DefaultMeter;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;


import javax.crypto.MacSpi;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.stream.Collectors;

@Component(immediate = true, service = {IPShufflingInterface.class})

public class IPShuffling implements IPShufflingInterface {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    private Map<DeviceId, Map<MacAddress, PortNumber>> macToPort = Maps.newConcurrentMap();

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final long SHUFFLE_INTERVAL = 240000;

    //private final Map<PortNumber, IpAddress> hostToIp = new HashMap<>();
    //private final Map<IpAddress, PortNumber> ipToHost = new HashMap<>();
    private Map<IpAddress, IpAddress> realToVirtual = new HashMap<>();
    private Map<IpAddress, IpAddress> virtualToReal = new HashMap<>();
    private Map<Ip4Address, DeviceId> hostAtSwitch = new HashMap<>();

    private Map<IpAddress, MacAddress> realIpToMAC = new HashMap<>();
    private Iterable<Device> devices;

    private Timer timer;

    private MTDPacketProcessor processor = new MTDPacketProcessor();

    private ApplicationId appId;

    private final String[] virtIPs = {"192.168.0.11", "192.168.0.12", "192.168.0.13", "192.168.0.14", "192.168.0.15", "192.168.0.16", "192.168.0.17",
            "192.168.0.18", "192.168.0.19", "192.168.0.20", "192.168.0.21", "192.168.0.22", "192.168.0.23", "192.168.0.24", "192.168.0.25", "192.168.0.26",
            "192.168.0.27", "192.168.0.28", "192.168.0.29", "192.168.0.30", "192.168.0.31", "192.168.0.32", "192.168.0.33", "192.168.0.34", "192.168.0.35",
            "192.168.0.36", "192.168.0.37", "192.168.0.38", "192.168.0.39", "192.168.0.40", "192.168.0.41", "192.168.0.42", "192.168.0.43", "192.168.0.44",
            "192.168.0.45", "192.168.0.46", "192.168.0.47", "192.168.0.48", "192.168.0.49", "192.168.0.50", "192.168.0.51", "192.168.0.52", "192.168.0.53",
            "192.168.0.54", "192.168.0.55", "192.168.0.56", "192.168.0.57", "192.168.0.58", "192.168.0.59", "192.168.0.60", "192.168.0.61", "192.168.0.62",
            "192.168.0.63", "192.168.0.64", "192.168.0.65", "192.168.0.66", "192.168.0.67", "192.168.0.68", "192.168.0.69", "192.168.0.70"};

    @Activate
    protected void activate() {
        log.info("Started IP Shuffling");

        appId = coreService.registerApplication("org.foo.app");
        packetService.addProcessor(processor, PacketProcessor.director(3));

        realToVirtual.put(IpAddress.valueOf("192.168.0.1"), null);
        realToVirtual.put(IpAddress.valueOf("192.168.0.2"), null);
        realToVirtual.put(IpAddress.valueOf("192.168.0.3"), null);
        realToVirtual.put(IpAddress.valueOf("192.168.0.4"), null);

        realIpToMAC.put(IpAddress.valueOf("192.168.0.1"), MacAddress.valueOf("AA:11:11:11:11:01"));
        realIpToMAC.put(IpAddress.valueOf("192.168.0.2"), MacAddress.valueOf("AA:11:11:11:11:02"));
        realIpToMAC.put(IpAddress.valueOf("192.168.0.3"), MacAddress.valueOf("AA:11:11:11:11:03"));
        realIpToMAC.put(IpAddress.valueOf("192.168.0.4"), MacAddress.valueOf("AA:11:11:11:11:04"));

        timer = new Timer();
        timer.schedule(new MTDTask(), 0, SHUFFLE_INTERVAL);
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        processor = null;
        timer = null;
        log.info("Stopped IP Shuffling");
    }


    private class MTDTask extends TimerTask {
        @Override
        public void run() {
            // Perform MTD techniques here
            log.info("Executing MTD techniques");

            // Atualizar os itens virtuais e redirecionar o tráfego para o controlador
            updateVirtualIP();
        }
    }

    public void emptyTable(DeviceId deviceId) {
        if (flowRuleService != null) {
            flowRuleService.getFlowEntries(deviceId).forEach(flowRuleService::removeFlowRules);
        } else {
            log.error("FlowRuleService is not available");
        }
    }

    public void updateVirtualIP() {

        Random random = new Random();
        int nextInt = random.nextInt(virtIPs.length);

        for (IpAddress key : realToVirtual.keySet()) {
            realToVirtual.put(key, IpAddress.valueOf(virtIPs[nextInt]));
            nextInt = (nextInt + 1) % virtIPs.length;
        }

        virtualToReal = realToVirtual.entrySet().stream().collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));

        log.info("realToVirtual: {}", realToVirtual);
        log.info("virtualToReal: {}", virtualToReal);

        //isto provavelmente n pode estar aqui

        devices = deviceService.getAvailableDevices();

        for (Device device : devices) {
            //log.info("Device " + device.id());
            emptyTable(device.id());

            TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(PortNumber.CONTROLLER).build();

            //log.info("Antes de instalar a regra");
            if (flowRuleService != null) {
                //log.info("Entrei para instalar a regra");

                FlowRule flowRule = DefaultFlowRule.builder()
                        .forDevice(device.id())
                        .withSelector(DefaultTrafficSelector.emptySelector())
                        .withTreatment(treatment)
                        .withPriority(0)
                        .fromApp(appId)
                        .makePermanent().build();

                flowRuleService.applyFlowRules(flowRule);
                //log.info("regra instalada");
            } else {
                log.error("FlowRuleService is not available");
            }

        }
    }

    private class MTDPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {


            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            ConnectPoint connectPoint = context.inPacket().receivedFrom();
            PortNumber portNumber = connectPoint.port();
            DeviceId deviceId = connectPoint.deviceId();

            TrafficSelector selectorBuilder = DefaultTrafficSelector.emptySelector();
            TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();

            MacAddress dstMac = ethPkt.getDestinationMAC();

            boolean pktDrop = false;
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {

                ARP arpPacket = (ARP) ethPkt.getPayload();
                Ip4Address srcIp = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
                Ip4Address dstIp = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());

                log.info("pacotes do tipo ARP - Source: {} - Destination: {}", srcIp, dstIp);

                if (rIP(srcIp) && !hostAtSwitch.containsKey(srcIp)) {
                    hostAtSwitch.put(srcIp, deviceId);
                }

                if (rIP(srcIp)) {

                    log.info("ARP: IP de ORIGEM real {} -> virtual {}", srcIp, realToVirtual.get(srcIp));
                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_ARP)
                            .matchInPort(portNumber)
                            .matchArpSpa(srcIp)
                            .matchArpTpa(dstIp).build();

                    // Creating actions to modify ARP packet fields
                    //treatmentBuilder = DefaultTrafficTreatment.builder().setArpSpa(realToVirtual.get(srcIp)).build();

                    treatmentBuilder.setArpSpa(realToVirtual.get(srcIp));


                }

                if (vIP(dstIp)) {

                    selectorBuilder = DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP)
                            .matchInPort(portNumber)
                            .matchArpTpa(dstIp)
                            .matchArpSpa(srcIp).build();

                    if (dirConnect(deviceId, virtualToReal.get(dstIp))) {

                        log.info("ARP: IP DESTINO virtual {} -> real {}", dstIp, virtualToReal.get(dstIp));

                        // Creating actions to modify ARP packet fields
                        //treatmentBuilder = DefaultTrafficTreatment.builder().setArpTpa(virtualToReal.get(dstIp)).build();

                        treatmentBuilder.setArpTpa(virtualToReal.get(dstIp));

                        dstMac = realIpToMAC.get(virtualToReal.get(dstIp));
                        log.info("ARP: Destination Mac {}", dstMac);

                    }
                } else if (rIP(dstIp)) {

                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_ARP)
                            .matchInPort(portNumber)
                            .matchArpSpa(srcIp)
                            .matchArpTpa(dstIp).build();

                    if (!dirConnect(deviceId, dstIp)) {
                        // drop packets
                        log.info("ARP: 1-Dropping packets from...");
                        pktDrop = true;
                    }

                } else {
                    // drop packets
                    pktDrop = true;
                    log.info("ARP: 2-Dropping packets from...");
                }

            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {

                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                Ip4Address srcIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
                Ip4Address dstIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());

                log.info("Pacotes do tipo ICMP - Source: {} - Destination: {}", srcIp, dstIp);

                if (rIP(srcIp) && !hostAtSwitch.containsKey(srcIp)) {
                    hostAtSwitch.put(srcIp, deviceId);
                }

                if (rIP(srcIp)) {
                    log.info("ICMP: IP de ORIGEM real {} -> virtual {}", srcIp, realToVirtual.get(srcIp));
                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchInPort(portNumber)
                            .matchIPSrc(IpPrefix.valueOf(srcIp, Ip4Prefix.MAX_MASK_LENGTH))
                            .matchIPDst(IpPrefix.valueOf(dstIp, Ip4Prefix.MAX_MASK_LENGTH))
                            .build();

                    // Creating actions to modify ARP packet fields
                    //treatmentBuilder = DefaultTrafficTreatment.builder().setIpSrc(realToVirtual.get(srcIp)).build();

                    treatmentBuilder.setIpSrc(realToVirtual.get(srcIp));

                }

                if (vIP(dstIp)) {

                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchInPort(portNumber)
                            .matchIPSrc(IpPrefix.valueOf(srcIp, Ip4Prefix.MAX_MASK_LENGTH))
                            .matchIPDst(IpPrefix.valueOf(dstIp, Ip4Prefix.MAX_MASK_LENGTH)).build();

                    if (dirConnect(deviceId, virtualToReal.get(dstIp))) {
                        log.info("ICMP: IP DESTINO virtual {} -> real {}", dstIp, virtualToReal.get(dstIp));

                        //treatmentBuilder = DefaultTrafficTreatment.builder().setIpDst(virtualToReal.get(dstIp)).build();

                        treatmentBuilder.setIpDst(virtualToReal.get(dstIp));

                        dstMac = realIpToMAC.get(virtualToReal.get(dstIp));
                        log.info("ICMP: Destination Mac {}", dstMac);

                    }
                } else if (rIP(dstIp)) {

                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchInPort(portNumber)
                            .matchIPSrc(IpPrefix.valueOf(srcIp, Ip4Prefix.MAX_MASK_LENGTH))
                            .matchIPDst(IpPrefix.valueOf(dstIp, Ip4Prefix.MAX_MASK_LENGTH)).build();

                    if (!dirConnect(deviceId, dstIp)) {
                        // drop packets
                        log.info("ICMP: 1-Dropping packets from...");

                        //treatmentBuilder = DefaultTrafficTreatment.builder().drop().build();

                        pktDrop = true;
                    }

                } else {
                    // drop packets
                    pktDrop = true;
                    log.info("ICMP: 2-Dropping packets from...");
                }

            }

            //MELHORAR ESTE CÓDIGO
            /*MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            //HostId id = HostId.hostId(dstMac);
            log.info("src mac {} dst mac {}", srcMac, dstMac);

            macToPort.putIfAbsent(deviceId, new HashMap<>());
            // Logging the information
            //log.info("Packet in " + deviceId + " " + srcMac + " " + dstMac + " " + portNumber);

            macToPort.get(deviceId).put(srcMac, portNumber);

            PortNumber outPort;
            if (macToPort.get(deviceId).containsKey(dstMac)) {
                outPort = macToPort.get(deviceId).get(dstMac);
                log.info("Sei o porto: {}", outPort);
            } else {
                outPort = PortNumber.FLOOD;
            }

            if (!pktDrop) {
                treatmentBuilder.setOutput(outPort);
            }

            if (outPort != PortNumber.FLOOD){
                FlowRule flowRule = DefaultFlowRule.builder()
                        .forDevice(deviceId)
                        .withSelector(selectorBuilder)
                        .withTreatment(treatmentBuilder.build())
                        .makePermanent()
                        .withPriority(10)
                        .fromApp(appId).build();

                flowRuleService.applyFlowRules(flowRule);
                log.info("regra instalada");
            }*/


            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(HostId.hostId(dstMac));
            if (dst == null) {
                //log.info("HOST NÃO ENCONTRADO");
                flood(context);
                return;
            }

            // Otherwise, get a set of paths that lead from here to the
            // destination edge switch.
            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                            pkt.receivedFrom().deviceId(),
                            dst.location().deviceId());
            if (paths.isEmpty()) {
                // If there are no paths, flood and bail.
                log.info("NO PATHS");
                flood(context);
                return;
            }

            // Otherwise, pick a path that does not lead back to where we
            // came from; if no such path, flood and bail.
            Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
            if (path == null) {
                log.warn("Don't know where to go from here {} for {} -> {}",
                        pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context);
                return;
            }

            treatmentBuilder.setOutput(path.src().port());


            FlowRule flowRule = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selectorBuilder)
                    .withTreatment(treatmentBuilder.build())
                    .makePermanent()
                    .withPriority(10)
                    .fromApp(appId).build();

            flowRuleService.applyFlowRules(flowRule);
            log.info("regra instalada");

            forwardPacketToDst(context, deviceId, treatmentBuilder.build());
            /*if (pktDrop) {
                packetOut(context, outPort);
            } else {
                forwardPacketToDst(context, deviceId, treatmentBuilder.build());
            }*/

        }

    }


    /*private void installRule(PacketContext context, PortNumber portNumber, TrafficSelector trafficSelector, TrafficTreatment trafficTreatment, boolean installFlows) {
        if (!installFlows) {
            packetOut(context, portNumber);
        } else {

        }
    }*/

    // Selects a path from the given set that does not lead back to the
    // specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        Path lastPath = null;
        for (Path path : paths) {
            lastPath = path;
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return lastPath;
    }


    /**
     * Sends a packet out the specified port.
     * @param context context packet
     * @param portNumber, NumberPort
     */
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void forwardPacketToDst(PacketContext context, DeviceId deviceId, TrafficTreatment treatment) {

        OutboundPacket packet;
        ByteBuffer buffer = ByteBuffer.wrap(context.inPacket().parsed().serialize());
        packet = new DefaultOutboundPacket(deviceId, treatment, buffer);
        //packet = new DefaultOutboundPacket(deviceId, context.treatmentBuilder().build(), context.inPacket().unparsed());

        this.packetService.emit(packet);
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        //log.info("FLOOD");
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                context.inPacket().receivedFrom())) {

            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }



    private boolean rIP(IpAddress ipAddress) {
        return this.realToVirtual.containsKey(ipAddress);
    }

    private boolean vIP(IpAddress ipAddress) {
        return this.realToVirtual.containsValue(ipAddress);
    }

    private boolean dirConnect(DeviceId deviceId, IpAddress ipAddress) {
        if (hostAtSwitch.containsKey(ipAddress)) {
            return hostAtSwitch.get(ipAddress).equals(deviceId);
        }
        return true;
    }


}
