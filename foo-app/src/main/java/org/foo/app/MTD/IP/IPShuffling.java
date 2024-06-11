package org.foo.app.MTD.IP;

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
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketService;
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


import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

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


    private final Ip4Address server = Ip4Address.valueOf("192.168.0.1");
    private final Ip4Address honeypot = Ip4Address.valueOf("192.168.0.2");
    private final Ip4Address attacker = Ip4Address.valueOf("192.168.0.3");
    private final Ip4Address snort = Ip4Address.valueOf("192.168.0.4");

    private boolean pktDrop;

    private boolean installDefaultRule = true;


    /*@Activate
    protected void activate() {
        log.info("Started IP Shuffling");

        appId = coreService.registerApplication("org.foo.app");
        packetService.addProcessor(processor, PacketProcessor.director(2));

        realToVirtual.put(server, null);
        realToVirtual.put(honeypot, null);
        realToVirtual.put(attacker, null);
        realToVirtual.put(snort, null);

        realIpToMAC.put(server, MacAddress.valueOf("AA:11:11:11:11:01"));
        realIpToMAC.put(honeypot, MacAddress.valueOf("AA:11:11:11:11:02"));
        realIpToMAC.put(attacker, MacAddress.valueOf("AA:11:11:11:11:03"));
        realIpToMAC.put(snort, MacAddress.valueOf("AA:11:11:11:11:04"));

        macToPort.putIfAbsent(DeviceId.deviceId("of:0000000000000005"), new HashMap<>());
        macToPort.get(DeviceId.deviceId("of:0000000000000005")).put(MacAddress.valueOf("AA:11:11:11:11:03"), PortNumber.portNumber(2));

        macToPort.putIfAbsent(DeviceId.deviceId("of:0000000000000005"), new HashMap<>());
        macToPort.get(DeviceId.deviceId("of:0000000000000005")).put(MacAddress.valueOf("AA:11:11:11:11:01"), PortNumber.portNumber(1));

        macToPort.putIfAbsent(DeviceId.deviceId("of:0000000000000001"), new HashMap<>());
        macToPort.get(DeviceId.deviceId("of:0000000000000001")).put(MacAddress.valueOf("AA:11:11:11:11:03"), PortNumber.portNumber(2));

        macToPort.putIfAbsent(DeviceId.deviceId("of:0000000000000001"), new HashMap<>());
        macToPort.get(DeviceId.deviceId("of:0000000000000001")).put(MacAddress.valueOf("AA:11:11:11:11:01"), PortNumber.portNumber(1));
        //#########################################################################################################################################
        macToPort.putIfAbsent(DeviceId.deviceId("of:0000000000000005"), new HashMap<>());
        macToPort.get(DeviceId.deviceId("of:0000000000000005")).put(MacAddress.valueOf("AA:11:11:11:11:02"), PortNumber.portNumber(1));

        macToPort.putIfAbsent(DeviceId.deviceId("of:0000000000000001"), new HashMap<>());
        macToPort.get(DeviceId.deviceId("of:0000000000000001")).put(MacAddress.valueOf("AA:11:11:11:11:02"), PortNumber.portNumber(3));
        //#########################################################################################################################################

        hostAtSwitch.put(server, DeviceId.deviceId("of:0000000000000001"));
        hostAtSwitch.put(attacker, DeviceId.deviceId("of:0000000000000005"));
        hostAtSwitch.put(honeypot, DeviceId.deviceId("of:0000000000000001"));

        timer = new Timer();
        timer.schedule(new MTDTask(), 0, SHUFFLE_INTERVAL);
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        processor = null;

        timer.cancel();
        timer = null;
        log.info("Stopped IP Shuffling");
    }*/


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
            //flowRuleService.getFlowEntries(deviceId).forEach(flowRuleService::removeFlowRules);
            flowRuleService.getFlowEntries(deviceId).forEach(flowEntry -> {
                if (flowEntry.priority() != 5 || flowEntry.appId() != appId.id()) {
                    flowRuleService.removeFlowRules(flowEntry);
                }
            });
        } else {
            log.error("FlowRuleService is not available");
        }
    }

    public void updateVirtualIP() {

        SecureRandom random = new SecureRandom();
        int nextInt = random.nextInt(virtIPs.length);

        for (IpAddress key :  realToVirtual.keySet()) {
            realToVirtual.put(key, IpAddress.valueOf(virtIPs[nextInt]));
            nextInt = (nextInt + 1) % virtIPs.length;
        }

        virtualToReal = realToVirtual.entrySet().stream().collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));

        log.info("realToVirtual: {}",  realToVirtual);
        log.info("virtualToReal: {}",  virtualToReal);

        devices = deviceService.getAvailableDevices();

        for (Device device : devices) {
            emptyTable(device.id());


            if (installDefaultRule) {
                TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(PortNumber.CONTROLLER).build();

                //log.info("Antes de instalar a regra");
                if (flowRuleService != null) {
                    log.info("Entrei para instalar a regra");
                    FlowRule flowRule = DefaultFlowRule.builder()
                            .forDevice(device.id())
                            .withSelector(DefaultTrafficSelector.emptySelector())
                            .withTreatment(treatment)
                            .withPriority(5)
                            .fromApp(appId)
                            .makePermanent().build();

                    flowRuleService.applyFlowRules(flowRule);

                    log.info("Device {} regra instalada", device.id());
                } else {
                    log.error("FlowRuleService is not available");
                }


            }

        }
        if (installDefaultRule) installDefaultRule = false;
    }

    private class MTDPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {


            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }

            if (isIpv6Multicast(ethPkt)){
                return;
            }

            ConnectPoint connectPoint = context.inPacket().receivedFrom();
            PortNumber portNumber = connectPoint.port();
            DeviceId deviceId = connectPoint.deviceId();

            TrafficSelector selectorBuilder = DefaultTrafficSelector.emptySelector();
            TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();

            MacAddress dstMac;

            pktDrop = false;
            //boolean redirect = true;

            //log.info("Device: {}", deviceId);
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {

                ARP arpPacket = (ARP) ethPkt.getPayload();
                Ip4Address srcIp = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
                Ip4Address dstIp = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());
                log.info("Device: {}", deviceId);
                log.info("pacotes do tipo ARP - Source: {} - Destination: {}", srcIp, dstIp);

                if (rIP(srcIp) && !hostAtSwitch.containsKey(srcIp)) {
                    hostAtSwitch.put(srcIp, deviceId);
                    log.info("hostAtSwitch: {}",  hostAtSwitch);
                }

                if (rIP(srcIp)) {

                    //log.info("ARP: IP de ORIGEM real {} -> virtual {}", srcIp, realToVirtual.get(srcIp));
                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_ARP)
                            .matchInPort(portNumber)
                            .matchArpSpa(srcIp)
                            .matchArpTpa(dstIp).build();

                    treatmentBuilder.setArpSpa(realToVirtual.get(srcIp));
                            //.setEthSrc(ethPkt.getSourceMAC());


                }

                if (vIP(dstIp)) {
                    //log.info("destino é virtual");
                    selectorBuilder = DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP)
                            .matchInPort(portNumber)
                            .matchArpTpa(dstIp)
                            .matchArpSpa(srcIp).build();
                    dstMac = realIpToMAC.get(virtualToReal.get(dstIp));
                    ethPkt.setDestinationMACAddress(dstMac);
                    if (dirConnect(deviceId, virtualToReal.get(dstIp))) {

                        //log.info("ARP: IP DESTINO virtual {} -> real {}", dstIp, virtualToReal.get(dstIp));


                        //dstMac =  realIpToMAC.get(virtualToReal.get(dstIp));
                        //ethPkt.setDestinationMACAddress(dstMac);
                        treatmentBuilder.setArpTpa(virtualToReal.get(dstIp));

                        //log.info("ARP: Destination Mac {}", dstMac);

                    }
                } else if (rIP(dstIp)) {

                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_ARP)
                            .matchInPort(portNumber)
                            .matchArpSpa(srcIp)
                            .matchArpTpa(dstIp).build();
                    //TODO: verificar se descomento a linha seguinte
                    //dstMac = realIpToMAC.get(dstIp);
                    if (!dirConnect(deviceId, dstIp)) {
                        // drop packets
                        log.info("ARP: 1-Dropping packets from...");
                        treatmentBuilder.drop();
                        pktDrop = true;
                    }

                } else {
                    // drop packets
                    pktDrop = true;
                    treatmentBuilder.drop();
                    log.info("ARP: 2-Dropping packets from...");
                }

            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {

                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                Ip4Address srcIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
                Ip4Address dstIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());
                Ip4Prefix matchIp4SrcPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                Ip4Prefix.MAX_MASK_LENGTH);

                Ip4Prefix matchIp4DstPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                Ip4Prefix.MAX_MASK_LENGTH);
                log.info("Device: {}", deviceId);
                log.info("Pacotes do tipo ICMP - Source: {} - Destination: {}", srcIp, dstIp);



                if (rIP(srcIp) && !hostAtSwitch.containsKey(srcIp)) {
                    hostAtSwitch.put(srcIp, deviceId);
                    log.info("hostAtSwitch: {}",  hostAtSwitch);
                }

                if (rIP(srcIp)) {
                    //log.info("ICMP: IP de ORIGEM real {} -> virtual {}", srcIp, realToVirtual.get(srcIp));
                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchInPort(portNumber)
                            .matchIPSrc(matchIp4SrcPrefix)
                            .matchIPDst(matchIp4DstPrefix)
                            .build();


                    treatmentBuilder.setIpSrc(realToVirtual.get(srcIp));

                }

                if (vIP(dstIp)) {

                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchInPort(portNumber)
                            .matchIPSrc(matchIp4SrcPrefix)
                            .matchIPDst(matchIp4DstPrefix).build();
                    dstMac =  realIpToMAC.get(virtualToReal.get(dstIp));
                    ethPkt.setDestinationMACAddress(dstMac);
                    
                    if (dirConnect(deviceId, virtualToReal.get(dstIp))) {
                        //log.info("ICMP: IP DESTINO virtual {} -> real {}", dstIp, virtualToReal.get(dstIp));


                        //dstMac =  realIpToMAC.get(virtualToReal.get(dstIp));
                        //ethPkt.setDestinationMACAddress(dstMac);
                        treatmentBuilder.setIpDst(virtualToReal.get(dstIp));

                        //log.info("ICMP: Destination Mac {}", dstMac);

                    }
                } else if (rIP(dstIp)) {

                    selectorBuilder = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchInPort(portNumber)
                            .matchIPSrc(matchIp4SrcPrefix)
                            .matchIPDst(matchIp4DstPrefix).build();
                    //TODO: verificar se descomento a linha seguinte
                    //dstMac = realIpToMAC.get(dstIp);
                    if (!dirConnect(deviceId, dstIp)) {
                        // drop packets
                        log.info("ICMP: 1-Dropping packets from...");

                        treatmentBuilder.drop();
                        pktDrop = true;
                    }

                } else {
                    // drop packets
                    pktDrop = true;
                    treatmentBuilder.drop();
                    log.info("ICMP: 2-Dropping packets from...");
                }

            }
            //treatmentBuilder.immediate();

            //MELHORAR ESTE CÓDIGO
            MacAddress srcMac = ethPkt.getSourceMAC();
            dstMac = ethPkt.getDestinationMAC();

            //HostId id = HostId.hostId(dstMac);


            //macToPort.putIfAbsent(deviceId, new HashMap<>());
            // Logging the information
            //log.info("Packet in " + deviceId + " " + srcMac + " " + dstMac + " " + portNumber);

            //macToPort.get(deviceId).put(srcMac, portNumber);

            PortNumber outPort;
            //if (macToPort.get(deviceId).containsKey(dstMac)) {
            //    outPort = macToPort.get(deviceId).get(dstMac);
            //    log.info("Porto In: {} -> Porto Out: {} -> dstMAC: {}", portNumber, outPort, dstMac);
            //} else {
            //    outPort = PortNumber.FLOOD;
            //}

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(HostId.hostId(dstMac));
            if (dst == null) {
                log.info("Host não encontrado");
                flood(context);
                return;
            }

            // Are we on an edge switch that our destination is on? If so,
            // simply forward out to the destination and bail.
            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    installRule(deviceId, context, dst.location().port(), treatmentBuilder, selectorBuilder);
                }
                return;
            }

            // Otherwise, get a set of paths that lead from here to the
            // destination edge switch.
            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                            pkt.receivedFrom().deviceId(),
                            dst.location().deviceId());
            log.info("Paths: {}", paths);
            if (paths.isEmpty()) {
                // If there are no paths, flood and bail.
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
            outPort = path.src().port();

            installRule(deviceId, context, outPort, treatmentBuilder, selectorBuilder);


        }

    }

    private void installRule(DeviceId deviceId, PacketContext context, PortNumber outPort, TrafficTreatment.Builder treatmentBuilder, TrafficSelector selectorBuilder){

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


        } else {
            flood(context);
            return;
        }

        //log.info("NUM ICMP PACKETS: {}", countPackets);
        //forwardPacketToDst(context, portNumber, deviceId, treatmentBuilder.build());
        //TODO: podem existir casos em que o PortNumber tenha outro valor
        packetOut(context,  PortNumber.TABLE);
    }


    //control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }



    // Selects a path from the given set that does not lead back to the
    // specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        for (Path path : paths) {
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return null;
    }



    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void forwardPacketToDst(PacketContext context, PortNumber portNumber, DeviceId deviceId, TrafficTreatment treatment) {

        OutboundPacket packet;
        ByteBuffer buffer = ByteBuffer.wrap(context.inPacket().parsed().serialize());
        //packet = new DefaultOutboundPacket(deviceId, treatment, context.inPacket().unparsed(), portNumber);
        packet = new DefaultOutboundPacket(deviceId, treatment, buffer, portNumber);
        log.info("Tratamento do pacote: {}", treatment);
        //log.info("OutboundPacket : {}", packet);
        this.packetService.emit(packet);
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {

        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                context.inPacket().receivedFrom())) {
            //log.info("FLOOD");
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }



    private boolean rIP(IpAddress ipAddress) {
        return realToVirtual.containsKey(ipAddress);
    }

    private boolean vIP(IpAddress ipAddress) {
        return realToVirtual.containsValue(ipAddress);
    }

    private boolean dirConnect(DeviceId deviceId, IpAddress ipAddress) {
        if ( hostAtSwitch.containsKey(ipAddress)) {
            return  hostAtSwitch.get(ipAddress).equals(deviceId);
        }
        return true;
    }


}
