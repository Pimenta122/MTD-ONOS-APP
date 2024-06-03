package org.foo.app.MTD.Route;

import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Set;
import java.util.Timer;

@Component(immediate = true, service = {RouteMutationInterface.class})

public class RouteMutation implements RouteMutationInterface{

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

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;

    private final Ip4Address server = Ip4Address.valueOf("192.168.0.1");
    private final MacAddress serverMac = MacAddress.valueOf("AA:11:11:11:11:01");

    private final Ip4Address honeypot = Ip4Address.valueOf("192.168.0.2");
    private final MacAddress honeypotMac = MacAddress.valueOf("AA:11:11:11:11:02");

    private final Ip4Address attacker = Ip4Address.valueOf("192.168.0.3");
    private final MacAddress attackerMac = MacAddress.valueOf("AA:11:11:11:11:03");

    private final Ip4Address snort = Ip4Address.valueOf("192.168.0.4");
    private final MacAddress snortMac = MacAddress.valueOf("AA:11:11:11:11:04");

    private Iterable<Device> devices;

    private RoutePacketProcessor processor = new RoutePacketProcessor();

    @Activate
    protected void activate() {
        log.info("Started Route Mutation + Honeypot");

        appId = coreService.registerApplication("org.foo.app");
        packetService.addProcessor(processor, PacketProcessor.director(10));

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);


        devices = deviceService.getAvailableDevices();

        for (Device device : devices) {
            emptyTable(device.id());

            TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(PortNumber.CONTROLLER).build();

            //log.info("Antes de instalar a regra");
            if (flowRuleService != null) {
                //log.info("Entrei para instalar a regra");
                FlowRule flowRule = DefaultFlowRule.builder()
                        .forDevice(device.id())
                        .withSelector(DefaultTrafficSelector.emptySelector())
                        .withTreatment(treatment)
                        .withPriority(5)
                        .fromApp(appId)
                        .makePermanent().build();

                flowRuleService.applyFlowRules(flowRule);

                //log.info("Device {} regra instalada", device.id());
            } else {
                log.error("FlowRuleService is not available");
            }

        }

    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        processor = null;
        flowRuleService.removeFlowRulesById(appId);
        log.info("Stopped Route Mutation + Honeypot");
    }


    private class RoutePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {

            if (context == null || context.inPacket() == null || context.inPacket().parsed() == null) {
                return;
            }

            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            if (isControlPacket(ethPkt)) {
                return;
            }

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();

            PortNumber portNumber = pkt.receivedFrom().port();

            selector.matchInPort(portNumber)
                    .matchEthSrc(ethPkt.getSourceMAC())
                    .matchEthDst(ethPkt.getDestinationMAC());
            //log.info("Aquiiii");
            HostId id = HostId.hostId(ethPkt.getDestinationMAC());
            //log.info("mac origem {}", ethPkt.getSourceMAC());
            //log.info("mac destino {}", ethPkt.getDestinationMAC());
            boolean redirected = false;

            /*if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {

                ARP arpPacket = (ARP) ethPkt.getPayload();
                Ip4Address srcIp = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
                Ip4Address dstIp = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());

                if (dstIp.equals(server)) {
                    log.info("Alterar os pacotes ARP");
                    arpPacket.setTargetHardwareAddress(honeypotMac.toBytes());
                    arpPacket.setTargetProtocolAddress(honeypot.toInt());
                    arpPacket.setSenderHardwareAddress(honeypotMac.toBytes());
                    arpPacket.setSenderProtocolAddress(honeypot.toInt());
                    ethPkt.setSourceMACAddress(honeypotMac);
                }


            }*/

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                byte ipv4Protocol = ipv4Packet.getProtocol();
                Ip4Address srcIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
                Ip4Address dstIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());


                if (ipv4Protocol == IPv4.PROTOCOL_TCP) {
                    if (dstIp.equals(server)) {

                        log.info("dst: server -> honeypot");
                        selector.matchIPSrc(IpPrefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                                .matchIPDst(IpPrefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                                .matchEthType(Ethernet.TYPE_IPV4)
                                .matchIPProtocol(IPv4.PROTOCOL_TCP);

                        ipv4Packet.setDestinationAddress(honeypot.toInt());
                        ethPkt.setDestinationMACAddress(honeypotMac);

                        treatment.setIpDst(IpAddress.valueOf(ipv4Packet.getDestinationAddress()))
                                .setEthDst(ethPkt.getDestinationMAC());

                        id = HostId.hostId(honeypotMac); // set destination for forwarding
                        //log.info("src IP {} | dst IP {}", srcIp, dstIp);
                        redirected = true;
                    } else if (srcIp.equals(honeypot) && dstIp.equals(attacker)) {
                        log.info("honeypot to attacker");
                        selector.matchIPSrc(IpPrefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                                .matchIPDst(IpPrefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                                .matchEthType(Ethernet.TYPE_IPV4)
                                .matchIPProtocol(IPv4.PROTOCOL_TCP);

                        ipv4Packet.setSourceAddress(server.toInt());
                        ethPkt.setSourceMACAddress(serverMac);

                        treatment.setIpSrc(IpAddress.valueOf(ipv4Packet.getSourceAddress()))
                                .setEthSrc(ethPkt.getSourceMAC());

                        redirected = true;
                    }
                }
            }
            //log.info("mac destino {}", ethPkt.getDestinationMAC());

            treatment.immediate();

            Host dst = hostService.getHost(id);
            if (dst == null) {
                //log.info("Host não encontrado");
                flood(context);
                return;
            }

            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    installRule(context, dst.location().port(), selector, treatment, redirected);
                }
                return;
            }

            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                            pkt.receivedFrom().deviceId(),
                            dst.location().deviceId());
            if (paths.isEmpty()) {
                flood(context);
                return;
            }

            Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
            if (path == null) {
                log.warn("Don't know where to go from here {} for {} -> {}",
                        pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context);
                return;
            }

            installRule(context, path.src().port(), selector, treatment, redirected);


        }
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber, TrafficSelector.Builder selectorBuilder, TrafficTreatment.Builder treatmentBuilder, boolean redirected) {

        Ethernet inPkt = context.inPacket().parsed();

        // If ARP packet then forward directly to output port
        if (inPkt.getEtherType() == Ethernet.TYPE_ARP) {

            packetOut(context, portNumber);
            return;
        }

        treatmentBuilder.setOutput(portNumber);
        log.info("Install rules");
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatmentBuilder.build())
                .withPriority(10)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makePermanent()
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                forwardingObjective);


        if (!redirected) {
            packetOut(context, portNumber);
        } else {
            // It has to be IPv4
            Ethernet packet = context.inPacket().parsed();
            IPv4 ipv4Packet = (IPv4) packet.getPayload();

            ipv4Packet.resetChecksum();
            packet.resetChecksum();

            ByteBuffer buffer = ByteBuffer.wrap(packet.serialize());

            packetService.emit(new DefaultOutboundPacket(
                    context.inPacket().receivedFrom().deviceId(),
                    treatmentBuilder.build(),
                    buffer)
            );


            Iterable<Device> devices = deviceService.getDevices();

            for (Device d : devices) {
                flowObjectiveService.forward(d.id(),
                        forwardingObjective);
            }
        }

    }

    public void emptyTable(DeviceId deviceId) {
        if (flowRuleService != null) {
            flowRuleService.getFlowEntries(deviceId).forEach(flowRuleService::removeFlowRules);
        } else {
            log.error("FlowRuleService is not available");
        }
    }

    private void flood(PacketContext context) {

        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                context.inPacket().receivedFrom())) {
            //log.info("FLOOD");
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

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

    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

}
