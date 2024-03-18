package org.foo.app.MTD;

import org.onlab.packet.*;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.*;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;


import java.util.HashMap;
import java.util.Map;

@Component(immediate = true,
        service = {IPShufflingInterface.class}
)

public class IPShuffling implements IPShufflingInterface, PacketProcessor{

    private FlowRuleService flowRuleService;
    private Map<DeviceId, Map<MacAddress, PortNumber>> macToPort = new HashMap<>();

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final long SHUFFLE_INTERVAL = 45000;

    //private final Map<PortNumber, IpAddress> hostToIp = new HashMap<>();
    //private final Map<IpAddress, PortNumber> ipToHost = new HashMap<>();
    private Map<IpAddress, IpAddress> realToVirtual = new HashMap<>();
    private Map<IpAddress, IpAddress> virtualToReal = new HashMap<>();

    private Map<Ip4Address, DeviceId> hostAtSwitch = new HashMap<>();

    private final String[] virtItems = {"10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14",
            "10.0.0.15", "10.0.0.16", "10.0.0.17", "10.0.0.18", "10.0.0.19", "10.0.0.20",
            "10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24", "10.0.0.25", "10.0.0.26",
            "10.0.0.27", "10.0.0.28", "10.0.0.29", "10.0.0.30", "10.0.0.31", "10.0.0.32",
            "10.0.0.33", "10.0.0.34", "10.0.0.35", "10.0.0.36", "10.0.0.37", "10.0.0.38",
            "10.0.0.39", "10.0.0.40", "10.0.0.41", "10.0.0.42", "10.0.0.43", "10.0.0.44",
            "10.0.0.45", "10.0.0.46", "10.0.0.47", "10.0.0.48", "10.0.0.49", "10.0.0.50",
            "10.0.0.51", "10.0.0.52", "10.0.0.53", "10.0.0.54", "10.0.0.55", "10.0.0.56",
            "10.0.0.57", "10.0.0.58", "10.0.0.59", "10.0.0.60", "10.0.0.61", "10.0.0.62",
            "10.0.0.63", "10.0.0.64", "10.0.0.65", "10.0.0.66", "10.0.0.67", "10.0.0.68",
            "10.0.0.69", "10.0.0.70"};

    @Activate
    protected void activate(){
        log.info("Started IP Shuffling");
    }

    @Override
    public void process(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();


        if (ethPkt == null) {
            return;
        }

        if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
            this.processArpPacket(context, ethPkt);
        } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4){

        }

        //MELHORAR ESTE CÓDIGO
        InboundPacket inPacket = context.inPacket();
        ConnectPoint connectPoint = inPacket.receivedFrom();
        DeviceId deviceId = connectPoint.deviceId();
        PortNumber inPort = connectPoint.port();
        MacAddress srcMac = ethPkt.getSourceMAC();
        MacAddress dstMac = ethPkt.getDestinationMAC();

        macToPort.putIfAbsent(deviceId, new HashMap<>());
        // Logging the information
        log.info("Packet in " + deviceId + " " + srcMac + " " + dstMac + " " + inPort);

        macToPort.get(deviceId).put(srcMac, inPort);
        PortNumber outPort;
        if (macToPort.get(deviceId).containsKey(dstMac)) {
            outPort = macToPort.get(deviceId).get(dstMac);
        } else {
            outPort = PortNumber.FLOOD;
        }
        //Até linha 328


    }

    private void processArpPacket(PacketContext context, Ethernet ethernet){
        ARP arpPacket = (ARP) ethernet.getPayload();
        Ip4Address srcIp = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
        Ip4Address dstIp = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());

        if (rIP(srcIp) && !hostAtSwitch.containsKey(srcIp)) {
            hostAtSwitch.put(srcIp, context.inPacket().receivedFrom().deviceId());
        }

        /*TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP)
                .matchInPort(context.inPacket().receivedFrom().port());*/

        ConnectPoint connectPoint = context.inPacket().receivedFrom();
        PortNumber portNumber = connectPoint.port();
        DeviceId deviceId = connectPoint.deviceId();

        if (rIP(srcIp)) {

            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_ARP)
                    .matchInPort(portNumber)
                    .matchArpSpa(srcIp)
                    .matchArpTpa(dstIp);

            // Creating actions to modify ARP packet fields
            TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder()
                    .setArpSpa(realToVirtual.get(srcIp));

            //realToVirtual.get(srcIp);

            /*FlowRule flowRule = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selectorBuilder.build())
                    .withTreatment(treatmentBuilder.build())
                    .makePermanent()
                    .withPriority(10)
                    //.fromApp(context)
                    .build();

            flowRuleService.applyFlowRules(flowRule);*/
        }

        if (vIP(dstIp)) {
            if (dirConnect(context.inPacket().receivedFrom().deviceId(), this.virtualToReal.get(dstIp))){
                //this.virtualToReal.get(dstIp);
                TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_ARP)
                        .matchInPort(portNumber)
                        .matchArpTpa(dstIp)
                        .matchArpSpa(srcIp);

                // Creating actions to modify ARP packet fields
                TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder()
                        .setArpSpa(virtualToReal.get(dstIp));

                /*FlowRule flowRule = DefaultFlowRule.builder()
                        .forDevice(deviceId)
                        .withSelector(selectorBuilder.build())
                        .withTreatment(treatmentBuilder.build())
                        .makePermanent()
                        .withPriority(10)
                        //.fromApp(context.appId())
                        .build();

                flowRuleService.applyFlowRules(flowRule);*/
            }
        } else if (rIP(dstIp)) {
            if (!dirConnect(context.inPacket().receivedFrom().deviceId(), dstIp)){
                // drop packets
                System.out.println("Dropping packets from...");
            }

        } else {
            // drop packets
        }


    }

    private boolean rIP(IpAddress ipAddress) {
        return this.realToVirtual.containsKey(ipAddress);
    }

    private boolean vIP(IpAddress ipAddress) {
        return this.realToVirtual.containsValue(ipAddress);
    }

    private boolean dirConnect(DeviceId deviceId, IpAddress ipAddress){
        if (hostAtSwitch.containsKey(ipAddress)) {
            return hostAtSwitch.get(ipAddress).equals(deviceId);
        }
        return true;
    }


}
