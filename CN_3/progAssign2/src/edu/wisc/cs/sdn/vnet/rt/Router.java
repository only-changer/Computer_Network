package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.util.*;
import java.nio.ByteBuffer;
import  java.util.Map;
import javax.swing.event.InternalFrameEvent;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
    /** Routing table for the router */
    private RouteTable routeTable;

    /** ARP cache for the router */
    private ArpCache arpCache;

    private static Map<Integer,Vector<Ethernet>> queue;
    class RIPInternalEntry {
        int metric;
        long timestamp;

        public RIPInternalEntry(int metric, long timestamp) {
            this.metric = metric;
            this.timestamp = timestamp;
        }
    }
    Map<String, RIPInternalEntry> ripInternalMap = Collections
            .synchronizedMap(new HashMap<String, RIPInternalEntry>());
    /**
     * Creates a router for a specific host.
     * @param host hostname for the router
     */
    public Router(String host, DumpFile logfile)
    {
        super(host,logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
    }

    /**
     * @return routing table for the router
     */
    public RouteTable getRouteTable()
    { return this.routeTable; }

    /**
     * Load a new routing table from a file.
     * @param routeTableFile the name of the file containing the routing table
     */
    public void loadRouteTable(String routeTableFile)
    {
        if (!routeTable.load(routeTableFile, this))
        {
            System.err.println("Error setting up routing table from file "
                    + routeTableFile);
            System.exit(1);
        }

        System.out.println("Loaded static route table");
        System.out.println("-------------------------------------------------");
        System.out.print(this.routeTable.toString());
        System.out.println("-------------------------------------------------");
    }
    private void sendRIPPacket(Iface iface, int destIp,
                               byte[] destMac, byte command)
    {
        Ethernet ethernet = new Ethernet();
        ethernet.setEtherType(Ethernet.TYPE_IPv4);
        ethernet.setDestinationMACAddress(destMac);
        ethernet.setSourceMACAddress(iface.getMacAddress().toBytes());

        UDP udp = new UDP();
        udp.setDestinationPort(UDP.RIP_PORT);
        udp.setSourcePort(UDP.RIP_PORT);

        IPv4 ip = new IPv4();
        ip.setDestinationAddress(destIp);
        ip.setSourceAddress(iface.getIpAddress());
        ip.setTtl((byte) 16);
        ip.setProtocol(IPv4.PROTOCOL_UDP);

        RIPv2 rip = new RIPv2();

        rip.setCommand(command);

        for (RouteEntry routeEntry : routeTable.entries)
        {
            int dstIP = routeEntry.getDestinationAddress();
            int mask = routeEntry.getMaskAddress();
            int metric = routeEntry.metric;

            RIPv2Entry ripEntry = new RIPv2Entry(dstIP, mask, metric);
            ripEntry.setNextHopAddress(iface.getIpAddress());
            rip.addEntry(ripEntry);
        }

        udp.setPayload(rip);
        ip.setPayload(udp);
        ethernet.setPayload(ip);
        sendPacket(ethernet,iface);
    }
    public void startRIP()
    {
        for (Iface di : interfaces.values()) {
            int mask = di.getSubnetMask();
            int na = di.getIpAddress() & mask;
            routeTable.insert(na, 0, mask, di);
            ripInternalMap.put(na + "," + mask,
                    new RIPInternalEntry(0, -1));
            System.out.println(na);
            System.out.println(mask);
            System.out.println(di);
            System.out.println("R.I.P.");
            sendRIPPacket(di, IPv4.toIPv4Address("224.0.0.9"), MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes(),
                    RIPv2.COMMAND_REQUEST);
        }

    }
    /**
     * Load a new ARP cache from a file.
     * @param arpCacheFile the name of the file containing the ARP cache
     */
    public void loadArpCache(String arpCacheFile)
    {
        if (!arpCache.load(arpCacheFile))
        {
            System.err.println("Error setting up ARP cache from file "
                    + arpCacheFile);
            System.exit(1);
        }

        System.out.println("Loaded static ARP cache");
        System.out.println("----------------------------------");
        System.out.print(this.arpCache.toString());
        System.out.println("----------------------------------");
    }

    /**
     * Handle an Ethernet packet received on a specific interface.
     */

    /**
     * Handle an Ethernet packet received on a specific interface.
     * @param inIface the interface on which the packet was received
     */
    private void sendICMPPacket(IPv4 packet,Iface inIface, int type, int code, boolean isEcho)
    {
        Ethernet ether = new Ethernet();
        IPv4 ip = new IPv4();
        ICMP icmp = new ICMP();

        ether.setEtherType(Ethernet.TYPE_IPv4);
        RouteEntry dest = routeTable.lookup(packet.getSourceAddress());
        if (dest == null)
        {
            System.out.println("wrong dest IP!");
            return;
        }
        MACAddress macAdd;
        if (dest.getGatewayAddress() == 0)
            macAdd = arpCache.lookup(packet.getSourceAddress()).getMac();
        else
            macAdd = arpCache.lookup(dest.getGatewayAddress()).getMac();
        ether.setDestinationMACAddress(macAdd.toBytes());
        ether.setSourceMACAddress(dest.getInterface().getMacAddress().toBytes());
        ip.setTtl((byte)64);
        ip.setProtocol(IPv4.PROTOCOL_ICMP);
        ip.setSourceAddress(inIface.getIpAddress());
        ip.setDestinationAddress(packet.getSourceAddress());
        icmp.setIcmpType((byte)type);
        icmp.setIcmpCode((byte)code);
        if (isEcho)
        {
            ICMP originalIcmp = (ICMP) packet.getPayload();
            Data datas = new Data(originalIcmp.getPayload().serialize());
            ether.setPayload(ip);
            ip.setPayload(icmp);
            icmp.setPayload(datas);
            sendPacket(ether, inIface);
            return;
        }else
        {
            int headerLenBytes = packet.getHeaderLength() * 4;
            byte[] dataBytes = new byte[4 + headerLenBytes + 8];
            Arrays.fill(dataBytes, 0, 4, (byte) 0);
            byte[] originalIPv4Bytes = packet.serialize();
            for (int i = 0; i < headerLenBytes + 8; i++)
            {
                dataBytes[i + 4] = originalIPv4Bytes[i];
            }
            Data datas = new Data(dataBytes);

            ether.setPayload(ip);
            ip.setPayload(icmp);
            icmp.setPayload(datas);

            this.sendPacket(ether, inIface);
            return;
        }
    }
    private void sendARPPacket(Ethernet etherPacket, Iface inIface ,boolean isrequest,int targetIP)
    {
        if (!isrequest)
        {
            ARP arpPacket = (ARP) etherPacket.getPayload();
            int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
            if (inIface.getIpAddress() != targetIp)
                return;
            Ethernet ether = new Ethernet();
            ARP arp = new ARP();
            ether.setEtherType(Ethernet.TYPE_ARP);
            ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
            ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
            arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
            arp.setProtocolType(ARP.PROTO_TYPE_IP);
            arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
            arp.setProtocolAddressLength((byte) 4);
            arp.setOpCode(ARP.OP_REPLY);
            arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
            arp.setSenderProtocolAddress(inIface.getIpAddress());
            arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
            arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
            ether.setPayload(arp);
            sendPacket(ether, inIface);
            System.out.println("*** -> Send reply packet: " +
                    ether.toString().replace("\n", "\n\t"));
        } else
        {
            Ethernet ether = new Ethernet();
            ARP arp = new ARP();
            ether.setEtherType(Ethernet.TYPE_ARP);
            ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
            ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
            arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
            arp.setProtocolType(ARP.PROTO_TYPE_IP);
            arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
            arp.setProtocolAddressLength((byte) 4);
            arp.setOpCode(ARP.OP_REQUEST);
            arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
            arp.setSenderProtocolAddress(inIface.getIpAddress());
            byte [] zero = new byte[6];
            for (int i = 0;i < 6;++i)
            {
                zero[i] = 0x0000;
            }
            arp.setTargetHardwareAddress(zero);
            arp.setTargetProtocolAddress(targetIP);
            ether.setPayload(arp);
            sendPacket(ether, inIface);
            System.out.println("*** -> Send request packet: " +
                    ether.toString().replace("\n", "\n\t"));
        }
    }
    private byte[] getDestinationMacOfNextHop(int dstAddr) {
        RouteEntry bestMatch = routeTable.lookup(dstAddr);
        if (null == bestMatch) {
            return null;
        }
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop) {
            nextHop = dstAddr;
        }
        ArpEntry arpEntry = arpCache.lookup(nextHop);
        if (null == arpEntry) {
            return null;
        }
        return arpEntry.getMac().toBytes();
    }
    public void handlePacket(Ethernet etherPacket, Iface inIface)
    {
        System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
        System.out.println(etherPacket.getEtherType());
        if (etherPacket.getEtherType() != 0x0800)
        {
            if (etherPacket.getEtherType() == Ethernet.TYPE_ARP )
            {
                ARP arpPacket = (ARP) etherPacket.getPayload();
                if (arpPacket.getOpCode() == ARP.OP_REPLY)
                {
                    System.out.println("get arp reply");
                    int targetIp = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress());
                    MACAddress targetMac = new MACAddress(arpPacket.getSenderHardwareAddress());
                    arpCache.insert(targetMac,targetIp);
                    System.out.println(queue.size());
                    if (queue.containsKey(targetIp))
                    {
                        System.out.println(queue.size());
                        for (int i = 0; i < queue.get(targetIp).size(); ++i)
                        {
                            System.out.println(i);
                            Ethernet e = queue.get(targetIp).get(i);
                            e.setDestinationMACAddress(targetMac.toBytes());
                            sendPacket(e, inIface);
                            System.out.println("*** -> Send dalay packet: " +
                                    e.toString().replace("\n", "\n\t"));
                        }
                        queue.remove(targetIp);
                    }
                }
                else
                {
                    System.out.println("get arp request");
                    sendARPPacket(etherPacket, inIface, false, 0);
                }
            }else
            {
                System.out.println("wrong package type!");
            }
            return;
        }
        IPv4 packet =  (IPv4) etherPacket.getPayload();
        if (packet.getPayload() instanceof UDP )
        {
            UDP udp = (UDP) packet.getPayload();
            if (udp.getDestinationPort() == 520)
            {
                RIPv2 rip = (RIPv2) udp.getPayload();
                if (rip.getCommand() == RIPv2.COMMAND_RESPONSE)
                {
                    boolean modified = false;
                    for (RIPv2Entry entry : rip.getEntries()) {
                        int na = entry.getAddress();
                        int mask = entry.getSubnetMask();
                        int metric = entry.getMetric() + 1;
                        int ip = entry.getNextHopAddress();
                        String hashKey = na + "," + mask;
                        boolean shouldAdd = !(ripInternalMap.containsKey(hashKey) && metric >= ripInternalMap
                                .get(hashKey).metric);
                        if (shouldAdd) {
                            if (routeTable.find(na, mask) != null) {
                                routeTable.remove(na, mask);
                            }
                            routeTable.insert(na, ip, mask, inIface);
                            ripInternalMap
                                    .put(hashKey,
                                            new RIPInternalEntry(metric, System
                                                    .currentTimeMillis()));
                            modified = true;
                        }
                    }
                    if (modified) {
                        for (Iface i : interfaces.values()) {
                            sendRIPPacket(i, IPv4.toIPv4Address("224.0.0.9"), MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes(),
                                    RIPv2.COMMAND_RESPONSE);
                        }
                    }
                } else
                {
                    RouteEntry dest = this.routeTable.lookup(packet.getDestinationAddress());
                    byte[] destMac = getDestinationMacOfNextHop(packet.getSourceAddress());
                    if (null == destMac)
                    {
                        etherPacket.setSourceMACAddress(destMac);
                        int targetIP = packet.getSourceAddress();
                        if (queue == null)
                            queue = new HashMap<Integer,Vector<Ethernet>>();
                        if (queue.containsKey(targetIP))
                        {
                            queue.get(targetIP).add(etherPacket);
                        }
                        else
                        {
                            System.out.println(targetIP);
                            queue.put(targetIP,new Vector<Ethernet>());
                            System.out.println("??????????");
                            System.out.println(queue.size());
                            System.out.println(queue.containsKey(targetIP));
                            queue.get(targetIP).add(etherPacket);
                        }
                        sendARPPacket(etherPacket,dest.getInterface(),true,targetIP);
                        System.out.println("arp not found!");
                        return;
                    } else {
                        for (Iface i : interfaces.values()) {
                            sendRIPPacket(i, IPv4.toIPv4Address("224.0.0.9"), MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes(),
                                    RIPv2.COMMAND_RESPONSE);
                        }
                    }
                }
            }
        }
        if (packet.getProtocol() == IPv4.PROTOCOL_TCP || packet.getProtocol() == IPv4.PROTOCOL_UDP)
        {
            sendICMPPacket(packet,inIface,3,3,false);
            return;
        }
        // checksum
        byte[] data = new byte[packet.getHeaderLength() * 4];
        ByteBuffer bb = ByteBuffer.wrap(data);
        bb.put((byte) (((packet.getVersion() & 0xf) << 4) | (packet.getHeaderLength() & 0xf)));
        bb.put(packet.getDiffServ());
        bb.putShort(packet.getTotalLength());
        bb.putShort(packet.getIdentification());
        bb.putShort((short) (((packet.getFlags() & 0x7) << 13) | (packet.getFragmentOffset() & 0x1fff)));
        bb.put(packet.getTtl());
        bb.put(packet.getProtocol());
        bb.putShort(packet.getChecksum());
        bb.putInt(packet.getSourceAddress());
        bb.putInt(packet.getDestinationAddress());
        if (packet.getOptions() != null)
            bb.put(packet.getOptions());
        bb.rewind();
        int accumulation = 0;
        for (int i = 0; i < packet.getHeaderLength() * 2; ++i) {
            accumulation += 0xffff & bb.getShort();
        }
        accumulation = ((accumulation >> 16) & 0xffff)
                + (accumulation & 0xffff);
        short sum = (short) (~accumulation & 0xffff);
        sum &= 0xffff;
        if (sum != 0x0000)
        {
            System.out.println("wrong checksum!");
            return;
        }
        //ttl
        packet.setTtl((byte)(packet.getTtl() - 1));
        if (packet.getTtl() == 0)
        {
            sendICMPPacket(packet,inIface,11,0,false);
            System.out.println("wrong ttl!");
            return;
        }

        //reset checksum
        packet.resetChecksum();
        data = new byte[packet.getHeaderLength() * 4];
        bb = ByteBuffer.wrap(data);
        bb.put((byte) (((packet.getVersion() & 0xf) << 4) | (packet.getHeaderLength() & 0xf)));
        bb.put(packet.getDiffServ());
        bb.putShort(packet.getTotalLength());
        bb.putShort(packet.getIdentification());
        bb.putShort((short) (((packet.getFlags() & 0x7) << 13) | (packet.getFragmentOffset() & 0x1fff)));
        bb.put(packet.getTtl());
        bb.put(packet.getProtocol());
        bb.putShort(packet.getChecksum());
        bb.putInt(packet.getSourceAddress());
        bb.putInt(packet.getDestinationAddress());
        if (packet.getOptions() != null)
            bb.put(packet.getOptions());
        bb.rewind();
        accumulation = 0;
        for (int i = 0; i < packet.getHeaderLength() * 2; ++i) {
            accumulation += 0xffff & bb.getShort();
        }
        accumulation = ((accumulation >> 16) & 0xffff)
                + (accumulation & 0xffff);
        short check = (short) (~accumulation & 0xffff);
        packet.setChecksum(check);
        //dest IP
        for (Iface i : super.interfaces.values())
        {
            if (i.getIpAddress() == packet.getDestinationAddress())
            {
                ICMP icmp = (ICMP) packet.getPayload();
                if (icmp.getIcmpType() == 8)
                {
                    sendICMPPacket(packet,inIface,0,0,true);
                    System.out.println("echo");
                }
                System.out.println("dest is router!");
                return;
            }
        }
        //forwarding
        RouteEntry dest = routeTable.lookup(packet.getDestinationAddress());
        if (dest == null)
        {
            System.out.println("wrong dest IP!");

            sendICMPPacket(packet,inIface,3,0,false);
            return;
        }
        MACAddress macAdd;
        int targetIP;
        if (dest.getGatewayAddress() == 0)
            targetIP = packet.getDestinationAddress();
        else
            targetIP = dest.getGatewayAddress();
        try
        {
            macAdd = arpCache.lookup(targetIP).getMac();
        } catch (NullPointerException e)
        {
            etherPacket.setSourceMACAddress(dest.getInterface().getMacAddress().toBytes());
            if (queue == null)
                queue = new HashMap<Integer,Vector<Ethernet>>();
            if (queue.containsKey(targetIP))
            {
                queue.get(targetIP).add(etherPacket);
            }
            else
            {
                System.out.println(targetIP);
                queue.put(targetIP,new Vector<Ethernet>());
                System.out.println("??????????");
                System.out.println(queue.size());
                System.out.println(queue.containsKey(targetIP));
                queue.get(targetIP).add(etherPacket);
            }
            sendARPPacket(etherPacket,dest.getInterface(),true,targetIP);
            System.out.println("arp not found!");
            return;
        }
        etherPacket.setDestinationMACAddress(macAdd.toBytes());
        etherPacket.setSourceMACAddress(dest.getInterface().getMacAddress().toBytes());
        this.sendPacket(etherPacket, dest.getInterface());
        System.out.println("*** -> Sent packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
    }
}
