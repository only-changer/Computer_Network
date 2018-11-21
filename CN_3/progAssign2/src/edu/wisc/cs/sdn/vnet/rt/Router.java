package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
    /** Routing table for the router */
    private RouteTable routeTable;

    /** ARP cache for the router */
    private ArpCache arpCache;

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
     * @param etherPacket the Ethernet packet that was received
     * @param inIface the interface on which the packet was received
     */

    public void handlePacket(Ethernet etherPacket, Iface inIface)
    {
        System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
        if (etherPacket.getEtherType() != 0x0800)
        {
            System.out.println("wrong package type!");
            return;
        }
        IPv4 packet =  (IPv4) etherPacket.getPayload();
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
        if (packet.getTtl() == 0)
        {
            System.out.println("wrong ttl!");
            return;
        }
        packet.setTtl(new Integer(packet.getTtl() - 1).byteValue());
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
                System.out.println("dest is router!");
                return;
            }
        }
        //forwarding
        RouteEntry dest = routeTable.lookup(packet.getDestinationAddress());
        if (dest == null)
        {
            System.out.println("wrong dest IP!");
            return;
        }
        MACAddress macAdd;
        if (dest.getGatewayAddress() == 0)
            macAdd = arpCache.lookup(packet.getDestinationAddress()).getMac();
        else
            macAdd = arpCache.lookup(dest.getGatewayAddress()).getMac();
        etherPacket.setDestinationMACAddress(macAdd.toBytes());
        etherPacket.setSourceMACAddress(dest.getInterface().getMacAddress().toBytes());
        this.sendPacket(etherPacket, dest.getInterface());
        System.out.println("*** -> Sent packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
    }
}
