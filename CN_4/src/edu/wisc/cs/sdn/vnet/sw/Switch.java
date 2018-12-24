package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.MACAddress;

import java.util.*;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{
	private Map<MACAddress,Iface> table = new HashMap();
	private Map<MACAddress, Long> times = new HashMap();
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
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
        MACAddress source = etherPacket.getSourceMAC();
        MACAddress dest = etherPacket.getDestinationMAC();
        table.put(source,inIface);
        times.put(source,System.currentTimeMillis());
        if (table.containsKey((dest)))
        {
            if (table.get(dest) != inIface)
                if (System.currentTimeMillis() - times.get(dest) <= 15000)
                {
                    sendPacket(etherPacket,table.get(dest));
                } else
                {
                    table.remove(dest);
                    times.remove(dest);
                    for (Iface i : super.interfaces.values())
                        if (i != inIface)
                        {
                            sendPacket(etherPacket,i);
                        }
                }
        } else
        {
            for (Iface i :  super.interfaces.values())
                if (i != inIface)
                {
                    sendPacket(etherPacket,i);
                }
        }
	}
}
