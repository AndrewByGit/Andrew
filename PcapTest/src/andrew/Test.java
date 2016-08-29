package andrew;

/**
 * Created by 安德魯 on 2016/6/10.
 */

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

import java.util.ArrayList;
import java.util.List;

public class Test {

    public static void main(String[] args) {

        List<PcapIf> alldevs= new ArrayList<PcapIf>();
        StringBuilder errbuf=new StringBuilder();
        int r=Pcap.findAllDevs(alldevs,errbuf);
        if(r != Pcap.OK || alldevs.isEmpty()) {
            System.out.println("Error");
            return ;
        }
        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device
                    .getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
                    description);
        }

        PcapIf device = alldevs.get(0); // Get first device in list
        System.out.printf("\nChoosing '%s' on your behalf:\n",
                (device.getDescription() != null) ? device.getDescription()
                        : device.getName());
        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
                byte[] data = packet.getByteArray(0, packet.size()); // the package data
                byte[] sIP = new byte[4];
                byte[] dIP = new byte[4];
                Ip4 ip = new Ip4();
                if (packet.hasHeader(ip) == false) {
                    return; // Not IP packet
                }
                ip.source(sIP);
                ip.destination(dIP);
				/* Use jNetPcap format utilities */
                String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

                System.out.println("srcIP=" + sourceIP +
                        " dstIP=" + destinationIP +
                        " caplen=" + packet.getCaptureHeader().caplen());
            }
        };

        // capture first 10 packages
        pcap.loop(10, jpacketHandler, "jNetPcap");
        pcap.close();
        System.out.println("End");

    }
}
