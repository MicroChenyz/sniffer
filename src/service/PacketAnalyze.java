package service;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.HashMap;

public class PacketAnalyze {

    // 解析协议类型
    private Ethernet ethernet;
    private Ip4 ip4;
    private Ip6 ip6;
    private Icmp icmp;
    private Arp arp;
    private Udp udp;
    private Tcp tcp;
    private Http http;

    PcapPacket pcapPacket;  // 要解析的数据包
    HashMap<String, String> analyzeInfo;  // 解析结果

    /*
    赋值要解析的数据包
     */

    public PacketAnalyze() {

    }

    public PacketAnalyze(PcapPacket pcapPacket) {
        this.pcapPacket = pcapPacket;
        ethernet = pcapPacket.getHeader(new Ethernet());
        ip4 = pcapPacket.getHeader(new Ip4());
        ip6 = pcapPacket.getHeader(new Ip6());
        icmp = pcapPacket.getHeader(new Icmp());
        arp = pcapPacket.getHeader(new Arp());
        udp = pcapPacket.getHeader(new Udp());
        tcp = pcapPacket.getHeader(new Tcp());
        http = pcapPacket.getHeader(new Http());
    }

    /*
    解析数据包
     */
    public HashMap<String, String> analyzePacket() {
        analyzeInfo = new HashMap<>();
        analyzeInfo.put("协议", analyzePacketProtocol());
        return analyzeInfo;
    }

    /*
    解析数据包协议类型
     */
    private String analyzePacketProtocol() {
        // 需要找到最高层的协议名，才是数据包真正的协议名
        JProtocol[] protocols = JProtocol.values();
        for (int i = protocols.length - 1; i >= 0; i--) {
            if (pcapPacket.hasHeader(protocols[i].getId())) {
                return protocols[i].name();
            }
        }
        return null;
    }

    /*
    解析数据包源Mac地址和目的Mac地址
     */
    private String[] analyzePacketMacAddress() {
        if(pcapPacket.hasHeader(ethernet)) {
            byte[] source = ethernet.source();
            byte[] destination = ethernet.destination();
            return new String[]{macBytesToString(source), macBytesToString(destination)};
        }
        return null;
    }

    /*
    将Mac地址的数组形式转换为字符串形式
     */
    private String macBytesToString(byte[] macAddress) {
        StringBuilder builder = new StringBuilder();
        for(int i = 0; i < macAddress.length; i++) {
            String hexString = Integer.toHexString(0xFF & macAddress[i]);
            if(hexString.length() < 2) {
                hexString = "0" + hexString;
            }
            builder.append(":").append(hexString);
        }
        return builder.substring(1);
    }

    /*
    解析数据包源IP和目的IP
     */
    private String[] analyzePacketIpAddress() throws UnknownHostException {
        int flag = 0;  // 根据flag判断IP地址是那种类型，或者都有
        String[] ipAddress = new String[5];
        if(pcapPacket.hasHeader(ip4)) {
            ipAddress[0] = Inet4Address.getByAddress(ip4.source()).getHostAddress();
            ipAddress[1] = Inet4Address.getByAddress(ip4.destination()).getHostAddress();
            flag = 1;
        }
        else if(pcapPacket.hasHeader(ip6)) {
            ipAddress[2] = Inet6Address.getByAddress(ip6.source()).getHostAddress();
            ipAddress[3] = Inet6Address.getByAddress(ip6.destination()).getHostAddress();
            flag = 2;
        }
        ipAddress[4] = Integer.toString(flag);
        return ipAddress;
    }

    /*
    解析数据包源port和目的port
     */
    private String[] analyzePacketPort() {
        if(pcapPacket.hasHeader(tcp)) {
            int sourcePort = tcp.source();
            int destinationPort = tcp.destination();
            return new String[]{Integer.toString(sourcePort), Integer.toString(destinationPort)};
        } else if(pcapPacket.hasHeader(udp)) {
            int sourcePort = udp.source();
            int destinationPort = udp.destination();
            return new String[]{Integer.toString(sourcePort), Integer.toString(destinationPort)};
        }
        return null;
    }

    /*
    解析数据包内容
     */
    private String analyzePacketInfo() {
        JBuffer jbuf = new JBuffer(pcapPacket.getTotalSize());
        pcapPacket.transferTo(jbuf);


        byte[] buff = new byte[pcapPacket.getTotalSize()];
        pcapPacket.transferStateAndDataTo(buff);
        JBuffer jbuffer = new JBuffer(buff);
        String pcapPacketInfo = jbuffer.toHexdump();
        return pcapPacketInfo;
    }


}
