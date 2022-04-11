package service;

import jpcap.packet.*;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class PacketFactory {
    public static PacketInfo packet2Info(Packet packet,Integer no){

        PacketInfo info = null;
        if (packet.getClass().equals(ICMPPacket.class)){
            info = ICMPanalyze(packet);
        }else if (packet.getClass().equals(TCPPacket.class)){
            info = TCPanalyze(packet);
        }else if (packet.getClass().equals(UDPPacket.class)){
            info = UDPanalyze(packet);
        }else if (packet.getClass().equals(IPPacket.class)){
            info = IPanalyze(packet);
        } else if(packet.getClass().equals(ARPPacket.class)) {
            info = ARPanalyze(packet);
        }

        if(info!=null) {
            info.setNo(no);
            if(info.getTargetPort() != null || info.getSourcePort() != null) {
                if (info.getTargetPort().equals("80") || info.getSourcePort().equals("80")) {
                    if(packet.data.length != 0)
                        info.setProtocol("HTTP");
                } else if((info.getSourcePort().equals("443") || info.getTargetPort().equals("443"))) {
                    if (packet.data.length != 0)
                        info.setProtocol("TLS");
                }
            }

        }


        return info;
    }

    public static PacketInfo IPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof IPPacket){
            info = new PacketInfo();
            IPPacket ipPacket = (IPPacket) packet;
            if(String.valueOf(ipPacket.version).equals("4"))
                info.setProtocol("IP4");
            else
                info.setProtocol("IP6");
            info.setTime(String.valueOf(ipPacket.sec));
            info.setSourceIp(ipPacket.src_ip.toString().substring(1));
            info.setTargetIp(ipPacket.dst_ip.toString().substring(1));
            info.setLength((int) ipPacket.length);
            info.setInfo(ipPacket.toString());
            info.setPacket(packet);

        }
        return info;
    }

    public static PacketInfo ICMPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof ICMPPacket){
            info = new PacketInfo();
            ICMPPacket icmpPacket = (ICMPPacket) packet;
            info.setProtocol("ICMP");
            info.setTime(String.valueOf(icmpPacket.sec));
            info.setSourceIp(icmpPacket.src_ip.toString().substring(1));
            info.setTargetIp(icmpPacket.dst_ip.toString().substring(1));
            info.setLength((int) icmpPacket.length);
            info.setInfo(icmpPacket.toString());
            info.setPacket(packet);

        }
        return info;
    }

    public static PacketInfo TCPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof TCPPacket){
            info = new PacketInfo();
            TCPPacket tcpPacket = (TCPPacket) packet;
            info.setProtocol("TCP");
            info.setTime(String.valueOf(tcpPacket.sec));
            info.setSourceIp(tcpPacket.src_ip.toString().substring(1));
            info.setTargetIp(tcpPacket.dst_ip.toString().substring(1));
            info.setLength((int) tcpPacket.length);
            info.setInfo(tcpPacket.toString());
            info.setPacket(packet);

            info.setSourcePort(String.valueOf(tcpPacket.src_port));
            info.setTargetPort(String.valueOf(tcpPacket.dst_port));
        }
        return info;
    }

    public static PacketInfo UDPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof UDPPacket){
            info = new PacketInfo();
            UDPPacket udpPacket = (UDPPacket) packet;
            info.setProtocol("UDP");
            info.setTime(String.valueOf(udpPacket.sec));
            info.setSourceIp(udpPacket.src_ip.toString().substring(1));
            info.setTargetIp(udpPacket.dst_ip.toString().substring(1));
            info.setLength(udpPacket.length);
            info.setInfo(udpPacket.toString());
            info.setPacket(packet);

            info.setSourcePort(String.valueOf(udpPacket.src_port));
            info.setTargetPort(String.valueOf(udpPacket.dst_port));
            System.out.println(info.getSourcePort() + "-------------" + info.getTargetPort());

            System.out.println(DatatypeConverter.printHexBinary(udpPacket.header));
        }
        return info;
    }

    public static PacketInfo ARPanalyze(Packet packet){
        PacketInfo info = null;
        if (packet instanceof ARPPacket){
            info = new PacketInfo();
            ARPPacket arpPacket = (ARPPacket) packet;
            info.setProtocol("ARP");
            info.setTime(String.valueOf(arpPacket.sec));
            info.setSourceIp(DatatypeConverter.printHexBinary(arpPacket.sender_hardaddr));
            info.setTargetIp(DatatypeConverter.printHexBinary(arpPacket.target_hardaddr));
            info.setLength(arpPacket.len);
            info.setInfo(arpPacket.toString());
            info.setPacket(packet);
        }
        return info;
    }

    public static String bytes2Mac(byte[] bytes){
        StringBuilder stringBuilder = new StringBuilder();
        int len = bytes.length;
        for (int i = 0; i < len; i++) {
            stringBuilder.append(String.format("%02x", bytes[i]));
            if (i!=len-1) stringBuilder.append(":");
        }
        return stringBuilder.toString();
    }

    public static String bytes2Str(byte[] bytes){
        StringBuilder stringBuilder = new StringBuilder();
        int len = bytes.length;
        for (byte b:
                bytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    public static String byte2Str(byte b){
        return String.format("%02x",b);
    }

    public static int bytes2Int(byte[] b) {
        int value= 0;
        for(int i=0;i<b.length;i++){
            int n=(b[i]<0?(int)b[i]+256:(int)b[i])<<(8*i);
            value+=n;
        }
        return value;
    }

    public static String bytes2Ip(byte[] bytes){
        StringBuilder stringBuilder = new StringBuilder();
        int len = bytes.length;

        for (int i = 0;i<len;i++){
            byte[] bs = {bytes[i]};
            stringBuilder.append(bytes2Int(bs)+(i==len-1?"":"."));
        }

        return stringBuilder.toString();
    }

    public static Map<String,Object> getPacketDetail(PacketInfo info, Packet packet){
        Map<String,Object> map = new LinkedHashMap<>();

        Map<String,String> ethernetMap = new LinkedHashMap<>();

        ethernetMap.put("time",String.valueOf(packet.sec));
        ethernetMap.put("dataLength",String.valueOf(packet.header.length));

        byte[] etherHead = Arrays.copyOf(packet.header,14);
        ethernetMap.put("macTarget",bytes2Mac(Arrays.copyOfRange(etherHead,0,6)));
        ethernetMap.put("macSocrce",bytes2Mac(Arrays.copyOfRange(etherHead,6,12)));
        byte[] etherprotocol = Arrays.copyOfRange(etherHead,12,14);
        ethernetMap.put("etherProtocol","0x"+bytes2Str(etherprotocol));

        map.put("Ethernet II,Src:"+ethernetMap.get("macSocrce")+",Dst:"+ethernetMap.get("macTarget"),ethernetMap);

        if (etherprotocol[0]==0x08&&etherprotocol[1]==0x00){
            Map<String,String> ipMap = new LinkedHashMap<>();
            int ipHeadlen = 20;
            byte[] ipHead = Arrays.copyOfRange(packet.header,14,14+ipHeadlen);
            byte i1 = ipHead[0];
            ipMap.put("ipVersion",String.valueOf(i1>>4));
            ipMap.put("ipHeadLen",String.valueOf((i1&0xF)*4));
            ipMap.put("ipServiceType","0x"+String.format("%02x",ipHead[1]));

            ipMap.put("ipTotalLen",String.valueOf(bytes2Int(Arrays.copyOfRange(ipHead,2,4))));
            ipMap.put("Identification","0x"+bytes2Str(Arrays.copyOfRange(ipHead,4,6)));
            ipMap.put("ipFlags","0x"+bytes2Str(Arrays.copyOfRange(ipHead,6,8)));
            byte i6 = ipHead[6];
            i6&=0x1F;
            byte[] offset = {i6,ipHead[7]};
            ipMap.put("ipOffset",String.valueOf(bytes2Int(offset)));
            ipMap.put("ipTTL",String.valueOf(bytes2Int(Arrays.copyOfRange(ipHead,8,9))));
            ipMap.put("ipProtocol",String.valueOf(bytes2Int(Arrays.copyOfRange(ipHead,9,10))));
            ipMap.put("ipHeaderCheckSum","0x"+bytes2Str(Arrays.copyOfRange(ipHead,10,12)));

            ipMap.put("ipSource",bytes2Ip(Arrays.copyOfRange(ipHead,12,16)));
            ipMap.put("ipDestinatin",bytes2Ip(Arrays.copyOfRange(ipHead,16,20)));

            map.put("InternetnProtocol Version 4,Src: "+ipMap.get("ipSource")+",Dst: "+ipMap.get("ipDestinatin"),ipMap);

            if (ipMap.get("ipProtocol").equals("6")){//TCP

                Map<String,String> tcpMap = new LinkedHashMap<>();

                byte[] tcpHead = Arrays.copyOfRange(packet.header,34,54);
                tcpMap.put("tcpSourcePort",info.getSourcePort());
                tcpMap.put("tcpDestinationPort",info.getTargetPort());
                tcpMap.put("tcpSequence",String.valueOf(bytes2Int(Arrays.copyOfRange(tcpHead,4,8))));
                tcpMap.put("tcpAck",String.valueOf(bytes2Int(Arrays.copyOfRange(tcpHead,8,12))));
                byte b12 = tcpHead[12];
                byte[] arrb12 = {(byte) (b12>>4)};

                tcpMap.put("tcpHeadLen",String.valueOf(bytes2Int(arrb12)*4));

                byte[] arrb13 = {(byte) (b12&0x3f),tcpHead[13]};
                tcpMap.put("tcpFlags","0x"+bytes2Str(arrb13));

                tcpMap.put("tcpWindowSize",String.valueOf(bytes2Int(Arrays.copyOfRange(tcpHead,14,16))));
                tcpMap.put("tcpCheckSum","0x"+bytes2Str(Arrays.copyOfRange(tcpHead,16,18)));
                tcpMap.put("tcpUrgent",String.valueOf(bytes2Int(Arrays.copyOfRange(tcpHead,18,20))));

                map.put("Transmission Control Protocol,Src Port: "+tcpMap.get("tcpSourcePort")+" Dst Port: "+tcpMap.get("tcpDestinationPort"),tcpMap);

                if((tcpMap.get("tcpSourcePort").equals("80") || tcpMap.get("tcpDestinationPort").equals("80")) && packet.data != null && packet.data.length != 0) {
                    Map<String,String> httpMap = new LinkedHashMap<>();
                    StringBuilder stringBuilder = new StringBuilder();
                    if (packet.data!=null&&packet.data.length!=0){
                        stringBuilder.append("\n\nData:\n");
                        try {
                            stringBuilder.append(service.UnknownBytes2String.parse(packet.data));
                        } catch ( UnsupportedEncodingException e) {
                            e.printStackTrace();
                        }
                    }
                    httpMap.put("data", stringBuilder.toString());
                    map.put("Hypertext Transfer Protocol", httpMap);
                }
                else if((tcpMap.get("tcpSourcePort").equals("443") || tcpMap.get("tcpDestinationPort").equals("443")) && packet.data != null && packet.data.length != 0) {
                    Map<String,String> tlsMap = new LinkedHashMap<>();
                    StringBuilder stringBuilder = new StringBuilder();
                    if (packet.data!=null&&packet.data.length!=0){
                        stringBuilder.append("\n\nData:\n");
                        try {
                            stringBuilder.append(service.UnknownBytes2String.parse(packet.data));
                        } catch ( UnsupportedEncodingException e) {
                            e.printStackTrace();
                        }
                    }
                    tlsMap.put("data", stringBuilder.toString());
                    map.put("Transport Layer Security", tlsMap);

                }


            }else if (ipMap.get("ipProtocol").equals("1")){//icmp
                Map<String,String> icmpMap = new LinkedHashMap<>();
                byte[] icmpHead = Arrays.copyOfRange(packet.header,34,42);
                icmpMap.put("icmpType",String.valueOf(bytes2Int(Arrays.copyOfRange(icmpHead,0,1))));
                icmpMap.put("icmpCode",String.valueOf(bytes2Int(Arrays.copyOfRange(icmpHead,1,2))));
                icmpMap.put("icmpCheckSum","0x"+bytes2Str(Arrays.copyOfRange(icmpHead,2,4)));

                map.put("Internet Control Message Protocol",icmpMap);

            }else if (ipMap.get("ipProtocol").equals("17")){//udp
                Map<String,String> udpMap = new LinkedHashMap<>();
                byte[] udpHead = Arrays.copyOfRange(packet.header,34,42);
                udpMap.put("udpSourcePort",info.getSourcePort());
                udpMap.put("udpDetinationPort",info.getTargetPort());
                udpMap.put("udpDataLen",String.valueOf(bytes2Int(Arrays.copyOfRange(udpHead,4,6))));
                udpMap.put("udpCheckSum",String.valueOf(bytes2Int(Arrays.copyOfRange(udpHead,6,8))));

                map.put("User Datagram Protocol,Src Port: "+udpMap.get("udpSourcePort")+",Dst Port: "+udpMap.get("udpDetinationPort"),udpMap);
            }

        }
        else if(etherprotocol[0]==0x08&&etherprotocol[1]==0x06) {
            Map<String,String> arpMap = new LinkedHashMap<>();
            int arpHeadlen = 28;
            byte[] arpHead = Arrays.copyOfRange(packet.header,14,14+arpHeadlen);
            arpMap.put("HardwareType",String.valueOf(bytes2Int(Arrays.copyOfRange(arpHead,0,2))));
            arpMap.put("ProtocolType",String.valueOf(bytes2Int(Arrays.copyOfRange(arpHead,2,4))));
            arpMap.put("HardwareSize",String.valueOf(bytes2Int(Arrays.copyOfRange(arpHead,4,5))));
            arpMap.put("ProtocolSize",String.valueOf(bytes2Int(Arrays.copyOfRange(arpHead,5,6))));
            arpMap.put("Opcode",String.valueOf(bytes2Int(Arrays.copyOfRange(arpHead,6,8))));
            arpMap.put("SenderMACAddress",bytes2Mac(Arrays.copyOfRange(arpHead,8,14)));
            arpMap.put("SenderIPAddress",bytes2Ip(Arrays.copyOfRange(arpHead,14,18)));
            arpMap.put("TargetMACAddress",bytes2Mac(Arrays.copyOfRange(arpHead,18,24)));
            arpMap.put("TargetIPAddress",bytes2Ip(Arrays.copyOfRange(arpHead,24,28)));
            map.put("AddressResolution Protocol" ,arpMap);

        }

        return map;
    }

    public static String getDetail(Packet packet){
        StringBuilder stringBuilder = new StringBuilder();

        byte[] head = packet.header;
        byte[] data = packet.data;

        int head_len = head.length;
        int data_len = data.length;
        int p = 0;
        stringBuilder.append("Head:\n");

        for (int i = 0;i<head_len;i++){
            stringBuilder.append(byte2Str(head[i]));
            p++;
            if (p==8){
                stringBuilder.append("    ");
            }else if (p==16){
                p = 0;
                stringBuilder.append("\n");
            }else stringBuilder.append("  ");
        }

        if (data!=null&&data_len!=0){
            stringBuilder.append("\n\nData:\n");
            try {
                stringBuilder.append(service.UnknownBytes2String.parse(data));
            } catch ( UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }

        return stringBuilder.toString();
    }




}
