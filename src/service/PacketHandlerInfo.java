package service;

import org.jnetpcap.packet.PcapPacket;

import java.util.ArrayList;
import java.util.HashMap;

public class PacketHandlerInfo {

    public static String filterProtocolMess = "";  // 过滤协议
    public static String filterSrcIpMess = "";  // 过滤源IP地址
    public static String filterDestIpMess = "";  // 过滤目的IP地址
    public static String filterMess = "";  // 根据包内容进行过滤
    public static String ipMess = "";  // 根据IP
    public static String portMess = "";  // 根据端口


    public static ArrayList<PcapPacket> pcapPackets = new ArrayList<>();
    public static ArrayList<PcapPacket> analyzePcapPackets = new ArrayList<>();

    public static void setFilterProtocolMess(String filterProtocolMess) {
        PacketHandlerInfo.filterProtocolMess = filterProtocolMess;
    }

    public static void setFilterSrcIpMess(String filterSrcIpMess) {
        PacketHandlerInfo.filterSrcIpMess = filterSrcIpMess;
    }

    public static void setFilterDestIpMess(String filterDestIpMess) {
        PacketHandlerInfo.filterDestIpMess = filterDestIpMess;
    }

    public static void setIpMess(String ipMess) {
        PacketHandlerInfo.ipMess = ipMess;
    }

    public static void setPortMess(String portMess) {
        PacketHandlerInfo.portMess = portMess;
    }

    public static void setFilterMess(String filterMess) {
        PacketHandlerInfo.filterMess = filterMess;
    }

    public void clear() {
        pcapPackets.clear();
        analyzePcapPackets.clear();
    }

    // 对数据包进行过滤
//    public static void filterPcapPackets() {
//        Filter filter = new Filter();
//
//        analyzePcapPackets.clear();
//        for(int i = 0; i < pcapPackets.size(); i++) {
//            if(Filter.isFilter(pcapPackets.get(i), filterProtocolMess, filterSrcIpMess, filterDestIpMess, filterMess)
//            && Filter.tracePacket(pcapPackets.get(i), ipMess, portMess)) {
//                analyzePcapPackets.add(pcapPackets.get(i));
//            }
//        }
//    }
//}
}

/*
过滤器类
 */
class Filter {

    /*
    根据过滤规则进行过滤
     */
    public static boolean isFilter(PcapPacket pcapPacket, String filterProtocolMess, String filterSrcIpMess,
                                   String filterDestIpMess, String filterMess) {
        PacketAnalyze packetAnalyze = new PacketAnalyze(pcapPacket);
        HashMap<String, String> hashMap = packetAnalyze.analyzePacket();

        /*
        对数据包进行过滤
         */
        switch (filterProtocolMess) {
            case "Ethernet":
                if (!hashMap.get("协议").equals("ETHERNET")) {
                    return false;
                }
                break;
            case "IP4":
                if (!hashMap.get("协议").equals("IP4")) {
                    return false;
                }
                break;
            case "IP6":
                if (!hashMap.get("协议").equals("IP6")) {
                    return false;
                }
                break;
            case "ICMP":
                if (!hashMap.get("协议").equals("ICMP")) {
                    return false;
                }
                break;
            case "ARP":
                if (!hashMap.get("协议").equals("ARP")) {
                    return false;
                }
                break;
            case "UDP":
                if (!hashMap.get("协议").equals("UDP")) {
                    return false;
                }
                break;
            case "TCP":
                if (!hashMap.get("协议").equals("TCP")) {
                    return false;
                }
                break;
            case "HTTP":
                if (!hashMap.get("协议").equals("HTTP")) {
                    return false;
                }
                break;
            case "":

                break;
        }
        if (!filterSrcIpMess.equals("")) {
            if (!(hashMap.get("源IP4").equals(filterSrcIpMess)||hashMap.get("源IP6").equals(filterSrcIpMess))) {
                return false;
            }
        }
        if (!filterDestIpMess.equals("")) {
            if (!(hashMap.get("目的IP4").equals(filterDestIpMess)||hashMap.get("目的IP6").equals(filterDestIpMess))) {
                return false;
            }
        }
        if (!filterMess.equals("")) {
            if (!hashMap.get("包内容").contains(filterMess)) {
                return false;
            }
        }


        return true;

    }

    /*
    根据IP+Port进行流追踪
     */
    public static boolean tracePacket(PcapPacket pcapPacket, String ip, String port) {
        if(ip.equals("") || port.equals("")) {
            return true;
        }
        PacketAnalyze packetAnalyze = new PacketAnalyze(pcapPacket);
        HashMap<String, String> hashMap = packetAnalyze.analyzePacket();
        if (hashMap.get("协议").equals("TCP")&&
                (hashMap.get("源IP4").equals(ip)|| hashMap.get("源IP6").equals(ip))&&
                hashMap.get("源端口").equals(port)){
            return true;
        }
        if (hashMap.get("协议").equals("TCP")&&
                (hashMap.get("目的IP4").equals(ip)||hashMap.get("目的IP6").equals(ip))&&
                hashMap.get("目的端口").equals(port)){
            return true;
        }
        return false;

    }
}
