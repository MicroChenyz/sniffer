package service;

import service.PacketInfo;
import javafx.collections.ObservableList;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import service.PacketFactory;

import java.io.IOException;
import java.util.ArrayList;

public class PacketCapture implements Runnable {

    private volatile static PacketCapture instance = null;

    private NetworkInterface device;

    private String Filter = "";
    private String protocolType = "";
    private ArrayList<Packet> packets = new ArrayList<>();
    private ObservableList<PacketInfo> packetInfos = null;

    private String[] protocolList = {"ARP","ICMP","UDP","TCP","IP4","HTTP","IP6","TLS"};


    private volatile boolean isRun = true;



    private PacketCapture(){}

    public static PacketCapture getInstance(){
        if (instance==null){
            synchronized (PacketCapture.class){
                if (instance==null){
                    instance = new PacketCapture();
                }
            }
        }
        return instance;
    }

    public void setDevice(NetworkInterface device) {
        this.device = device;
    }

    public void setRun(boolean run) {
        isRun = run;
    }


    public void bindTable(ObservableList<PacketInfo> packetInfos){
        this.packetInfos = packetInfos;
    }

    public void setFilter(String filter) {
        Filter = filter;
        DrawTable();
    }

    public void setProtocolType(String protocolType) {
        this.protocolType = protocolType;
        DrawTable();
    }

    public void clearPackets(){
        packets.clear();
        packetInfos.clear();
    }

    public void DrawTable(){
        if (packetInfos!=null){
            packetInfos.clear();
            for (Packet p: packets) {
                PacketInfo info = null;
                if ((info = isFilter(p))!=null){
                    info.setNo(packetInfos.size()+1);
                    packetInfos.add(info);
                }
            }
        }
    }

    public void addItem2Table(Packet packet){
        PacketInfo info = null;
        if (packetInfos!=null&&(info = isFilter(packet))!=null){
            info.setNo(packetInfos.size()+1);
            packetInfos.add(info);
        }
    }

    private PacketInfo isFilter(Packet packet){//返回true表示满足过滤条件
        boolean flag = true;
        PacketInfo info = PacketFactory.packet2Info(packet,0);
        if (info==null) return null;
        if (!("".equals(protocolType))){
            if (!(info.getProtocol().contains(protocolType))) flag = false;
        }
        if (!("".equals(Filter))){
            if (Filter.contains("src.ip")){
                int equalsIndex = Filter.indexOf("==");
                String sip = Filter.substring(equalsIndex + 2);
                if (!info.getSourceIp().contains(sip)) flag = false;
            }else if (Filter.contains("dst.ip")){
                int equalsIndex = Filter.indexOf("==");
                String dip = Filter.substring(equalsIndex + 2);
                if (!info.getTargetIp().contains(dip)) flag = false;
            }else if (Filter.contains("keyword")){
                int equalsIndex = Filter.indexOf("==");
                String keyword = Filter.substring(equalsIndex + 2);
                if (!info.getInfo().contains(keyword)) flag = false;
            }else if (Filter.contains("src.port")){
                int equalsIndex = Filter.indexOf("==");
                String port = Filter.substring(equalsIndex + 2);
                String sport = info.getSourcePort();
                if (sport==null||(!sport.contains(port))) flag = false;
            } else if (Filter.contains("dst.port")) {
                int equalsIndex = Filter.indexOf("==");
                String port = Filter.substring(equalsIndex + 2);
                String dport = info.getTargetPort();
                if (dport==null||(!dport.contains(port))) flag = false;
            }
            for (String p:protocolList) {
                if (Filter.contains(p)){
                    if (!info.getProtocol().equals(p)) flag = false;
                    break;
                }
            }
        }

        info.setInterfaceName(device.name);

        return flag?info:null;
    }


    public static String traceRoute(PacketInfo packetInfo) {

        String srcIP = packetInfo.getSourceIp();
        String srcPort = packetInfo.getSourcePort();
        String dstIP = packetInfo.getTargetIp();
        String dstPort = packetInfo.getTargetPort();

        if(srcIP.equals("") || srcPort.equals("") || dstPort.equals("")||dstIP.equals(""))
            return "";

        StringBuilder strb = new StringBuilder();

        for(Packet packet : getInstance().packets) {
            PacketInfo info = PacketFactory.packet2Info(packet, 0);
            if(info == null) continue;
            String srcIP1 = info.getSourceIp();
            String srcPort1 = info.getSourcePort();
            String dstIP1 = info.getTargetIp();
            String dstPort1 = info.getTargetPort();
            if(srcIP1 == null || srcPort1 == null || dstPort1 == null||dstIP1 == null)
                continue;
            if(srcIP1.equals("") || srcPort1.equals("") || dstPort1.equals("")||dstIP1.equals(""))
                continue;
            if(srcIP1.equals(srcIP) && srcPort1.equals(srcPort))
                strb.append(info);
            else if(srcIP1.equals(dstIP) && srcPort1.equals(dstPort))
                strb.append(info);
            else if(dstIP1.equals(srcIP) && dstPort1.equals(srcPort))
                strb.append(info);
            else if(dstIP1.equals(dstIP) && dstPort1.equals(dstPort))
                strb.append(info);
        }

        return strb.toString();
    }

    @Override
    public void run() {
        Packet packet;
        try {
            JpcapCaptor captor = JpcapCaptor.openDevice(device,65535,true,20);
            while (isRun){
                long startTime = System.currentTimeMillis();
                while (startTime+500>=System.currentTimeMillis()){
                    packet = captor.getPacket();
                    if (packet!=null){
                        packets.add(packet);
                        //DrawTable();
                        addItem2Table(packet);
                    }
                }
                Thread.sleep(600);
            }
        }catch (IOException | InterruptedException e){
            e.printStackTrace();
        }
    }
}
