package service;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class PacketCapture implements Runnable{

    private PcapIf device;  // 抓包设备
    private PacketHandlerInfo packetHandlerInfo;  // 处理器信息
    static Pcap pcap;  // 用于捕获数据包，注意：使用完后需要进行关闭


    public PacketCapture() {

    }

    public PacketCapture(PcapIf device, PacketHandlerInfo packetHandlerInfo) {
        this.device = device;
        this.packetHandlerInfo = packetHandlerInfo;
    }

    public PcapIf getDevice() {
        return device;
    }

    public PacketHandlerInfo getPacketHandler() {
        return packetHandlerInfo;
    }

    public void setDevice(PcapIf device) {
        this.device = device;
    }

    public void setPacketHandler(PacketHandlerInfo packetHandlerInfo) {
        this.packetHandlerInfo = packetHandlerInfo;
    }






    @Override
    public void run() {
        int snaplen = Pcap.DEFAULT_JPACKET_BUFFER_SIZE;  // 可以捕获的最大的byte数
        int flags = Pcap.MODE_PROMISCUOUS;  // 捕获所有包
        int timeout = 10 * 1000;  // 使得捕获包后等待一定的时间
        StringBuilder errbuf = new StringBuilder();  // 获取错误信息
        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if(pcap == null) {
            System.err.println("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        // 定义一个处理器来处理接收的数据包
        PacketHandler<Object> packetHandler = new PacketHandler();

        int count = 1;  // 数据包计数器
        while(true) {
            long startTime = System.currentTimeMillis();
            while(startTime + 500 >= System.currentTimeMillis()) {
                pcap.loop(count, packetHandler, packetHandlerInfo);
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }

    }
}
