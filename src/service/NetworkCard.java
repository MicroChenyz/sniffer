package service;


import org.jnetpcap.PcapIf;
import org.jnetpcap.Pcap;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;



public class NetworkCard {

    List<PcapIf> alldevs = new ArrayList<>();  // 用于加载所有的网卡设备
    StringBuilder errbuf = new StringBuilder();  // 获取错误信息

    /*
    首先获取系统中的设备列表
     */
    public List<PcapIf> getAlldevs() {
        /*
        类似于pcap_open_live()打开的所有网络设备
         */
        int statusCode = Pcap.findAllDevs(alldevs, errbuf);
        if (statusCode != Pcap.OK || alldevs.isEmpty()) {
            System.out.println("Error occurred: " + errbuf.toString());
            return alldevs;
        }

        System.out.println("Network devices found:");
        int i = 0;
        for(PcapIf device : alldevs) {
            String description =
                    (device.getDescription() != null) ? device.getDescription()
                            : "No description available";  // 如果该设备介绍，则输出介绍
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        return alldevs;
    }

    /**
     * 测试方法：getAlldevs()
     */
    @Test
    public void test() {
        getAlldevs();
    }

}
