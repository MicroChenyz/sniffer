package service;

import jpcap.*;

import java.util.Arrays;

/** NetWorkCard 作用是用于获取网卡
 * @author micro_chen
 */
public class NetworkCard {

    public static NetworkInterface[] getDevices() {
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        return devices;
    }

    // 测试代码
    public static void main(String[] args) {
        NetworkInterface[] devices = getDevices();
        for(int i = 0; i < devices.length; i++) {
            System.out.println(i + ": " + devices[i].name + "("
                    + devices[i].description  + ")");
        }
    }
}
