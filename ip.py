# 导入requests库，用于发送HTTP请求
import requests
# 导入Scapy库，用于发送ARP请求并接收响应
from scapy.all import *
# 从Scapy库的第二层（数据链路层）导入Ether和ARP类
from scapy.layers.l2 import Ether, ARP

class CheckIP:
    """
    该类用于检查指定IP地址的MAC地址，并测试指定端口是否开放。
    """
    def __init__(self):
        """
        初始化方法，创建一个空列表来存储IP和MAC地址的映射。
        """
        # 创建一个空字典,装储ip地址
        self.ip_mac_map = []

    def send_arp(self, ip):
        """
        发送ARP请求以获取指定IP地址的MAC地址。

        :param ip: 需要查询MAC地址的IP地址
        :return: 存储了IP和MAC地址映射的列表
        """
        # 构造ARP请求报文，目标MAC地址为广播地址，目标IP地址为指定IP
        arp_req = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
        # 发送ARP请求并等待响应，超时时间为2秒，不输出详细信息
        arp_resq = srp(arp_req, timeout=2, verbose=0)[0]
        # 遍历所有收到的ARP响应，存储IP和MAC地址的映射
        for arp in arp_resq:
            self.ip_mac_map.append([arp[1].psrc])
        return self.ip_mac_map

    def check_ip(self, ip):
        """
        检查指定IP地址的MAC地址。

        :param ip: 需要检查的IP地址
        """
        # 调用send_arp方法获取IP和MAC地址的映射
        self.send_arp(ip)  # self.send_arp(ip)是获取ip
        # 遍历映射列表，打印每个IP地址
        for ip in self.ip_mac_map:
            print(f"{ip}")

    def port_test(self, ip_in, ports):
        """
        测试指定IP地址的端口是否开放。

        :param ip_in: 需要测试的IP地址
        :param ports: 需要测试的端口范围
        :return: 开放的端口列表
        """
        # 调用send_arp方法获取IP地址的列表
        ip_lists = self.send_arp(ip_in)
        ports_list = []
        # 遍历IP地址列表，对每个IP地址测试指定端口范围
        for ip in ip_lists:
            for port in range(ports.start, ports.stop + 1):
                try:
                    # 构造HTTP请求URL
                    url = f"http://{ip[0]}:{port}"
                    # 发送HTTP GET请求，超时时间为1秒
                    res = requests.get(url, timeout=1)
                    # 如果请求成功，端口开放
                    if res.status_code == 200:
                        print(f"{ip[0]}的{port}端口开放")
                        ports_list.append(f"{ip[0]}:{port}")
                except requests.exceptions.ConnectionError:
                    # 如果连接错误，端口未开放
                    print(f"{ip[0]}的{port}端口未开放")
                except Exception as e:
                    # 其他异常输出错误信息
                    print(f"发生错误：{e}")
        return ports_list

    def save_txt(self, items, filename="dict.txt"):
        """
        将列表中的项保存到文本文件中。

        :param items: 需要保存的列表
        :param filename: 保存的文件名，默认为"dict.txt"
        :return: 保存后的列表
        """
        with open(filename, 'a') as f:
            # 遍历列表，每项写入一行
            for item in items:
                f.write(f"{item}\n")
        return items


if __name__ == '__main__':
    checker = CheckIP()
    ip = input("请输入要测试的ip地址: ")
    checker.check_ip(ip)

    input_port = input("请输入端口范围(1-65535): ")
    try:
        start_port, end_port = map(int, input_port.split("-"))
        if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
            raise ValueError("端口超出有效范围")
        ports = range(start_port, end_port + 1)
        ports_list = checker.port_test(ip, ports)
        print(f"{ip}的开放端口为：{ports_list}")
        checker.save_txt(ports_list, "port.txt")
        print(ports_list)
    except ValueError:
        print("输入的端口范围格式不正确，请输入类似'1-65535'的格式。")
    except Exception as e:
        print(f"发生错误：{e}")
