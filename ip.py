import requests
from scapy.all import *
from scapy.layers.l2 import Ether, ARP


class CheckIP:
    def __init__(self):
        # 创建一个空字典,装储ip地址
        self.ip_mac_map = []

    def send_arp(self, ip):
        arp_req = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
        arp_resq = srp(arp_req, timeout=2, verbose=0)[0]
        for arp in arp_resq:
            self.ip_mac_map.append([arp[1].psrc])
        return self.ip_mac_map

    def check_ip(self, ip):
        self.send_arp(ip)  # self.send_arp(ip)是获取ip
        for ip in self.ip_mac_map:
            print(f"{ip}")

    def port_test(self, ip_in, ports):
        ip_lists = self.send_arp(ip_in)
        ports_list = []
        for ip in ip_lists:
            for port in range(ports.start, ports.stop + 1):
                try:
                    url = f"http://{ip[0]}:{port}"
                    res = requests.get(url, timeout=1)
                    if res.status_code == 200:
                        print(f"{ip[0]}的{port}端口开放")
                        ports_list.append(f"{ip[0]}:{port}")
                except requests.exceptions.ConnectionError:
                    print(f"{ip[0]}的{port}端口未开放")
                except Exception as e:
                    print(f"发生错误：{e}")

        return ports_list

    def save_txt(self, items, filename="dict.txt"):
        with open(filename, 'a') as f:
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

