#AsFast_Scanner

#!/usr/bin/env python
import scapy.all as scapy
import optparse
import os

def get_args():
        parser = optparse.OptionParser()
        parser.add_option("-t", "--target", dest="target", help="for help")
        (options, args) = parser.parse_args()
        return options

def scanner(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        pack = broadcast/arp_request
        ans_list = scapy.srp(pack, timeout=1)[0]
        client_list = []
        for element in ans_list:
                client_dict = {"ip": element[1].psrc, "mac" : element[1].hwsrc}
                client_list.append(client_dict)
        return client_list

def print_res(results_list):
        print("    IP \t\t\t MAC Address\n-------------------------------------------")
        for client in results_list:
                print(client["ip"] + "\t\t" + client["mac"])


# for windows
os.system('cls')
print('''
╭━━━╮╱╱╭━━━╮╱╱╱╱╱╭╮╱╭━━━╮
┃╭━╮┃╱╱┃╭━━╯╱╱╱╱╭╯╰╮┃╭━╮┃
┃┃╱┃┣━━┫╰━━┳━━┳━┻╮╭╯┃╰━━┳━━┳━━┳━╮╭━╮╭━━┳━╮
┃╰━╯┃━━┫╭━━┫╭╮┃━━┫┃╱╰━━╮┃╭━┫╭╮┃╭╮┫╭╮┫┃━┫╭╯
┃╭━╮┣━━┃┃╱╱┃╭╮┣━━┃╰╮┃╰━╯┃╰━┫╭╮┃┃┃┃┃┃┃┃━┫┃
╰╯╱╰┻━━┻╯╱╱╰╯╰┻━━┻━╯╰━━━┻━━┻╯╰┻╯╰┻╯╰┻━━┻╯''')
options = get_args()
scanner_res = scanner(options.target)
print_res(scanner_res)
