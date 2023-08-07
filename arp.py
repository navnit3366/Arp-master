#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import ARP, Ether, srp
import sys


def arp_scan(ip):
    # ARP(pdst) cria o objeto ARP
    # pdst quer dizer "Target protocol address" ou "Endereço Alvo do Protocolo"
    arp_request = ARP(pdst=ip)
    # Ether(dst) cria a objeto Ethernet
    # dst quer dizer "Broadcast MAC Address" ou "Endereço MAC de Transmissão"
    # 'ff:ff:ff:ff:ff:ff' é o valor padrão
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast/arp_request cria o pacote a ser enviado
    arp_request_broadcast = broadcast/arp_request
    # a funcão srp() envia o pacote

    # a função sr() é usada para enviar pacotes e receber respostas
    # e retorna um par de pacotes e resposta além dos pacotes não recebidos

    # a função sr1() é uma variação que só retorna apenas um pacote
    # que respondeu ao pacote enviado
    # os pacotes dessa função são camada 3(ex: IP)

    # a função srp() faz o mesmo com pacotes da camada 2(ex: Ethernet)
    # o timeout define quanto tempo o sistema deve esperar
    # depois que o ultimo pacote foi enviado
    answered_list = srp(arp_request_broadcast, timeout=2)[0]
    # answered_list é a lista com todas as respostas
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_formatted(results):
    header_footer = '+{:<20}-{:<20}+'.format('-'*20, '-'*20)
    division = '|{:<20}+{:<20}|'.format('-'*20, '-'*20)

    print (header_footer)
    print ('|{:<20}|{:<20}|'.format('IP', 'MAC address'))

    if len(results) > 0:
        print (division)
        for result in results:
            print ('|{:<20}|{:<20}|'.format(result['ip'], result['mac']))
            print (division)
    else:
        print (division)
        print ('|{:<41}|'.format('NO ANSWER'))
        print(header_footer)


if __name__ == '__main__':
    if len(sys.argv) > 2:
        ip = sys.argv[1]
    else:
        ip = '8.8.8.8/80'

    scan_result = arp_scan(ip)
    print_formatted(scan_result)
