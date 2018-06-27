#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ARP cache Poisonning

import socket

class ARPCP:
    """ Classe principale qui crée un packet ARP avec l'adresse mac associé à l'ip. """
    def __init__(self, mac, spoofed_ip):
        # Construction du packet
        self.mac = ARPCP.mth(mac)
        self.spoofed_ip = ARPCP.ith(spoofed_ip)
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

    def send(self, target, mac='00:50:56:c0:00:08'): 
        # Envoie du packet sur le réseau à l'host target
        """ arp = "
        \x00\x0c\x29\x6c\xc9\xc0
        \x00\x50\x56\xe6\xde\x35
        \x08\x06
        \x00\x01\x08\x00\x06\x04\x00\x02
            \x00\x50\x56\xe6\xde\x35
            \xac\x10\x40\x02
            \x00\x0c\x29\x6c\xc9\xc0
            \xac\x10\x40\x86
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
        "
        #socket.gethostbyaddr(target)
        #self.packet.hwdst = mac
        #self.packet.pdst = target
        #self.send(packet)
        """
        pass
            
    def ith(ip_addr):
        """ Retourne une adresse IP sous hexadécimal. """
        h_ip = [hex(int(i)) for i in ip_addr.split('.')]
        print h_ip
        return None            
    ith = staticmethod(ith)
        
    def mth(mac_addr):
        """ Retourne une adresse MAC sous hexadécimal. """
        return None
    mth = staticmethod(mth)

if __name__ == '__main__':
    a = ARPCP("00:50:56:c0:00:08", "127.0.0.1")
