#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                            ANÁLISIS DE PUERTOS
        A partir de IP y puertos recibidos, se valida si el puerto respuesta
        abierto filtrado o cerrado
        Si la IP no esta informada o si el puerto no esta informado o no es
        numerico, se devuelve un error.
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

"""""""""""""""""""""""""""""""""""""""""""""""""""
                    ESCANEO UDP CON SCAPY
"""""""""""""""""""""""""""""""""""""""""""""""""""

from termcolor import  colored
from scapy.all import *

def scapy_udp(IP_dest,portScan):
    if  IP_dest.isspace()==True or len(IP_dest)==0:
        errorUDPIp=print(colored("IP no informada",'red',attrs=['bold']))
        print("                                              ")
        return errorUDPIp
    else:
        if  portScan.isdigit()==False:
            errorUDPPort=print(colored("Puerto no informado o no numerico",'red',attrs=['bold']))
            print("                                         ")
            return errorUDPPort
        else:
            print("                                         ")
            print(colored("IP a escanear udp: " + str(IP_dest),'green',attrs=['bold']))
            print(colored("Puerto/s a escanear udp: " + str(portScan),'green',attrs=['bold']))
            print("                                         ")
            try:
                respuesta =sr1(IP(dst=IP_dest)/UDP(dport=int(portScan)),timeout=3)
                respuestaUDP=validar_Respuesta(respuesta,portScan)

            except():
                respuestaUDP=print(colored("ERROR INEXPERADO SCANEO UDP: " + str(IP_dest),'red',attrs=['bold']))

            return respuestaUDP

def validar_Respuesta(respuesta,puerto):
    if (str(type(respuesta))=="<class 'NoneType'>"):
        respUDP=print(colored("Tipo de clase Nonetype",'red',attrs=['bold']))

    elif (response.haslayer(UDP)):
        respUDP=print(colored("[+] Puerto " + puerto + " Estado:Abierto",'green',attrs=['bold']))

    elif (response.haslayer(ICMP)):
        if (int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code==3)):
            respUDP=print(colored("[-] Puerto " + puerto + " Estado:Cerrado",'red',attrs=['bold']))

        elif (int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,9,10,13]):
            respUDP=print(colored("[x] Puerto " + puerto + " Estado:Filtrado",'red',attrs=['bold']))
    return respUDP
