#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                            ANÁLISIS DE VULNERABILIDADES

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

"""""""""""""""""""""""""""""""""""""""""""""""""""
                    ESCANEO XMAS
"""""""""""""""""""""""""""""""""""""""""""""""""""

from termcolor import  colored
from scapy.all import *

def scapy_xmas(IP_dest,portScan):
    if  IP_dest.isspace()==True or len(IP_dest)==0:
        errorXMASIp=print(colored("IP no informada",'red',attrs=['bold']))
        print("                                              ")
        return errorXMASIp
    else:
        if  portScan.isdigit()==False:
            errorNULLPort=print(colored("Puerto no informado o no numerico",'red',attrs=['bold']))
            print("                                         ")
            return errorXMASPort
        else:
            print("                                         ")
            print(colored("IP a escanear xmas: " + str(IP_dest),'green',attrs=['bold']))
            print(colored("Puerto/s a escanear xmas: " + str(portScan),'green',attrs=['bold']))
            try:
                respuesta = sr1(IP(dst=IP_dest)/TCP(dport=int(portScan),flags="FPU"),timeout=3)
                respuestaXMAS=validar_Respuesta(respuesta,portScan)

            except():
                respuestaXMAS=print(colored("ERROR INEXPERADO SCANEO XMAS: " + str(IP_dest),'red',attrs=['bold']))

            return respuestaXMAS

def validar_Respuesta(respuesta,puerto):
    if respuesta is None:
        respXMAS=print ("[+] Puerto %s Abierto o filtrado " % (puerto))
    elif (respuesta.haslayer(TCP) and respuesta.getlayer(TCP).flags == 0x14):
        respXMAS=print ("[-] Puerto %s Cerrado " % (puerto))
    elif (respuesta.haslayer(ICMP) and respuesta.getlayer(ICMP).type == 3):
        respXMAS=print ("[x] Puerto %s Filtrado " % (puerto))
    else:
        respXMAS=print ("Puerto inválido")

    return respXMAS
