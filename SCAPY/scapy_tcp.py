#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                            ANÁLISIS DE PUERTOS
        A partir de IP y puertos recibidos, se valida si el puerto respuesta
        abierto o cerrado
        Si la IP no esta informada o si el puerto no esta informado o no es
        numerico, se devuelve un error.
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

"""""""""""""""""""""""""""""""""""""""""""""""""""
                    ESCANEO TCP CON SCAPY
"""""""""""""""""""""""""""""""""""""""""""""""""""

from termcolor import  colored
from scapy.all import *

def scapy_tcp(IP_dest,portScan):
    if  IP_dest.isspace()==True or len(IP_dest)==0:
        errorTCPIp=print(colored("IP no informada",'red',attrs=['bold']))
        print("                                              ")
        return errorTCPIp
    else:
        if  portScan.isdigit()==False:
            errorTCPPort=print(colored("Puerto no informado o no numerico",'red',attrs=['bold']))
            print("                                         ")
            return errorTCPPort
        else:
            print("                                         ")
            print(colored("IP a escanear: " + str(IP_dest),'green',attrs=['bold']))
            print(colored("Puerto/s a escanear: " + str(portScan),'green',attrs=['bold']))
            print("                                         ")
            try:
                respuesta = sr1(IP(dst=IP_dest)/TCP(dport=int(portScan),flags="S"),timeout=3)
                respuestaTCP=validar_Respuesta(respuesta,portScan)

            except():
                respuestaTCP=print(colored("ERROR INEXPERADO SCANEO TCP: " + str(IP_dest),'red',attrs=['bold']))

            return respuestaTCP
            
def validar_Respuesta(respuesta,puerto):
    if (str(type(respuesta))=="<class 'NoneType'>"):
        respTCP=print (colored("[-] Puerto " + puerto + "  Estado:Cerrado",'red',attrs=['bold']))

    elif (respuesta.haslayer(TCP)):
        if (respuesta.getlayer(TCP).flags==0x12):
            respTCP=print (colored("[+] Puerto " + puerto + "  Estado:Abierto",'green',attrs=['bold']))

    elif (respuesta.haslayer(ICMP)):
        if (respuesta.getlayer(TCP).flags==0x14):
            respTCP=print (colored("[-] Puerto " + puerto + "  Estado:Cerrado",'red',attrs=['bold']))
    return respTCP
