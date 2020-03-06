#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                            ANÁLISIS DE PUERTOS
        A partir de IP y puertos recibidos, se valida si hay o no firewall
        Si la IP no esta informada o si el puerto no esta informado o no es
        numerico, se devuelve un error.
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

"""""""""""""""""""""""""""""""""""""""""""""""""""
                    ESCANEO ACK CON SCAPY
"""""""""""""""""""""""""""""""""""""""""""""""""""

from termcolor import  colored
from scapy.all import *

def scapy_ack(IP_dest,portScan):
    if  IP_dest.isspace()==True or len(IP_dest)==0:
        errorACKIp=print(colored("IP no informada",'red',attrs=['bold']))
        print("                                              ")
        return errorACKIp
    else:
        if  portScan.isdigit()==False:
            errorACKPort=print(colored("Puerto no informado o no numerico",'red',attrs=['bold']))
            print("                                         ")
            return errorACKPort
        else:
            print("                                         ")
            print(colored("IP a escanear: " + str(IP_dest),'green',attrs=['bold']))
            print(colored("Puerto/s a escanear: " + str(portScan),'green',attrs=['bold']))
            try:
                respuesta = sr1(IP(dst=IP_dest)/TCP(dport=int(portScan),flags="A"),timeout=3)
                respuestaACK=validar_Respuesta(respuesta,portScan)

            except():
                respuestaACK=print(colored("ERROR INEXPERADO SCANEO ACK: " + str(IP_dest),'red',attrs=['bold']))

            return respuestaACK

def validar_Respuesta(respuesta,puerto):

    if (str(type(respuesta))=="<class 'NoneType'>"):
        respACK=print (colored("[+] Encontrado firewall",'red',attrs=['bold']))

    elif (respuesta.haslayer(TCP)):

        if (respuesta.getlayer(TCP).flags==0x4):
            print("entro 0x4")
            respACK=print (colored("[-] No encontrado firewall",'green',attrs=['bold']))

    elif (respuesta.haslayer(ICMP)):
        if (respuesta.getlayer(ICMP).type==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("entro type 3 code")
            respACK=print (colored("[+] Encontrado firewall",'red',attrs=['bold']))

    return respACK
