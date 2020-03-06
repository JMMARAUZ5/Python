#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                            ANÁLISIS DE VULNERABILIDADES

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

"""""""""""""""""""""""""""""""""""""""""""""""""""
                    ESCANEO NULL
"""""""""""""""""""""""""""""""""""""""""""""""""""
from termcolor import  colored
from scapy.all import *

def scapy_null(IP_dest,portScan):
    if  IP_dest.isspace()==True or len(IP_dest)==0:
        errorNULLIp=print(colored("IP no informada",'red',attrs=['bold']))
        print("                                              ")
        return errorNULLIp
    else:
        if  portScan.isdigit()==False:
            errorNULLPort=print(colored("Puerto no informado o no numerico",'red',attrs=['bold']))
            print("                                         ")
            return errorNULLPort
        else:
            print("                                         ")
            print(colored("IP a escanear null: " + str(IP_dest),'green',attrs=['bold']))
            print(colored("Puerto/s a escanear null: " + str(portScan),'green',attrs=['bold']))
            try:
                respuesta = sr1(IP(dst=IP_dest)/TCP(dport=int(portScan),flags=""),timeout=3)
                respuestaNULL=validar_Respuesta(respuesta,portScan)

            except():
                respuestaNULL=print(colored("ERROR INEXPERADO SCANEO NULL: " + str(IP_dest),'red',attrs=['bold']))

            return respuestaNULL

def validar_Respuesta(respuesta,puerto):
    if (str(type(respuesta))=="<class 'NoneType'>"):
        respNULL=print ("[+] Puerto %s Abierto " % (puerto))

    elif (respuesta.haslayer(TCP)):
        if (respuesta.getlayer(TCP).flags==0x14):
            respNULL=print ("[-] Puerto %s Cerrado " % (puerto))

    elif (respuesta.haslayer(ICMP)):
        if (respuesta.getlayer(ICMP).type==3 and int(respuesta.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            respNULL=print ("[x] Puerto %s Filtrado " % (puerto))

    return respNULL
