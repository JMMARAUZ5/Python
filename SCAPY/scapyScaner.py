#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
                   SCANER CON SCAPY
    SE ESCANEA IP Y PUERTO CON LOS DISTINTOS METODOS
    NECESARIO PERMISOS DE ROOT PARA PODER EJECUTAR SCRITP
    EJ: sudo python3 scapyScaner.py
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from termcolor import colored
from scapy_tcp import *
from scapy_udp import *
from scapy_ack import *
from scapy_null import *
from scapy_xmas import *
import time

####################################################
# Se borra las pantalla
####################################################
def borrarPantalla():
    if os.name == "posix":
        os.system ("clear")
    elif os.name == "ce" or os.name == "nt" or os.name == "dos":
        os.system ("cls")

def scapy_TCP():
    IP=informarIP()
    puerto=informarPuerto()
    resultadoTCP=scapy_tcp(IP,puerto)
    print(resultadoTCP)
    print(colored("Regreso menu principal en 3,2,1.....: ",'green',attrs=['bold']))
    time.sleep(3)
    borrarPantalla()
    main()

def scapy_ACK():
    IP=informarIP()
    puerto=informarPuerto()
    resultadoACK=scapy_ack(IP,puerto)
    print(resultadoACK)
    print(colored("Regreso menu principal en 3,2,1.....: ",'green',attrs=['bold']))
    time.sleep(3)
    borrarPantalla()
    main()

def scapy_UDP():
    IP=informarIP()
    puerto=informarPuerto()
    resultadoUDP=scapy_udp(IP,puerto)
    print(resultadoUDP)
    print(colored("Regreso menu principal en 3,2,1.....: ",'green',attrs=['bold']))
    time.sleep(3)
    borrarPantalla()
    main()

def scapy_NULL():
    IP=informarIP()
    puerto=informarPuerto()
    resultadoNULL=scapy_null(IP,puerto)
    print(resultadoNULL)
    print(colored("Regreso menu principal en 3,2,1.....: ",'green',attrs=['bold']))
    time.sleep(3)
    borrarPantalla()
    main()

def scapy_XMAS():
    IP=informarIP()
    puerto=informarPuerto()
    resultadoXMAS=scapy_xmas(IP,puerto)
    print(resultadoXMAS)
    print(colored("Regreso menu principal en 3,2,1.....: ",'green',attrs=['bold']))
    time.sleep(3)
    borrarPantalla()
    main()

def informarIP():
    IPopcion=input(colored("Introduzca IP ,por favor: ",'green',attrs=['bold']))
    return IPopcion

def informarPuerto():
    puertoOpcion=input(colored("Introduzca Puerto ,por favor: ",'green',attrs=['bold']))
    return puertoOpcion



def main():
    print(colored("=============================",'green',attrs=['bold']))
    print(colored("ESCANEOS DE PUERTOS CON SCAPY",'green',attrs=['bold']))
    print(colored("=============================",'green',attrs=['bold']))
    print("                                                             ")
    print(colored("1.-ESCANEO ACK",'green',attrs=['bold']))
    print(colored("2.-ESCANEO NULL",'green',attrs=['bold']))
    print(colored("3.-ESCANEO TCP",'green',attrs=['bold']))
    print(colored("4.-ESCANEO UDP",'green',attrs=['bold']))
    print(colored("5.-ESCANEO XMAS",'green',attrs=['bold']))
    print(colored("6.-EXIT DEL SCANER SCAPY",'green',attrs=['bold']))
    print("                                                              ")
    opcion=input(colored("Elija opcion de scaneo scapy: ",'green',attrs=['bold']))

    if opcion=="1":
        scapy_ACK()
    elif opcion=="2":
        scapy_NULL()
    elif opcion=="3":
        scapy_TCP()
    elif opcion=="4":
        scapy_UDP()
    elif opcion=="5":
        scapy_XMAS()
    elif opcion=="6":
        print(colored("Gracias por su visita,hasta la proxima .....",'green',attrs=['bold']))
    else:
        print(colored("Debe de elegir opcion 1,2,3,4 o 5",'red',attrs=['bold']))
        time.sleep(2)
        borrarPantalla()
        main()

if __name__=="__main__":
    main()
