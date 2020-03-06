#!/usr/bin/env python
# -*- coding: utf-8 -*-

##################################################################################
#                           SCANEO NMAP                                          #
#  Se realizara un scaneo sobre una IP o IPs objetivo,segun se elija             #
#  asi como sobre un puerto o intervalo de puertos                               #
#  se indicara el estado del puerto ,el servicio que se ejecuta en dicho puerto  #
#  y la version del mismo                                                        #
##################################################################################

##################################################################################
# import a realizar                                                              #
##################################################################################
import nmap
import sys
import os
import time
from termcolor import colored
from scaneoNMAPsobreIP import *

####################################################
# Se borra las pantalla
####################################################
def borrarPantalla():
    if os.name == "posix":
        os.system ("clear")
    elif os.name == "ce" or os.name == "nt" or os.name == "dos":
        os.system ("cls")
######################################################
# Se valida que la ip tenga formato correcto         #
#al menos que tenga 3  puntos xxx.xxx.xxx.xxx        #
######################################################
def validarIP(IPEntrada):
    totalPuntos=0
    for i in IPEntrada:
        if i==".":
            totalPuntos=totalPuntos +1
        else:
            if i.isdigit()==False:
                print(colored("[-] IP Rango con valores no numericos",'red',attrs=['bold']))
                print("                                                 ")
                time.sleep(3)
                borrarPantalla()
                main()
    if totalPuntos < 3:
        print(colored("[-] IP con formato no valido debe ser del tipo XXX.XXX.XXX.XXX ",'red',attrs=['bold']))
        print("                                                 ")
        time.sleep(3)
        borrarPantalla()
        main()
######################################################
# Se valida que la ip tenga formato correcto         #
# al menos que tenga 2  puntos xxx.xxx.xxx           #
# no debe incluir el ultimo octeto                   #
######################################################
def validarIPRango(IPEntrada):
    totalPuntosRango=0
    for i in IPEntrada:
        if i==".":
            totalPuntosRango=totalPuntosRango +1
        else:
            if i.isdigit()==False:
                print(colored("[-] IP Rango con valores no numericos",'red',attrs=['bold']))
                print("                                                 ")
                time.sleep(3)
                borrarPantalla()
                main()

    if totalPuntosRango < 2:
        print(colored("[-] IP Rango con formato no valido debe ser del tipo XXX.XXX.XXX , sin ultimo octeto",'red',attrs=['bold']))
        print("                                                 ")
        time.sleep(3)
        borrarPantalla()
        main()

######################################################
# Se realiza el scaneo sobre el rango IPs            #
# que llega por parametro                            #
# se convierte en integer los valores desde hasta    #
# se suma 1 al rango hasta pues range con dos        #
# parametros n,m ,va desde n a m-1                   #
######################################################
def NMAPRangoIPs(IPEntrada,desdeRango,hastaRango):

    desdeRangoInt=int(desdeRango)
    hastaRangoInt=int(hastaRango) + 1

    for octeto in range(desdeRangoInt,hastaRangoInt):
        ipTot=IPEntrada + '.' + str(octeto)
        print ("ip con rango: " + ipTot)
        scaneoNMAPsobreIP(ipTot)

######################################################
# Se realiza el scaneo sobre un rango elegido        #
# el metodo de scaneo y puerto o puertos a escanear  #
######################################################
def scaneoNMAPsobreRangoIP(IPEntrada):
    print(colored("1.-INDICAR RANGO DE IP's,DESDE HASTA: ",'green',attrs=['bold']))
    print(colored("e.-SALIR ",'green',attrs=['bold']))
    print("                                                 ")
    opcionRAngo=input(colored("POR FAVOR, ELIJA UNA OPCION: ",'green',attrs=['bold']))
    print("                                                 ")

    if opcionRAngo=="1":
        desdeRango=input(colored("INDICAR RANGO DESDE,EJEMPLO 123: ",'green',attrs=['bold']))
        print("                                                 ")
        hastaRango=input(colored("INDICAR RANGO HASTA,EJEMPLO 123: ",'green',attrs=['bold']))
        print("                                                 ")

        if ( len(desdeRango)==0 or desdeRango.isspace()==True or
           len(hastaRango)==0 or hastaRango.isspace()==True ):
           print(colored("[-] Rango Desde o Hasta no introducido o sin valor.... ",'red',attrs=['bold']))
           print("                                                 ")
           time.sleep(3)
           borrarPantalla()
           main()
        elif desdeRango >= hastaRango:
           print(colored("[-] Rango Desde debe ser menor que Rango Hasta",'red',attrs=['bold']))
           print("                                                 ")
           time.sleep(3)
           borrarPantalla()
           main()
        else:
           NMAPRangoIPs(IPEntrada,desdeRango,hastaRango)
    elif opcionRAngo.lower()=="e":
        print(colored("Retorno menu principal... ",'green',attrs=['bold']))
        print("                                                 ")
        time.sleep(3)
        borrarPantalla()
        main()
    else:
        print(colored("[-] Opcion elegida incorrecta ",'red',attrs=['bold']))
        print("                                                 ")
        time.sleep(3)
        borrarPantalla()
        main()

##################################################################################
# metodo principal, se selecciona si se quiere realizar nmap sobre una IP o      #
# sobre un rango de IPs.Tras elegir un metodo u otro se elige un puerto o        #
# intervalo de puertos y el tipo de scaneo a realizar.                           #
##################################################################################
def main():
    print(colored("********************************************",'blue',attrs=['bold']))
    print(colored("       ESCANEO DE PUERTOS CON NMAP",'blue',attrs=['bold']))
    print(colored("         version:        ",'blue',attrs=['bold']),colored(" 1.0",'yellow',attrs=['bold']))
    print(colored("         Autor:          ",'blue',attrs=['bold']),colored(" Jose Manuel Martinez",'yellow',attrs=['bold']))
    print(colored("         Fecha Creacion: ",'blue',attrs=['bold']),colored(" 2020-02-16",'yellow',attrs=['bold']))
    print(colored("********************************************",'blue',attrs=['bold']))
    print("                                                    ")
    print("                                                    ")

    print(colored("1.-SCANEO DE PUERTOS CON NMAP SOBRE UNA IP",'green',attrs=['bold']))
    print(colored("2.-SCANEO DE PUERTOS CON NMAP SOBRE UN RANGO DE IP's",'green',attrs=['bold']))
    print(colored("e.-SALIR DEL MODULO",'green',attrs=['bold']))
    print("                                                    ")
    opcion=input(colored("POR FAVOR,ELIJA UNA DE LAS OPCIONES: ",'green',attrs=['bold']))
    print("                                                    ")
    if opcion=="1":
        IPEntrada=input(colored("POR FAVOR,INTRODUZCA IP, EJEMPLO XXX.XXX.XXX.XXX: ",'green',attrs=['bold']))
        print("                                                                    ")
        if len(IPEntrada)==0:
            print(colored("[-] Valor IP NO Introducido....",'red',attrs=['bold']))
            time.sleep(2)
            borrarPantalla()
            main()
        else:
            validarIP(IPEntrada)
            scaneoNMAPsobreIP(IPEntrada)
    elif opcion=="2":
        IPEntradaRango=input(colored("POR FAVOR,INTRODIZCA IP SIN EL ULTIMO OCTETO(HOST), EJEMPLO XXX.XXX.XXX: ",'green',attrs=['bold']))
        print("                                                                    ")
        if len(IPEntradaRango)==0:
            print(colored("Valor IP NO Introducido....",'red',attrs=['bold']))
            time.sleep(2)
            borrarPantalla()
            main()
        else:
            validarIPRango(IPEntradaRango)
            scaneoNMAPsobreRangoIP(IPEntradaRango)
    elif opcion.lower()=="e":
        print(colored("Gracias por su visita, hasta la proxima.....",'green',attrs=['bold']))
        exit()
    else:
        print(colored("[-] Error, no se ha elegido una de las opciones esperadas,por favor vuelva a intentarlo",'red',attrs=['bold']))
        time.sleep(2)
        borrarPantalla()
        main()

if __name__== "__main__":
    main()
