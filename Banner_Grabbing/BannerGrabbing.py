#!/usr/bin/env python
# -*- coding: utf-8 -*-

##################################################################################
#                           BANNER GRABBING                                      #
#  Se pasa por parametro la ip objetivo  yse dispone de dos ficheros             #
#  uno con un listado de puertos y otro con las vulnerabilidades a estudiar      #
#  se valida cada vulnerabilidad para cada puerto                                #
##################################################################################

import socket
import sys
import os
import time
from termcolor import colored

################################################################
# Funcion para obtener el banner de un puerto para una IP dada #
# establecemos una relacion cliente servidor utilizando socket #
# creamos objeto socket con la funcion socket e indicamos el   #
# el protocolo en este caso AF_INET y el tipo de comunicacion  #
# SOCK_STREAM-->protocolo orientado a comunicaciones TCP       #
# recv-->1024 cantidad de datos maxima que se puede recibir de #
# una vez                                                      #
################################################################
def obtenerBanner(ipEnt,puerto,vulnerabilidad):
  print("ip: " + ipEnt)
  print("puerto: " + puerto)
  print("vulnerabilidad: " + vulnerabilidad)

  try:
      conexion=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      socket.setdefaulttimeout(5)
      conexion.connect((ipEnt,int(puerto)))      
      socket.setdefaulttimeout(5)
      banner = conexion.recv(1024)
      print ("banner obtenido: " + str(banner).strip())

      if str(vulnerabilidad).strip() in str(banner).strip():
          print (colored('***************************************','green',attrs=['bold']))
          print (colored('[+] EL BANNER ES VULNERABLE','green',attrs=['bold']))
          print (colored('[+] IP            : ' + ipEnt,'green',attrs=['bold']))
          print (colored('[+] PUERTO        : ' + puerto,'green',attrs=['bold']))
          print (colored('[+] VULNERABILIDAD: ' + vulnerabilidad,'green',attrs=['bold']))
          print (colored('***************************************','green',attrs=['bold']))
      else:
          print (colored('***************************************','red',attrs=['bold']))
          print (colored('[-] EL BANNER NO ES VULNERABLE','red',attrs=['bold']))
          print (colored('[-] IP            : ' + ipEnt,'red',attrs=['bold']))
          print (colored('[-] PUERTO        : ' + puerto,'red',attrs=['bold']))
          print (colored('***************************************','red',attrs=['bold']))
  except ConnectionRefusedError as e:
      print (colored('***************************************','red',attrs=['bold']))
      print(colored("CONEXION REFUSED",'red',attrs=['bold']))
      print(colored("PUERTO: " + puerto ,'red',attrs=['bold']))
      print (colored('***************************************','red',attrs=['bold']))
  except ConnectionResetError as e:
      print (colored('***************************************','red',attrs=['bold']))
      print(colored("CONEXION RESET ERROR",'red',attrs=['bold']))
      print(colored("PUERTO: " + puerto ,'red',attrs=['bold']))
      print (colored('***************************************','red',attrs=['bold']))
  except socket.timeout as e:
      print (colored('***************************************','red',attrs=['bold']))
      print(colored("TIMEOUT EN CONEXION",'red',attrs=['bold']))
      print(colored("PUERTO: " + puerto ,'red',attrs=['bold']))
      print (colored('***************************************','red',attrs=['bold']))
  except:
      print(colored("ERROR INESPERADO AL INTENTAR CONEXION AL SOCKET",'red',attrs=['bold']))
      exit()
##################################################################
# Leemos fichero de vulnerabilidades                             #
#################################################################
def leerFichVuln(fichEnt):
    leerFichV=open(fichEnt,'r').readlines()
    leerFichVFinal=(vulnera.strip() for vulnera in leerFichV)
    return leerFichVFinal
##################################################################
# Leemos fichero de puertos                                     #
#################################################################
def leerFichPort(fichEnt):
    leerFichP=open(fichEnt,'r').readlines()
    leerFichPFinal=(port.strip() for port in leerFichP)
    return leerFichPFinal
##################################################################
# Validamos que el fichero de puertos existe                     #
# en la ruta indicada,si no exite e devuelve error               #
#################################################################
def validarFicheroPuerto(dir,fichEntPuertos):
    name_dir = os.path.join(os.path.dirname(__file__),dir)

    name_file = os.path.join(name_dir,fichEntPuertos)

    if not os.path.isfile(name_file):
        print(colored("No existe el fichero de puertos indicado,por favor revise nombre fichero",'red',attrs=['bold']))
        exit()
    elif os.stat(name_file).st_size == 0:
        print(colored("El fichero de puertos esta vacio",'red',attrs=['bold']))
        exit()
    else:
        leerPort=leerFichPort(name_file)

    return leerPort
##################################################################
# Validamos que el fichero de vulnerabilidades exista            #
# en la ruta indicada,si no exite e devuelve error               #
#################################################################
def validarFicheroVuln(dir,fichEntVuln):
    name_dir = os.path.join(os.path.dirname(__file__),dir)

    name_file = os.path.join(name_dir,fichEntVuln)

    if not os.path.isfile(name_file):
        print(colored("No existe el fichero de vulnerabilidades indicado,por favor revise nombre fichero",'red',attrs=['bold']))
        exit()
    elif os.stat(name_file).st_size == 0:
        print(colored("El fichero de puertos esta vacio",'red',attrs=['bold']))
        exit()
    else:
        leerVuln=leerFichVuln(name_file)

    return leerVuln
##################################################################
# Vamos al menu principal se pide IP objetivo                    #
# Se validan que los ficheros existan.                           #
# se valida que los ficheros no esten vacios y se realiza        #
# mediante la api socket conexion con la maquina objetivo para   #
# recuperar el banner y validarlo para cada vulnerabilidad       #
# y para cada uno de los puertos                                 #
##################################################################
def main():
   print(colored("***********************************************************",'green',attrs=['bold']))
   print(colored("ESTUDIO VULNERABILIDADES IP-PUERTOS TECNICA BANNER-GRABBING",'green',attrs=['bold']))
   print(colored("***********************************************************",'green',attrs=['bold']))
   print(colored("                                                           ",'green',attrs=['bold']))
   ipEnt=input(colored("Por favor, indique IP objetivo: ",'green',attrs=['bold']))

   if len(ipEnt)==0:
       print(colored("Introduzca IP valida, IP no ha sido informada",'red',attrs=['bold']))
       exit()
   else:
       leerPort=validarFicheroPuerto("ficherosEnt","puertos.txt")
       leerVuln=validarFicheroVuln("ficherosEnt","vulnerables.txt")

       for vulnerabilidad in leerVuln:
           for puerto in leerPort:
                obtenerBanner(ipEnt,puerto,vulnerabilidad)
                leerPort=validarFicheroPuerto("ficherosEnt","puertos.txt")

if __name__ == '__main__':
  main()
