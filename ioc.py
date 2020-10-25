import os
import sys
import validators
import requests
import json
import socket
from lxml.html import fromstring
from itertools import cycle
import urllib3
import datetime
import subprocess
import time

import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi

class bcolor:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    WHITE  = '\033[97m'

# class proxies:
#     proxies = {
#       'https': 'http://165.22.36.75:8888',
#       'http': 'http://67.207.83.225:80',
#       'http': 'http://67.207.83.225:80',
#     }

class banner:
    def __init__(self):
        flag = """
          =======================================================================================================
          *       ********     ******     **       **   **         **     ******    **           '``'           *
          *          **       **    **     **     **    ** **      **   **     **   **          '- framet'?''   *
          *          **       **    **      **   **     **  **     **   **     **   **            ''    ''      *
          *          **       **    **       ** **      **    **   **   *********   **                          *
          *          **       **    **        ***       **     **  **   **     **   **                          *
          *     **   **       **    **         **       **      *****   **     **   **       **                 *
          *      *****         ******          **       **        ***   **     **   ***********                 *
          =======================================================================================================
            """
        print(bcolor.GREEN + flag)

class ioc:
    file_name = ""
    url = []
    url_ok = []    # Url not malicios
    ip = []
    ip_ok = []      # Ips not malicious
    hash = []
    file = []
    hash_malicius = 0
    hash_undetected = 0
    hash_mal_vendor_count = {'McAfee': 0,
                            'Kaspersky':0,
                            'ESET-NOD32':0,
                            'F-Secure':0,
                            'Bkav':0 }
    hash_und_vendor_count = {'McAfee': 0,
                            'Kaspersky':0,
                            'ESET-NOD32':0,
                            'F-Secure':0,
                            'Bkav':0 }

    def __init__(self, file_name):
        self.file_name = file_name

    def validate_path(self, file_name):
        if not os.path.isfile(file_name):
            return False
        else:
            return True

    def get_format(self):
        url = []
        i = 0
        file = open(self.file_name, 'r')
        for data in file:
            text = data.replace("[.]",".")
            text = text.strip()
            if text != "":
                if self.validate_ip(text) == True:
                    self.ip.append(text)
                else:
                    if self.validate_hash(text) == True:
                        self.hash.append(text)
                    else:
                        if self.validate_url(text) == True:
                            self.url.append(text)

        self.print_test()

    def get_proxies(self):
        url = 'https://free-proxy-list.net/'
        response = requests.get(url)
        parser = fromstring(response.text)
        proxies = set()
        for i in parser.xpath('//tbody/tr')[:10]:
            if i.xpath('.//td[7][contains(text(),"yes")]'):
                proxy = ":".join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
                proxies.add(proxy)
        return proxies

    def geoloca (self, ip, band = "ip", proxy= "127.0.0.1"):
        try:
            if band == "url":
                ip = socket.gethostbyname(ip)
        except socket.gaierror as e:
            return ""
            raise
        api_url = "http://ipwhois.app/json/"
        param = "country"
        data = {'fields':param}
        try:
            res = requests.get(api_url + ip, data = data ,  timeout=6).json()
            if res['success'] == True:
                return res["country"]
            else:
                print ("No hay información disponible")
        except Exception as e:
            print (e)

    def score(self, ip, band = "ip", proxy = "127.0.0.1"):
        try:
            if band == "url":
                ip = socket.gethostbyname(ip)
        except socket.gaierror as e:
            return ""
            raise
        api_url = "https://scamalytics.com/ip/"
        try:
            cmd = "curl -s " + api_url + ip
            text = subprocess.check_output(cmd.split())
            return str(text).split("IP address <b>" + ip + "</b>")[1].split("</div>")[0]
        except Exception as  e:# -*- coding: utf-8 -*-
            print (e)
            return "no"

    def find_hash(self, txt):
        API_KEY = "c191181dc1e97a46ff462d0c9acf1efc6fec1b8479aaf61c58c303f41fabd946"   # lIcence 4 request for minute
        URL = "https://www.virustotal.com/api/v3/files/%s"
        headers = {"x-apikey": API_KEY}
        success = False
        debug=False
        vez = 0

        p = self.get_proxies()
        proxy_pool = cycle(p)
        while not success:
            try:
                if vez < 4: # It's about licence Virus Total 4 request for minute
                    response_dict_code = requests.get(URL % txt, headers=headers)
                    response = json.loads(response_dict_code.content.decode("utf-8"))
                    vez += 1
                else:
                    response_dict_code.close()
                    vez = 0

                if vez < 4 :
                    self.file_append ("Clasificación de McAfee: " + str(self.comprobate_hash(response,'McAfee')))
                    self.file_append ("Clasificación de Kaspersky: " + str(self.comprobate_hash(response,'Kaspersky')))
                    self.file_append ("Clasificación de ESET-NOD32: " + str(self.comprobate_hash(response,'ESET-NOD32')))
                    self.file_append ("Clasificación de F-Secure: " + str(self.comprobate_hash(response,'F-Secure')))
                    self.file_append ("Clasificación de Bkav: " + str(self.comprobate_hash(response,'Bkav')))
                    self.file_append ("\n\n")
                success = True
            except Exception as e:
                if debug:
                    proxies = self.get_proxies()
                    proxy_pool = cycle(proxies)
                    traceback.print_exc()
                response_dict_code.close()

    def find_hash_antivirues(self, txt, antivirues):
        if antivirues == "K":
            url = "https://opentip.kaspersky.com/"

        cmd = "curl -s " + txt
        text = subprocess.check_output (cmd.split())


    def comprobate_hash(self,hash,type):
        try:
            cad = hash['data']['attributes']['last_analysis_results'][type]['category']
            if cad == "malicious":
                self.hash_mal_vendor_count[type] +=1
                self.hash_malicius += 1
            else:
                self.hash_und_vendor_count[type] +=1
                self.hash_undetected += 1
            return cad
        except Exception as e:
            self.file_append ("No se encoentraron datos de Hash")
            self.file_append ("\n\n")
            raise

    def print_test(self):
        self.file_append("----------------- Ejecución ---------------------")
    #################### IPs #################################################################
        self.file_append ("Listado de IPS: " + "\n" + "-------------------------")
        proxy = "127.0.0.1"
        for list in self.ip:
            self.file_append (list)
            self.file_append ("---------------------")
    ###################### Geolocalización ##################################
            try:
                data = self.geoloca(list, "ip", proxy)
                self.file_append ("Ip a validar: " + list +  " -  Proxy: " + str(proxy) )
                self.file_append ("a. Geolocalización : " + data)
        ##################### Score #######################################################
                data = self.score(list,"ip", proxy)
                self.file_append ("b. Reputación : " + data)
                self.file_append ("\n\n")
            except Exception as e:
                continue
    ####################### uRL #########################################################333
        self.file_append ("Listado de Url: " + "\n" + "-------------------------")
        for list in self.url:
            self.file_append (list)
            self.file_append ("---------------------")
            ################## geolocalizaion #############################
            try:
                data = self.geoloca(list, "url", proxy)
                self.file_append("URL : " + list + " ---- IP: " + str(socket.gethostbyname(list)))
                self.file_append ("a. Geolocalización : " + data)
                ################## Score #######################################
                data = self.score(list,"url", proxy)
                self.file_append ("b. Reputación : " + data)
                self.file_append ("\n")
            except socket.gaierror as e:
                self.file_append("URL no esta asignada a una IP")
                continue
            except Exception as e:
                continue

    ######################## Hashes #######################################################
        self.file_append("Listado de hashes: " + "\n" +  "-------------------------")
        request = 0
        for list in self.hash:
            self.file_append ("Hash : "  +  list)
            self.find_hash(list)

    ######################## Resultados Finales #############################################
        self.file_append(" ************* RESULTADOS ************** " + "\n")
        self.file_append("Cantidad de Url: " + str(len(self.url)))
        self.file_append("Cantidad de Ips: " + str(len(self.ip)))
        self.file_append("Cantidad de Hashes: " + str(len(self.hash)))
        self.file_append("\n\n")

        self.file_append("Cantidad de Hashes detectadas Maliciosas por Antivirus:" + "\n")
        self.file_append("--------------------------------------" + "\n")
        self.file_append("McAfee: " + str(self.hash_mal_vendor_count['McAfee']))
        self.file_append("Kaspersky: " + str(self.hash_mal_vendor_count['Kaspersky']))
        self.file_append("ESET-NOD32: " + str(self.hash_mal_vendor_count['ESET-NOD32']))
        self.file_append("F-Secure: " + str(self.hash_mal_vendor_count['F-Secure']))
        self.file_append("Bkav: " + str(self.hash_mal_vendor_count['Bkav']))
        self.file_append("\n\n")

        self.file_append("Cantidad de Hashes No detectadas por Antivirus:" + "\n")
        self.file_append("--------------------------------------" + "\n")
        self.file_append("McAfee: " + str(self.hash_und_vendor_count['McAfee']))
        self.file_append("Kaspersky: " + str(self.hash_und_vendor_count['Kaspersky']))
        self.file_append("ESET-NOD32: " + str(self.hash_und_vendor_count['ESET-NOD32']))
        self.file_append("F-Secure: " + str(self.hash_und_vendor_count['F-Secure']))
        self.file_append("Bkav: " + str(self.hash_und_vendor_count['Bkav']))
        self.file_append("\n\n")

        self.write_file()

    def file_append (self, line):
        self.file.append (line)
        self.file.append("\n")
        print (line)

    def write_file (self):
        cmd = "echo " + str(self.file) + " > ./resultado_" + str(datetime.datetime.now()) + ".txt"
        os.system(cmd)

    def validate_ip(self, txt):
        if validators.ipv4(txt) or validators.ipv6(txt):
            return True
        return False

    def validate_url(self,txt):
        if validators.domain(txt) == True:
            return True
        return False

    def validate_hash(self,txt):
        count = txt.count(".")
        count += txt.count(" ")
        count += txt.count("_")
        if count > 0:
            return False
        return True

if __name__ == "__main__":
    banner()

    file_name = input ("Ingrese la ruta del archivo a analizar (Default: ./ioc.csv ): ")
    if file_name == "":
        file_name = "./ioc.csv"
    ioc = ioc(str(file_name))

    if not ioc.validate_path(file_name):
        print("No existe el archivo")
        sys.exit(1)
    else:
        ioc.get_format()
