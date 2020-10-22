import os
import sys
import validators
import requests
import json
import socket

import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi

class bcolor:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    WHITE  = '\033[97m'

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

    def geoloca (self, ip, band = "ip"):
        try:
            if band == "url":
                print ("IP :" + ip)
            api_url = "http://ip-api.com/json/"
            param = "city,country,countryCode,isp"
            data = {'fields':param}
            res = requests.get(api_url + ip, data = data)
            resu = json.loads(res.content)
            if resu["status"] == "success":
                return resu["country"]
            return "No información disponible"
        except ValueError as e:
            print ("Decoding JSON ha fallado")
            return "No información disponible"
        except socket.gaierror as e:
            return "No información disponible"

    def find_hash(self, txt):
        API_KEY = "XXXXXXX"   # lIcence 4 request for minute
        vt = VirusTotalPublicApi(API_KEY)
        response = vt.get_file_report(txt)
        print(json.dumps(response, sort_keys=False, indent=4))

    def print_test(self):
        print ("------------------ Resultados ----------------------")

        print ("Cantidad de Ips: {}".format(len(self.ip)))
        print ("Listado de IPS: " + "\n" + "-------------------------")
        for list in self.ip:
            print (bcolor.RED + list + "\n" + "----------------" + bcolor.GREEN)
            data = self.geoloca(list, "ip")
            print ("a. Geolocalización : {}".format(data))
            print ("b. Reputación : " + "\n")

        print ("Cantidad de Hashes: {}".format(len(self.hash)))
        print ("Listado de hashes: " + "\n" + "-------------------------")
        for list in self.hash:
            print (bcolor.RED + list + "\n" + "----------------" + bcolor.GREEN)
            self.find_hash(list)

        print ("Cantidad de Url: {}".format(len(self.url)))
        print ("Listado de Url: " + "\n" + "-------------------------")
        for list in self.url:
            print (bcolor.RED + list + "\n" + "----------------" + bcolor.GREEN)
            data = self.geoloca(list, "url")
            print ("a. Geolocalización : {}".format(data))
            print ("b. Reputación : " + "\n")



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
        if count > 0:
            return False
        return True

if __name__ == "__main__":
    banner()

    file_name = input ("Ingrese la ruta del archivo a analizar (Ejm: ./ioc.csv ): ")
    file_name = "./ioc.csv"
    ioc = ioc(file_name)

    if not ioc.validate_path(file_name):
        print("No existe el archivo")
        sys.exit(1)
    else:
        #ioc.get_format()
        ioc.find_hash("40c46bcab9acc0d6d235491c01a66d4c6f35d884c19c6f410901af6d1e33513b")
