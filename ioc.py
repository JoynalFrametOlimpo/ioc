import os
import sys
import validators
import requests
import json

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

    def geoloca (self, ip):
        try:
            api_url = "http://ip-api.com/json/"
            param = "city,country,countryCode,isp"
            data = {'fields':param}
            res = requests.get(api_url + ip, data = data)
            return json.loads(res.content)
        except json.decoder.JSONDecodeError as e:
            print ("Error datos")
            return ""
#51.195.148.18
    def print_test(self):
        print ("------------------ Resultados ----------------------")
        print ("Cantidad de Ips: {}".format(len(self.ip)))
        print ("Listado de IPS: " + "\n" + "-------------------------")
        for list in self.ip:
            print (bcolor.RED + list + "\n" + "----------------" + bcolor.GREEN)
            print (len(list))
            print ("a. Geolocalización : {}".format(self.geoloca(list)["country"]))
            print ("b. Reputación : " + "\n")
        print ("Cantidad de Hashes: {}".format(len(self.hash)))
        print ("Listado de hashes: " + "\n" + "-------------------------")
        for list in self.hash:
            print (list)
        print ("Cantidad de Url: {}".format(len(self.url)))
        print ("Listado de Url: " + "\n" + "-------------------------")
        for list in self.url:
            print (list)

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
        ioc.get_format()
