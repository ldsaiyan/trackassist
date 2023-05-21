# !/usr/bin/env Python3
# -*- coding: utf-8 -*-
# @FILE     : TrackAssist.py

import time
import re
import json
import logging

import nmap
import ipaddress
from gevent import monkey;monkey.patch_all()
import gevent.queue
import gevent.pool
import requests
from requests.packages import urllib3;urllib3.disable_warnings()
from readability import Document

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
    'cookie': 'Hm_lvt_d5e9e87de330d4ceb8f78059e5df3182=1652335544; Hm_lpvt_d5e9e87de330d4ceb8f78059e5df3182=1652335544; _dd_s=logs=1&id=adcaf65f-7f7c-49f6-a988-4d5b8b74435a&created=1652335533303&expire=1652336450793'
}


class TrackAssist():
    def __init__(self):
        self.pool = gevent.pool.Pool(100)
        self.work = gevent.queue.Queue()
        self.file = "ip.txt"
        self.info = {}
        self.ip_set = set()

        self.get_adress_url = "https://www.ipaddress.com/ipv4/{}"
        self.get_site_url = "https://site.ip138.com/{}/"
        self.get_beian_search_url = "https://www.beian88.com/home/Search"
        self.get_beian_d_url = "https://www.beian88.com/d/{}"
        self.get_whois_url = "http://whois.4.cn/api/main"

    def pretreat(self):
        # logger.info("[*] Load pretreat")
        try:
            file = open(self.file)
            ip_lines = file.readlines()

            for ip_address in ip_lines:
                ip_address = ip_address.strip()
                if ip_address not in self.ip_set:
                    if not ipaddress.ip_address(ip_address).is_private:
                        self.ip_set.add(ip_address)

            file.close()

        except Exception as e:
            logger.info("[-] pretreat() have something problem in {}".format(str(e)))
            return []

    def get_base(self, ip):
        # logger.info("[*] Load get_base")
        try:
            country_pattern = re.compile(r'IP Country</th><td>(?:<i>)?(.*)(?:</i>)?</td>')
            state_pattern = re.compile(r'IP State<\/th><td>(?:<i>)?(.*?) \((.*?)\)(?:<\/i>)?<\/td>')
            city_pattern = re.compile(r'IP City<\/th><td>(?:<i>)?(.*?)(?:<\/i>)?<\/td>')
            ptr_pattern = re.compile(r'PTR</abbr>\)</th><td><a[^>]+>(.+(?:\..+)*)<\/a>')

            get_adress_url = self.get_adress_url.format(str(ip))
            response = requests.get(get_adress_url, headers=headers, verify=False)
            if response.status_code == 200:
                org_pattern = r'Organization</th><td>(?:<i>)?(\w+)(?: </i>)?</td>'
                organization = re.findall(org_pattern, response.text)
                country_match = country_pattern.search(response.text)
                state_match = state_pattern.search(response.text)
                city_match = city_pattern.search(response.text)
                ptr_match = ptr_pattern.search(response.text)

                if organization:
                    Organization = organization[0]
                    self.info[ip]["org"] = "[+]Org: " + Organization

                self.info[ip]["address"] = "[+]Address: "
                if country_match:
                    self.info[ip]["address"] += country_match.group(1)
                else:
                    self.info[ip]["address"] += " unknown"
                if state_match:
                    self.info[ip]["address"] += " " + state_match.group(1)
                else:
                    self.info[ip]["address"] += " unknown"
                if city_match:
                    self.info[ip]["address"] += " " + city_match.group(1)
                else:
                    self.info[ip]["address"] += " unknown"

                if ptr_match:
                    self.info[ip]["ptr"] = "[+]PTR: " + ptr_match.group(1)
                    # return ptr_match.group(1)
                else:
                    return None

        except Exception as e:
            logger.info("[-] get_base() have something problem in {}".format(str(e)))
            return []



    def get_site(self,ip):
        # logger.info("[*] Load get_site")
        try:
            get_site_url = self.get_site_url.format(str(ip))
            req = requests.get(get_site_url, timeout=3, headers=headers, verify=False)
            req.encoding = "utf-8"
            site = re.findall(
                '<li><span\sclass="date">[\d\-\s]+</span><a\shref=".*?"\starget="_blank">(.*?)</a></li>',
                req.text)
            if site != "":
                if type(site) == list and len(site) == 0:
                    return None
                elif type(site) == list and len(site) != 0:
                    site = site[0]

                self.info[ip]["site"] = "[+]Site:" + site
                return site

        except Exception as e:
            logger.info("[-] get_site() have something problem in {}".format(str(e)))
            return []

    def nmap_port(self, ip):
        # logger.info("[*] Load nmap_port")
        try:
            _ip = "\"" + ip + "\""
            nmap_result = []
            n = nmap.PortScanner()
            # print("nmap_port for " + str(ip))

            n.scan(hosts=_ip,
                   arguments="-sV -Pn -p 21,22,80,90,443,1433,1521,3306,3389,6379,7001,7002,8000,8080,8081,8888.8090,9000,9090,9200,50000,50030,50070")
            for x in n.all_hosts():
                # if n[x].hostname() != "":
                #     print("[+]HostName: " + n[x].hostname())
                #     nmap_result.append(n[x].hostname())
                for y in n[x].all_protocols():
                    # print("[+]Protocols: " + y)
                    # nmap_result.append("[+]Protocols: " + y)
                    for z in n[x][y].keys():
                        if n[x][y][z]["state"] == "open":
                            # print("[+]port: " + str(z) + " | name: " + n[x][y][z]["name"] + " | state: " + n[x][y][z]["state"])
                            port_message = "[+]port: " + str(z) + " | name: " + n[x][y][z]["name"] + " | state: " + \
                                           n[x][y][z]["state"]
                            nmap_result.append(port_message)
                self.info[ip]["nmap_result"] = nmap_result[:]

        except Exception as e:
            logger.info("[-] pretreat() have something problem in {}".format(str(e)))
            return []

    def get_title(self, ip, site):
        # logger.info("[*] Load get_title")
        protocols = {'http://': '[+]HTTP Title: ', 'https://': '[+]HTTPS Title: '}
        title_result = []

        for protocol, param in protocols.items():
            url = protocol + site
            try:
                response = requests.get(url, timeout=2, verify=False)
                response.encoding = 'utf-8'
                doc = Document(response.text)
                title = doc.title()

            except Exception as e:
                title = None
                # logger.info("[-] get_title() have something problem in {}".format(str(e)))
                # return []

            if title:
                # print(f'{protocol}{ip}的网站标题为：{title}')
                title_result.append(param + title)

        self.info[ip]["title_result"] = title_result[:]

    def get_beian(self, ip, site):
        # logger.info("[*] Load get_beian")
        try:
            req = requests.post(self.get_beian_d_url, data={'d': site}, timeout=3, headers=headers, verify=False)
            req.encoding = "utf-8"
            key = re.findall('"key":"(.*?)"}', req.text)
            if key:
                get_beian_d_url = self.get_beian_d_url.format(key[0])
                requ = requests.get(get_beian_d_url, timeout=3, headers=headers, verify=False)
                requ.encoding = "utf-8"
                name = re.findall('<span class="field-value" id="ba_Name">(.*?)</span>', requ.text)
                if name[0] != "":
                    webname = re.findall('<span class="field-value" id="ba_WebName">(.*?)</span>', requ.text)
                    type = re.findall('<span class="field-value" id="ba_Type">(.*?)</span>', requ.text)
                    license = re.findall('<span class="field-value" id="ba_License">(.*?)</span>', requ.text)
                    beian_result = ["[+]网站名称:" + webname[0], "[+]主办单位名称:" + name[0],
                                    "[+]主办单位性质:" + type[0],
                                    "[+]网站备案/许可证号:" + license[0]]
                    self.info[ip]["beian_result"] = beian_result[:]

        except Exception as e:
            logger.info("[-] get_beian() have something problem in {}".format(str(e)))
            return []

    def get_whois(self, ip, site):
        # logger.info("[*] Load get_whois")
        try:
            req = requests.post(self.get_whois_url, data={'domain': site}, headers=headers, verify=False)
            json_data = json.loads(req.text)

            if json_data['retcode'] == 0 and json_data['data']['owner_name'] != '':
                whois_result = ["[+]域名所有者:" + json_data['data']['owner_name'],
                                "[+]域名所有者邮箱:" + json_data['data']['owner_email'],
                                "[+]域名所有者注册:" + json_data['data']['registrars']]
                self.info[ip]["whois_result"] = whois_result[:]

        except Exception as e:
            logger.info("[-] get_whois() have something problem in {}".format(str(e)))
            return []

    def put_queue(self):
        try:
            # logger.info("[*] Load put_queue")
            for ip_address in self.ip_set:
                self.work.put_nowait(ip_address)
                self.info[ip_address] = {"address": "", "org": "", "attribute": "", "ptr": "", "site": "", "title_result": [],
                                         "nmap_result": [],
                                         "beian_result": [], "whois_result": []}

        except Exception as e:
            logger.info("[-] put_queue() have something problem in {}".format(str(e)))
            return []

    def get_queue(self):
        while not self.work.empty():
            self.build(self.work.get_nowait())

    def build(self, ip):
        self.get_base(ip)
        site = self.get_site(ip)
        self.nmap_port(ip)
        if site != None:
            self.get_title(ip, site)
            self.get_beian(ip, site)
            self.get_whois(ip, site)

    def run(self):
        # logger.info("[*] Load run")
        self.pretreat()
        self.put_queue()

        for i in range(100):
            self.pool.apply_async(self.get_queue)
        self.pool.join()

        while True:
            time.sleep(0.0001)
            if self.work.empty():
                break


if __name__ == '__main__':
    start = time.time()
    test = TrackAssist()
    test.run()
    end = time.time()
    print("\nThe script spend time is %.3f seconds" % (end - start))

    for key, value in test.info.items():
        print(key)
        print(value["address"]) if value["address"] != "" else None
        print(value["org"]) if value["org"] != "" else None
        print(value["ptr"]) if value["ptr"] != "" else None
        print(value["site"]) if value["site"] != "" else None
        [print(i) for i in value["title_result"]] if len(value["title_result"]) > 0 else None
        [print(i) for i in value["nmap_result"]] if len(value["nmap_result"]) > 0 else None
        [print(i) for i in value["beian_result"]] if len(value["beian_result"]) > 0 else None
        [print(i) for i in value["whois_result"]] if len(value["whois_result"]) > 0 else None
