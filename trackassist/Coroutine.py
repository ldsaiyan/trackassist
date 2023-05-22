# !/usr/bin/env Python3
# -*- coding: utf-8 -*-
# @FILE     : Coroutine.py

import time
import warnings;warnings.filterwarnings("ignore")

from gevent import monkey;monkey.patch_all()
import gevent.queue
import gevent.pool
from requests.packages import urllib3;urllib3.disable_warnings()


class Coroutine():
    def __init__(self):
        self.pool = gevent.pool.Pool(100)
        self.work = gevent.queue.Queue()
        self.url = "ip.txt"
        self.info = []

    def put_queue(self):
        with open(self.url) as f:
            for url in f:
                url = url.replace('\n', '')
                self.work.put_nowait(url)
                self.info.append(url)

    def get_queue(self):
        while not self.work.empty():
            self.build(self.work.get_nowait())

    def build(self,ip):
        print(ip)
        time.sleep(1)

    def run(self):
        self.put_queue()

        for i in range(100):
            self.pool.apply_async(self.get_queue)
        self.pool.join()

        while True:  # 防止主线程结束
            time.sleep(0.0001)  # 避免cpu空转，浪费资源
            if self.work.empty():
                break

if __name__ == '__main__':
    start = time.time()
    test = Coroutine()
    test.run()
    end = time.time()
    print("\nThe script spend time is %.3f seconds" % (end - start))
