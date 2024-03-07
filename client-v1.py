from asyncore import loop
from socket import timeout
from requests import get,post
import http.client
from urllib import request, parse
from urllib.request import urljoin
from json import dump
from time import sleep
from urllib import parse
from datetime import datetime, timedelta
from scapy.all import *
import asyncio

import json
import re

ADbots_addr = "https://10.10.254.85"
Server_addr = "localhost:8100"
login_url = "/api/v1/login/"
# check_attack_url = "/api/v1/scrubbingenvironments/5/monitor/ads/events/"
check_attack_url = "/api/v1/scrubbingnodes/11/largescreen/mitigation/events/"
token = ""
cookies = {"sessionid":"sibryp4smkm9bacjhe2qlparm1dv3hbw"}
delta_time = 7*60 # min
timestamp = datetime.utcnow();
packets = []

def parse_log(log_strings):
    parsed_logs = []
    for log_string in log_strings:
        parts = re.findall(r'(\w+)=("[^"]+"|\S+)', log_string)
        log_dict = {key: value.strip('"') for key, value in parts}
        parsed_logs.append(log_dict)
    return parsed_logs

# 比对时间并判断是否发生攻击
def attacked_time(timestamp):
    timestamp_datetime = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
    current_datetime = datetime.utcnow()
    time_difference = current_datetime - timestamp_datetime
    return time_difference.seconds < delta_time
    pass

# 判断是否发生攻击，只要summary中有设备名为ADS02的且发生时间在delta_time内的，就认为发生攻击
def attacked(result):
    return result!= {}
    pass

# 按目标IP分类，返回字典，键为目标IP，值为列表，列表中元素为该目标IP发生的攻击信息
def summary(results):
    valid_results = []
    results = parse_log(results)
    for result in results:
        print(result)
        if "EndTime" in result and result["EndTime"] == '--' :
            print("one valid found")
            valid_results.append(result)
    results_by_dst = {}
    for result in valid_results:
        if result["DstIP"] not in results_by_dst:
            results_by_dst[result["DstIP"]] = []
        res_dict = {"start_time": result["BeginTime"],
                "attack_type": result["AttackType"],
                "total_bits": int(result["Flow"].split('/')[0]),
                "total_packets": int(result["Flow"].split('/')[1])}
        results_by_dst[result["DstIP"]].append(res_dict)
    print(results_by_dst)
    return results_by_dst
    pass

async def sniff_packets_with_timeout():
    packets = []
    sniffer = AsyncSniffer(iface="以太网 3", filter='src host 10.10.249.90 && dst host 10.16.14.12 && port 514', count=20)
    sniffer.start()
    sleep(10)
    sniffer.stop()
    packets = sniffer.results
    return packets

async def check_attack():
    packets = await sniff_packets_with_timeout()
    print(packets)
    datas = []
    for packet in packets:
        if packet.haslayer("Raw"):
            data = packet.getlayer("Raw").load.decode()
            datas.append(data)
    return datas


# 发送清洗请求到Server
def request_server(result):
    conn = http.client.HTTPConnection(Server_addr)
    conn.request("GET", "", json.dumps(result))
    r1 = conn.getresponse()
    print(r1.status, r1.reason)
    r1.close()
    return
    pass

async def main():
    while True:
        results = await check_attack()
        sum = summary(results)
        if(attacked(sum)):
            request_server(sum);

asyncio.run(main())