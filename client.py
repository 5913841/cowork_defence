from requests import get,post
import http.client
from urllib import request, parse
from urllib.request import urljoin
from json import dump
from time import sleep
from urllib import parse
from datetime import datetime, timedelta

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
    for result in results:
        if result["device_name"] == "ADS02" and attacked_time(result["start_time"]) :
        # (result["dispsal_status"] == "牵引中" or result["dispsal_status"] == "未处置") :
            valid_results.append(result)
    results_by_dst = {}
    for result in valid_results:
        if result["dstip"] not in results_by_dst:
            results_by_dst[result["dstip"]] = []
        results_by_dst[result["dstip"]].append(result)
    return results_by_dst
    pass

# 登录，获取token
def login():
    login_headers = {
        "authority": "10.10.254.85",
        "accept": "application/json",
        "accept-language": "zh",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "local-server": "true",
        "origin": "https://10.10.254.85",
        "referer": "https://10.10.254.85/login",
        "sec-ch-ua": "\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
    }
    body = {"username":"admin", "password":"abcd@123"}
    data = parse.urlencode(body)
    response = post(ADbots_addr+login_url, headers = login_headers, data=data, cookies=cookies, verify = False)
    response_dict = json.loads(response.text)
    global token 
    token = response_dict["token"]

# 发送请求，获取结果
def check_attack():
    headers = {
        "Authorization":"Token "+token
    }
    params = {
        "chart": "table",
        "orderby": "-time",
        "limit": 60,
        "offset": 0
    }
    response = get(ADbots_addr+check_attack_url, headers=headers, cookies=cookies, verify=False, params=params)
    response_dict = json.loads(response.text)
    print(json.dumps(response_dict, indent=2))
    return response_dict["results"]
    # resent_result = 0
    # for result in response_dict["results"]:
    #     if result["device_name"] == "ADS02":
    #         resent_result = result
    #         break
    # if(resent_result == 0):
    #     return {}
    # return {"start_time": resent_result["start_time"],
    #         "attack_type": resent_result["attack_type"],
    #         "total_bits": resent_result["total_bits"],
    #         "total_packets": resent_result["total_packets"],
    #         "max_bps": resent_result["max_bps"],
    #         "max_pps": resent_result["max_pps"],
    #         "device_ip": resent_result["device_ip"]}
    pass

# 发送清洗请求到Server
def request_server(result):
    conn = http.client.HTTPConnection(Server_addr)
    conn.request("GET", "", json.dumps(result))
    r1 = conn.getresponse()
    print(r1.status, r1.reason)
    r1.close()
    return
    pass

login()
while(True):
    results = check_attack()
    sum = summary(results)
    if(attacked(sum)):
        request_server(sum);
# request_server({})