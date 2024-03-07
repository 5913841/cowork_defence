from multiprocessing import process
from tracemalloc import start
from requests import get,post
import http.client
from urllib import request, parse
from urllib.request import urljoin
from json import dump
from time import sleep
from urllib import parse
from datetime import datetime, timedelta
from scapy.all import *

import json

import socket
import re
import os
import threading

cap_num = 20

def intFromBytes(bytes):
    return int.from_bytes(bytes, byteorder='big', signed=False)

# Netflow v9 field types，可以参考RFC
netflow_v9_field_types = {
    1: "IN_BYTES",
    2: "IN_PKTS",
    3: "FLOWS",
    4: "PROTOCOL",
    5: "SRC_TOS",
    6: "TCP_FLAGS",
    7: "L4_SRC_PORT",
    8: "IPV4_SRC_ADDR",
    9: "SRC_MASK",
    10: "INPUT_SNMP",
    11: "L4_DST_PORT",  # 目的端口
    12: "IPV4_DST_ADDR",  # 目的IP地址
    13: "DST_MASK",  # 目的IP地址掩码
    14: "OUTPUT_SNMP",
    15: "IPV4_NEXT_HOP",
    16: "SRC_AS",
    17: "DST_AS",
    18: "BGP_IPV4_NEXT_HOP",
    19: "MUL_DST_PKTS",
    20: "MUL_DST_BYTES",
    21: "LAST_SWITCHED",
    22: "FIRST_SWITCHED",
    23: "OUT_BYTES",
    24: "OUT_PKTS",
    25: "MIN_PKT_LNGTH",
    26: "MAX_PKT_LNGTH",
    27: "IPV6_SRC_ADDR",
    28: "IPV6_DST_ADDR",
    29: "IPV6_SRC_MASK",
    30: "IPV6_DST_MASK",
    31: "IPV6_FLOW_LABEL",
    32: "ICMP_TYPE",
    33: "MUL_IGMP_TYPE",
    34: "SAMPLING_INTERVAL",
    35: "SAMPLING_ALGORITHM",
    36: "FLOW_ACTIVE_TIMEOUT",
    37: "FLOW_INACTIVE_TIMEOUT",
    38: "ENGINE_TYPE",
    39: "ENGINE_ID",
    40: "TOTAL_BYTES_EXP",
    41: "TOTAL_PKTS_EXP",
    42: "TOTAL_FLOWS_EXP",

    44: "IPV4_SRC_PREFIX",
    45: "IPV4_DST_PREFIX",
    46: "MPLS_TOP_LABEL_TYPE",
    47: "MPLS_TOP_LABEL_IP_ADDR",
    48: "FLOW_SAMPLER_ID",
    49: "FLOW_SAMPLER_MODE",
    50: "FLOW_SAMPLER_RANDOM_INTERVAL",

    52: "MIN_TTL",
    53: "MAX_TTL",
    54: "IPV4_IDENT",
    55: "DST_TOS",
    56: "IN_SRC_MAC",
    57: "OUT_DST_MAC",
    58: "SRC_VLAN",
    59: "DST_VLAN",
    60: "IP_PROTOCOL_VERSION",
    61: "DIRECTION",
    62: "IPV6_NEXT_HOP",
    63: "BGP_IPV6_NEXT_HOP",
    64: "IPV6_OPTION_HEADERS",






    70: "MPLS_LABEL_1",
    71: "MPLS_LABEL_2",
    72: "MPLS_LABEL_3",
    73: "MPLS_LABEL_4",
    74: "MPLS_LABEL_5",
    75: "MPLS_LABEL_6",
    76: "MPLS_LABEL_7",
    77: "MPLS_LABEL_8",
    78: "MPLS_LABEL_9",
    79: "MPLS_LABEL_10",
    80: "IN_DST_MAC",
    81: "OUT_SRC_MAC",
    82: "IF_NAME",
    83: "IF_DESC",
    84: "SAMPLER_NAME",
    85: "IN_PERMANENT_BYTES",
    86: "IN_PERMANENT_PKTS",
    88: "FRAGMENT_OFFSET",
    89: "FORWARDING_STATUS",
    90: "MPLS_PAL_RD",
    91: "MPLS_PREFIX_LEN",
    92: "SRC_TRAFFIC_INDEX",
    93: "DST_TRAFFIC_INDEX",
    94: "APPLICATION_DESC",
    95: "APPLICATION_ID",
    96: "APPLICATION_NAME",
    97: "postipDiffServCodePoint",
    98: "replication_factor",
    99: "DEPRECATED",
    100: "layer2packetSectionOffset",
    101: "layer2packetSectionSize",
    102: "layer2packetSectionData",
    103: "layer2packetSectionFlags",
    104: "layer2packetSectionPadding",
    105: "layer2packetSectionEntropy",
    106: "postipDiffServType",
    107: "multicastReplicationFactor",
    108: "DEPRECATED",
    109: "layer3packetSectionOffset",
    225: "postNATSourceIPv4Address",
    226: "postNATDestinationIPv4Address",
    227: "postNAPTSourceTransportPort",
    228: "postNAPTDestinationTransportPort",
}

delta = 50
ADbots_addr = "https://10.10.254.85"
login_url = "/api/v1/login/"
check_attack_url = "/api/v1/scrubbingenvironments/5/monitor/ads/events/"
token = ""
cookies = {"sessionid":"sibryp4smkm9bacjhe2qlparm1dv3hbw"}
start_clean_url = "/api/v1/disposalip/start/"

# 登录
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

# 根据模板解析Netflow数据
def parse_netflow_v9(template, data):
    parsed_data = {}
    for field in template.template_fields:
        field_data = data[:field.fieldLength]
        data = data[field.fieldLength:]
        fieldName = netflow_v9_field_types[field.fieldType]
        parsed_data[fieldName] = field_data
    return parsed_data

# 通过抓包获取netflow数据，并与攻击数据进行比对
# 一次获取50个netflow数据，然后与攻击数据进行比对，如果存在一个流平均包长和上报的攻击平均包长差距在delta范围内，则认为攻击有效
# netflow数据要先收到template，然后才能解析数据
def attack_valid(attack_infos):
    print("verifying attack")
    packets = sniff(iface = "以太网 3" ,filter = 'src host 10.10.254.87 && dst host 10.16.14.12 && port 9999', count = 50)
    print("sniff complete")
    templates = []
    beg_parse = False
    netflow_infos = []
    for packet in packets:
        if(packet.haslayer("NetflowFlowsetV9") and packet.getlayer("NetflowFlowsetV9").flowSetID == 0):
            flowset = packet.getlayer("NetflowFlowsetV9")
            flowset_length = flowset.length
            templates = flowset.templates
            template_ids = [template.templateID for template in templates]
            beg_parse = True
        if(beg_parse and packet.haslayer("NetflowDataflowsetV9")):
            netflow_info = parse_netflow_v9(templates[template_ids.index(packet.getlayer("NetflowDataflowsetV9").templateID)], packet.getlayer("NetflowDataflowsetV9").records[0].fieldValue)
            netflow_infos.append(netflow_info)
    print("netflow data sample collected")
    for ip in attack_infos:
        for attack_info in attack_infos[ip]:
            for info in netflow_infos:
                print(info)
                print("netflow in bytes: "+str(intFromBytes(info['IN_BYTES'])))
                print("netflow in pkts: "+str(intFromBytes(info['IN_PKTS'])))
                print("attack in bytes: "+str(attack_info['total_bits']/8))
                print("attack in packets: "+str(attack_info['total_packets']))
                print("netflow pkt len: "+str(intFromBytes(info['IN_BYTES'])/intFromBytes(info['IN_PKTS'])))
                print("attack pkt len: "+str(attack_info['total_bits']/attack_info['total_packets']/8))
                if abs(intFromBytes(info['IN_BYTES'])/intFromBytes(info['IN_PKTS']) - attack_info['total_bits']/attack_info['total_packets']/8) <= delta :
                    return True
    return False
    pass

# 登录并启动中位清洗
def start_middle_clean(attack_infos):
    login()
    
    headers = {
        "Authorization":"Token "+token
    }
    body = {
        "advanced_config": {"10.10.249.89":[2]},
        "advanced_config_enable": True,
        "disposal_type": "ads_divert",
        "dstip": [ip for ip in attack_infos],
        "keep_time_seconds": 500,
        "scrubbing_environment": 5
    }
    response = post(ADbots_addr+start_clean_url, headers = headers, json=body, cookies=cookies, verify = False)
    if(response.status_code == 200):
        print(response.text)
        print("Start clean successfully")
        return True
    print(response.text)
    return False
    pass

# 监听客户端请求，并进行攻击检测和中位清洗
def service_client(new_socket):
    request = new_socket.recv(1024*1024).decode('utf-8')
    request_header_lines = request.splitlines()
    print(request_header_lines)
    data = request_header_lines[-1]
    print(data)
    # ret = re.match(r'[^/]+(/[^ ]*)', request_header_lines[0])
    ret =  list(request_header_lines[0].split(' '))[1]
    method = list(request_header_lines[0].split(' '))[0]
    path_name = "/"
    if method == 'GET':
        if ret:
            path = ret
            path_name = parse.unquote(path)
        if attack_valid(json.loads(data)) and start_middle_clean(json.loads(data)):
            
            content = "HELP SUCCESS"
            # 准备发给浏览器的数据 -- header
            response = "HTTP/1.1 200 OK\r\n"
            response += "\r\n"
            new_socket.send(response.encode("utf-8"))
            new_socket.send(content.encode("utf-8"))
            # 关闭套接字
        else:
            print("The attack is not true")
            response = "HTTP/1.1 404 NOT FOUND\r\n"
            response += "\r\n"
            response += "------The attack is not true------"
            new_socket.send(response.encode("utf-8"))


tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_server_socket.bind(("localhost", 8100))
tcp_server_socket.listen(128)
while True:
    new_socket, client_addr = tcp_server_socket.accept()
    t = threading.Thread(target=service_client, args=(new_socket,))
    t.start()
            
# start_middle_clean(0)