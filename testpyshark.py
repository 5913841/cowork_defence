from email.base64mime import header_length
import pyshark
import struct

def parse_netflowv9(packet):
    netflow_packet = bytes.fromhex(packet['UDP'].payload.replace(':', ''))
    header_format = '!HHIIIIBBH'
    header_length = struct.calcsize(header_format)
    netflow_header = netflow_packet[:header_length]
    
    version, count, sys_uptime, unix_secs, unix_nsecs, flow_sequence, engine_type, engine_id, sampling_interval = struct.unpack(header_format, netflow_header)
    
    flows = []
    flow_data = netflow_packet[header_length:]

    for i in range(count):
        flow_format = '!IIIIIIIIIIIBBHBBHHHBB'
        flow_length = struct.calcsize(flow_format)
        flow_offset = i * flow_length
        flow_header = flow_data[flow_offset:flow_offset+flow_length]
        src_addr, dst_addr, next_hop, input_int, output_int, packet_count, byte_count, start_time, end_time, src_port, dst_port, pad1, tcp_flags, protocol, tos, src_as, dst_as, src_mask, dst_mask = struct.unpack(flow_format, flow_header)
        
        flow = {
            'src_addr': src_addr,
            'dst_addr': dst_addr,
            'next_hop': next_hop,
            'input_int': input_int,
            'output_int': output_int,
            'packet_count': packet_count,
            'byte_count': byte_count,
            'start_time': start_time,
            'end_time': end_time,
            'src_port': src_port,
            'dst_port': dst_port,
            'tcp_flags': tcp_flags,
            'protocol': protocol,
            'tos': tos,
            'src_as': src_as,
            'dst_as': dst_as,
            'src_mask': src_mask,
            'dst_mask': dst_mask
        }
        flows.append(flow)

    return flows

def capture_packets(interface):
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='udp port 9999', tshark_path="D:\wireshark\\tshark.exe")
    for packet in capture.sniff_continuously():
        if 'UDP' in packet and 'CFLOW' in packet:
            flows = parse_netflowv9(packet)
            print(flows)

if __name__ == "__main__":
    interface = '以太网 3'  # 设置为你的网络接口
    capture_packets(interface)