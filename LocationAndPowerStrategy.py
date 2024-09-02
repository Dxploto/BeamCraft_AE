from scapy.all import *
from scapy.layers.dot11 import Dot11    
# 定义目标MAC地址
target_mac = "90:DE:80:F1:4A:B2"
ap_mac = "A4:A9:30:95:22:5B"
action_pkt=[]
ndp_pkt=[]
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
    if packet.haslayer(Dot11) and packet.addr2== "90:de:80:f1:4a:b2" and packet.type==0 and packet.subtype==14:
        global action_pkt
        action_pkt.append(packet)
        print(f"Capture one Action Frame: {packet.summary()}")
        print(f"Victim's SNR to AP: {hex_to_six_bit_complement(str(packet.load[5]))} dB")
        print(f"Victim's SNR to Attacker: {packet.dBm_AntSignal} dBm")
        print(f"Victim's Address: {packet.addr2}")
        print(f"Victim's Rate: {packet.Rate}")
    # if packet.haslayer(Dot11) and packet.addr1== "90:de:80:f1:4a:b2" and packet.type==1 and packet.subtype==5:
    if packet.haslayer(Dot11) and packet.addr2== "a4:a9:30:95:22:5b" and packet.Rate==6:
        global ndp_pkt
        ndp_pkt.append(packet)
        # print(f"Capture one NDP Frame: {packet.summary()}")
        print(f"Capture one NDP Frame")
        print(f"AP's SNR to Attacker: {packet.dBm_AntSignal} dBm")
        print(f"AP's Address: {packet.addr2}")
        print(f"AP's Rate: {packet.Rate}")
    if action_pkt and ndp_pkt:
        global stop_sniffing
        stop_sniffing=True
# 定义停止条件函数
def stop_filter(packet):
    return stop_sniffing
# 开始嗅探
pkt=sniff(iface="wlp88s0", prn=sniff_packet,stop_filter=stop_filter)

SNR_delta=ndp_pkt[0].dBm_AntSignal-action_pkt[0].dBm_AntSignal
attenuator=31.25-SNR_delta
if attenuator<0:
    attenuator=0
print("********************************************************")
print(f"Victim's MAC address is: {target_mac}")
print(f"AP's MAC address is: {ap_mac}")
print(f"Attacker's available snr delta is: {SNR_delta} dBm")
print("Attacker's default Tx power as 50mw")
print(f"Now setting attacker's attenuator to {attenuator} dBm")
print("Now setting attacker's MCS as MCS 7")
print("Location and Power Selection Pass !")
print("********************************************************")
