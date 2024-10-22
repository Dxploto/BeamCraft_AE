# BeamCraft
Welcome to BeamCraft! This respository provides the code and resources to implement BeamCraft. Also, you can watch our demo using this url: [Artifacts-BeamCraft-Demo](https://entuedu-my.sharepoint.com/:v:/g/personal/n2308654g_e_ntu_edu_sg/ESQwR6Sg3ENBvOy6GZTxIVsBEYvIusrxY8IYM_wFoZ8LGw).

## Table of Contents
- [Requirements](#requirement)
- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [License](#license)


## Requirements
### Hardware Requirements
- Attacker
PC equipped with CPU Intel i7-13700H or above; or
Raspberry Pi 4B.
- Wi-Fi AP router: 
Xiaomi Redmi AC2100 Wi-Fi AP router;
- Wi-Fi NIC card (Attacker): 
Alfa AWUS036ACM USB Wi-Fi Adapter; MT7921.
- Wi-Fi NIC card (Victim): 
RTL 8812bu; RTL 8821cu; Intel 8625; MT7612; MT7921; Mobile phones: Xiaomi 13 pro, iPhone 14 pro max.
### Software Requirements
- PC: Ubuntu 24.04 with kernel 6.2 or above.
- Raspberry Pi: Kali Linux with kernel 6.2 or above.
- libpcap;
- gcc/g++;
- eigen3.

## Introduction
BeamCraft is the first attack to manipulate traffic in commodity Wi-Fi systems via beamforming. It aims to perform traffic disruption or traffic plunder on Wi-Fi clients supporting beamforming. This artifact includes instructions to implement and evaluate BeamCraft. BeamCraft includes one device equipped with a Wi-Fi NIC and installed attack programs acting as attacker and several Wi-Fi clients acting as victims. All victims are connected to a Wi-Fi AP. The attack programs include location and power selection strategy, beamforming feedback information (BFI) forging, and BFI compressing and injection. The location and power selection strategy ensures covert attack by analysing the received signal-to-noise ratio (SNR) in non-data packet (NDP) packets form the Wi-Fi AP and BFI packets from the victims. The BFI forging, compressing and injection programs aim at crafting BFIs and feeding them back to the Wi-Fi AP for traffic disruption or traffic plunder.
## Getting Started
To get started with BeamCraft and use the code to implement attack, follow these steps:

1. Clone this repository to your local attacker using `git clone https://github.com/BeamCraft.git`
2. Install the necessary packages using `apt install g++ libpcap0.8-dev libegien3-dev`
3. Configure the code to select one Wi-Fi NIC card as attacker and the victim's MAC address.
4. Compile the attack code using `g++ main_su.cpp -o main_su -I/usr/include/eigen3/ -L/usr/lib/x86_64-linux-gnu/ -lpcap -pthread -O3`
5. Setting up the Wi-Fi NIC card to monitor mode and choose the wireless channel.
`sudo ifconfig wlan0 down`
`sudo iw dev wlan0 set type monitor`
`sudo ifconfig wlan0 up`
`sudo iw dev wlan0 set channel 153`
6. Run the attack application `sudo main_su`

For more detailed instruction, please kindly refer to our [artifact appendix]().
## License
This repository is licensed under the MIT License. For more details, please refer to the `LICENSE` file.
