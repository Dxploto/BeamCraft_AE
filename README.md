# BeamCraft
Welcome to BeamCraft! This respository provides the code and resources to implement BeamCraft.

## Table of Contents
- [Requirements](#requirement)
- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Experiment Preparements](#experiment-preparements)


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
BeamCraft is the first attack to manipulate traffic in commodity Wi-Fi systems via beamforming.
## Getting Started
To get started with BeamCraft and use the code to implement attack, follow these steps:

1. Clone this repository to your local attacker using `git clone https://github.com/BeamCraft.git`
2. Install the necessary packages using `apt g++ install libpcap0.8-dev libegien3-dev`
3. Configure the code to select one Wi-Fi NIC card as attacker and the victim's MAC address.
4. Compile the attack code using `g++ main_su.cpp -o main_su -I/usr/include/eigen3/ -L/usr/lib/x86_64-linux-gnu/ -lpcap -pthread -O3`
5. Setting up the Wi-Fi NIC card to monitor mode and choose the wireless channel.
`sudo ifconfig wlan0 down`
`sudo iw dev wlan0 set type monitor`
`sudo ifconfig wlan0 up`
`sudo iw dev wlan0 set channel 153`
6. Run the attack application `sudo main_su`
