#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>
#include <vector>
#include <Eigen/Core>
#include <bitset> 
#include <cmath>
#include <random>
#include <thread>

#define MAX_PACKET_SIZE 65535
#define NumBitsPhi 6
#define NumBitsPsi 4


// 此版本是action后进行注入
// 标准SU注入 4*2 MUMIMO 倒序
// LSB to MSB

// (wlan.fc == 0x5400 && wlan.ra == 90:de:80:f1:4a:b2) || (wlan.ta == 90:de:80:f1:4a:b2 && wlan.fc.subtype==14)
const float pi = 3.14159265;// 358979323846;
const std::complex<float> complex_j(0,1.0);


const float alpha = 1;
const float sqrt_1_alpha = std::sqrt(1-alpha);
const float sqrt_alpha = std::sqrt(alpha);



int app_stopped = 0;
std::seed_seq seed{1, 2, 3, 4, 5};
std::mt19937 rng(seed);
int save_lock = 0, save_lock2 = 0;
int save_lock_bak = 0, save_lock_bak2 = 0;

void sigint_handler(int sig){
	if(sig == SIGINT){
		// ctrl+c退出时执行的代码
		printf("ctrl+c pressed!\n");
		app_stopped = 1;
	}
}

int len_mu_feedback = 325;// 325;

void re_beamforming(unsigned char * feedback, unsigned char * feedback_new){
	struct timeval tv;
	struct timeval tv2;
	gettimeofday(&tv, NULL);
	int Nr = 4, Nc = 2, Nst = 52;
	double pow_phi = std::pow(2, NumBitsPhi), pow_psi = std::pow(2, NumBitsPsi+2);

	//int len_mu_feedback = sizeof(feedback);
	std::string binaryString = "";

	//std::cout<< "len_mu_feedback " << len_mu_feedback << std::endl;
	while (save_lock_bak)
	{
		usleep(2);
	}
	std::string tmp_bin;
	save_lock_bak2 = 1;
    for (int i=0; i < len_mu_feedback; i++) {
        // 将整数转换为二进制字符串，并连接到结果字符串
		//printf("%x, ", (int)mu_feedback[i] );
		//std::cout  << std::bitset<8>(mu_feedback[i]).to_string() << " ";
		tmp_bin = std::bitset<8>(feedback[i]).to_string();
		std::reverse(tmp_bin.begin(), tmp_bin.end());
        binaryString += tmp_bin;
    }
	save_lock_bak2 = 0;

	//std::cout << std::endl;
	//std::cout<< "binaryString: " << binaryString << std::endl;
	
	// 二进制字符串转化为角度信息
	Eigen::Matrix<float, 10, 52> angles;
	int index = 0;
	//std::cout << binaryString.substr(index, index+NumBitsPhi) << ", V:" << std::bitset<9>(binaryString.substr(index, index+NumBitsPhi)).to_ulong() << ", pow " << std::pow(2, NumBitsPhi) << std::endl;
	for(int kk=0; kk<Nst; kk++){
		int angcnt = 0;
		for(int ii=Nr-1; ii>=std::max(Nr-Nc, 1); ii--){
			for(int jj=0; jj<ii; jj++){
				std::string tmp = binaryString.substr(index, NumBitsPhi);
				std::reverse(tmp.begin(), tmp.end());
				angles(angcnt, kk) = (2* std::bitset<NumBitsPhi>(tmp).to_ulong()+1)/( pow_phi );
				angcnt++;
				index = index + NumBitsPhi;
			}
			for(int jj=0; jj<ii; jj++){
				//if(jj==0) std::cout << "kk: "<< kk <<"," << binaryString.substr(index, NumBitsPsi) << ", " << std::bitset<9>(binaryString.substr(index, index+NumBitsPsi)).to_ulong() << std::endl;
				std::string tmp = binaryString.substr(index, NumBitsPsi);
				std::reverse(tmp.begin(), tmp.end());
				angles(angcnt, kk) = (2*std::bitset<NumBitsPsi>(tmp).to_ulong()+1)/( pow_psi );
				angcnt++;
				index = index + NumBitsPsi;
			}

		}
	}

	// 将角度转化为V
	Eigen::Matrix<std::complex<float>, 4, 2> V_kk;
	V_kk << 1,0, 0,1, 0,0, 0,0;
	Eigen::Matrix<std::complex<float>, 4, 1> D;
	D << 1, 1, 1, 1;
	Eigen::Matrix<std::complex<float>, 4, 1> D_tmp;
	// std::cout << V_kk << std::endl;
	std::vector< Eigen::Matrix<std::complex<float>, 4, 2> >  V(52, V_kk);
	//std::cout << V[1] << std::endl;
	Eigen::Matrix<float, 4, 4> Gt;
	int p = std::min(Nc, Nr-1);
	int NumAnglesCnt = 10;
	for(int ii=p; ii>=1; ii--){
		//std::cout << "ii " << ii<< std::endl;
		for(int jj=Nr; jj>=ii+1; jj--){
			for(int kk=0; kk<Nst; kk++){
				Gt.setIdentity(4,4);
				//std::cout << V[kk] << std::endl;
				Gt(ii-1,ii-1) = std::cos(angles(NumAnglesCnt-1,kk)*pi);
				Gt(ii-1,jj-1) = -1*std::sin(angles(NumAnglesCnt-1,kk)*pi);
            	Gt(jj-1,ii-1) = std::sin(angles(NumAnglesCnt-1,kk)*pi);
            	Gt(jj-1,jj-1) = std::cos(angles(NumAnglesCnt-1,kk)*pi);
				//std::cout << std::cos(angles(NumAnglesCnt-1,kk)*pi) << std::endl;
				//std::cout << V[kk] << std::endl;
            	V[kk] = Gt*V[kk];
				//if(kk==0) std::cout<< V[kk] <<std::endl;

			}
			NumAnglesCnt--;
		}
		for(int kk=0; kk<Nst; kk++){
			D_tmp = D;
			index = 0;
			for(int jj=-Nr+ii+1; jj<=0; jj++){
				D_tmp[ii-1+index] = std::exp(complex_j*pi*angles(NumAnglesCnt+jj-1,kk));
				index ++;
			}
			for(int jj=0; jj<Nr; jj++){
				V[kk].row(jj) *=  D_tmp[jj];
			}
		}
		NumAnglesCnt = NumAnglesCnt - Nr + ii;
	}
	

	//gettimeofday(&tv2, NULL);
	//std::cout << "time: " << (tv2.tv_sec-tv.tv_sec)+(tv2.tv_usec-tv.tv_usec)/1000000.f << std::endl;
	// 寻找正交矩阵W
	V_kk << 0,0, 0,0, 0,0, 0,0;
	std::vector< Eigen::Matrix<std::complex<float>, 4, 2> >  W(52, V_kk);
	Eigen::Matrix<std::complex<float>, 4, 2>  R_rand = Eigen::MatrixXf::Random(4,2) + complex_j*Eigen::MatrixXf::Random(4,2);
	//std::cout << "R: " << R_rand << std::endl;
	for(int kk=0; kk<Nst; kk++){
		W[kk].col(0) = R_rand.col(0) - V[kk].col(0).adjoint()*R_rand.col(0)*V[kk].col(0) - V[kk].col(1).adjoint()*R_rand.col(0)*V[kk].col(1);	
		W[kk].col(0) = W[kk].col(0)/W[kk](3,0);
		W[kk].col(0) = W[kk].col(0)/W[kk].col(0).norm();

		W[kk].col(1) = R_rand.col(1) - V[kk].col(0).adjoint()*R_rand.col(1)*V[kk].col(0) 
			- V[kk].col(1).adjoint()*R_rand.col(1)*V[kk].col(1) - W[kk].col(0).adjoint()*R_rand.col(1)*W[kk].col(0);
		W[kk].col(1) = W[kk].col(1)/W[kk](3,1);
		W[kk].col(1) = W[kk].col(1)/W[kk].col(1).norm();
		
		W[kk].col(0) =  sqrt_1_alpha * V[kk].col(0) + sqrt_alpha * W[kk].col(0);
		W[kk].col(1) =  sqrt_1_alpha * V[kk].col(1) + sqrt_alpha * W[kk].col(1);
		//std::cout <<  W[kk] << std::endl;
		//std::cout <<  V[kk].adjoint()*W[kk] << std::endl;
		//std::cout <<  V[kk].adjoint()*V[kk] << std::endl;
		//std::cout <<  W[kk].adjoint()*W[kk] << std::endl;
	}
	
	// 将W转化为相位

	int NumAngles = 10;
	Eigen::Matrix<float, 10, 52> angles_W;
	int angcnt = 0;
	float phi = 0, psi = 0;
	for(int ii=1; ii<=std::min(Nc, Nr-1); ii++){
		//int index = 0;
		for(int kk=0; kk<Nst; kk++){
			for(int jj=0; jj<Nr-ii; jj++){
				phi = std::arg(W[kk](ii+jj-1,ii-1));
				//std::cout << "phi " << phi << " w " << W[kk](ii+jj-1,ii-1) << std::endl;
				if(phi<0) phi += pi*2;
				angles_W(angcnt+jj, kk) = phi;
			}
			//D_tmp = D;
			for(int jj=0; jj<Nr-ii; jj++){
				W[kk].row(ii-1+jj) *= std::exp(-complex_j*angles_W(angcnt+jj, kk));
			}
		}
		angcnt = angcnt + Nr-ii;
		for(int ll=ii+1; ll<=Nr; ll++){
			for(int kk=0; kk<Nst; kk++){
				psi = std::atan(W[kk](ll-1,ii-1).real() / W[kk](ii-1,ii-1).real());
				angles_W(angcnt, kk) = psi;

				Gt.setIdentity(4,4);
				Gt(ii-1,ii-1) = std::cos(psi);
				Gt(ii-1,ll-1) = std::sin(psi);
				Gt(ll-1,ii-1) = -std::sin(psi);
				Gt(ll-1,ll-1) = std::cos(psi);  
				W[kk] = Gt*W[kk]; 
			}
			angcnt ++;
		}
	}
	//std::cout << "angcnt: " << angcnt << std::endl;

	//将相位转化为bit

	std::string binaryString_W = "";
	int tmp = 0;
	std::string tmp_string;
	for(int kk=0; kk<Nst; kk++){
		int angcnt = 0;
		for(int ii=Nr-1; ii>=std::max(Nr-Nc,1); ii--){
			for(int jj=1; jj<=ii; jj++){
				tmp = std::round(0.5*((angles_W(angcnt,kk)*(( pow_phi ))/pi)-1));
				tmp_string = std::bitset<NumBitsPhi>(tmp).to_string();
				std::reverse(tmp_string.begin(), tmp_string.end());
				binaryString_W += tmp_string;
				angcnt ++;
			}
			for(int jj=1; jj<=ii; jj++){
				tmp = std::round(0.5*((angles_W(angcnt,kk)*(( pow_psi ))/pi)-1));
				tmp_string = std::bitset<NumBitsPsi>(tmp).to_string();
				std::reverse(tmp_string.begin(), tmp_string.end());
				binaryString_W += tmp_string;
				angcnt ++;
			}
		}
	}

	index = 0;
	while(save_lock2) usleep(2);
	save_lock = 1;
	for (int i=0; i < len_mu_feedback; i++) {
		tmp_bin = binaryString_W.substr(index, 8);
		std::reverse(tmp_bin.begin(), tmp_bin.end());
		feedback_new[i] = std::bitset<8>(tmp_bin).to_ulong();
		index += 8;
		//printf("%x, ", feedback[i]);
		//std::cout << "binaryString_W: " <<binaryString_W
	}
	save_lock = 0;

	gettimeofday(&tv2, NULL);
	std::cout << "time: " << (tv2.tv_sec-tv.tv_sec)+(tv2.tv_usec-tv.tv_usec)/1000000.f << std::endl;
}


int main() {
    char *dev = "wlp88s0"; //wlan0mon, wlx00c0cab3f55d
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_t *send_handle = NULL;
    struct pcap_pkthdr header;
    struct timeval tv;
    struct timeval tv2;
    struct timeval tv3;
    int save_not = 0;

    // ctrl+c 
	signal(SIGINT, sigint_handler);

    
    //monitor -> sniff packets
    char pcap_errbuf[100];
	pcap_t *pcap = pcap_create("wlp88s0", pcap_errbuf); // wlp3s0mon,  wlp43s0mon
	if (pcap == NULL) {
        printf("Could not open device or file: %s\n", pcap_errbuf);
        return 1;
    }
	int res_time = pcap_set_tstamp_type(pcap, PCAP_TSTAMP_HOST_HIPREC);
	pcap_set_snaplen(pcap, MAX_PACKET_SIZE);
    pcap_set_promisc(pcap, 1);
    //设置为immediate模式
	if (pcap_set_immediate_mode(pcap, 1)==PCAP_ERROR_ACTIVATED)
	{
		printf("pcap_set_immediate_mode\n");
        return 1;
	}
	int res_activate = pcap_activate(pcap);
    printf("res_time: %d, pcap_activate: %d\n", res_time, res_activate);

    struct bpf_program fp;
	char filter_exp[] = "(type mgt and not (subtype assoc-req or subtype assoc-resp or subtype reassoc-req or subtype reassoc-resp or subtype probe-req or subtype probe-resp or subtype beacon or subtype atim or subtype disassoc or subtype auth or subtype deauth) and (wlan addr2 90:de:80:f1:4a:b2 or wlan addr2 00:1D:43:20:16:6A))";   // for NDP a & ta 15:59:c0:33:8b:77 90:de:80:a9:e5:8a 90:de:80:f1:4a:b2 and wlan addr1 ff:ff:ff:ff:ff:ff 90:DE:80:F1:4A:B2 90:DE:80:E3:BB:0C 98:2C:BC:16:A6:A2
	// 90:DE:80:A9:E5:8A
	if (pcap_compile(pcap, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(0);
    }
	
	//pcap_setfilter:为pcap实例设置一个编译好的过滤程序
    if (pcap_setfilter(pcap, &fp) == -1) {
        printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(0);
    }

    //injected packet variable 
	struct pcap_pkthdr *pkh;
	u_char *h80211_rx = reinterpret_cast<uint8_t*>(malloc(4096));
	u_char *h80211_rx_bak = reinterpret_cast<uint8_t*>(malloc(4096));
	if (h80211_rx == NULL) {
		// 处理内存分配失败的情况
		exit(EXIT_FAILURE);
	}
	size_t n_rx = 0;
	for(int i=0; i<4096; i++)
		h80211_rx[i] = 0;

    // for injecting packets
    send_handle = pcap_open_live(dev, MAX_PACKET_SIZE, 1, 0, pcap_errbuf);
	if (send_handle == NULL) {
        printf("Send: could not open device or file: %s\n", pcap_errbuf);
        return 1;
    }


	gettimeofday(&tv, NULL);

    //	u8aRadiotap
	/*
    unsigned char u8aRadiotap[] = {
		0x00, 0x00, 
		0x1c, 0x00, 
		0x0a, 0x80, 0x20, 0x00, 
		0x90, 0x00, //flag
		0xc8, 0x14, //channel frequency
		0x40, 0x01, //channel flag
		0x18, 0x00, // TX flag
		0xff, 0x01, // VHT
		0x06, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x80, 0x0f};

	*/
	unsigned char u8aRadiotap[] = {
		0x00,
		0x00, // <-- radiotap version
		0x0c, // <- radiotap header length
		0x00, 
		0x04,
		0x80,
		0x00,
		0x00, 
		0x30, // <-- rate 6c
		0x00, // <-- padding for natural alignment
		0x18,
		0x00, // <-- TX flags
	};

uint8_t test_bfi_report[]={0x15, 0x00, 0x19, 0x84, 0x84, 0x35, 0x19, 
0x3B, 0xA6, 0xB0, 0xDF, 0xCE, 0x4D, 0x36, 0xFC, 0xCA, 0x54, 0xF9, 0x75, 0x3E, 0xC0, 0xD9, 0x15, 
0x79, 0x3A, 0x0E, 0xD4, 0xC9, 0x09, 0x1D, 0x9F, 0x50, 0xAA, 0x26, 0xD8, 0x90, 0x51, 0x48, 0x6A, 
0xB0, 0x55, 0x33, 0xFC, 0xE5, 0x1E, 0x17, 0x15, 0x19, 0x1D, 0x32, 0x57, 0x5F, 0x07, 0x65, 0x08, 
0xF1, 0x70, 0x48, 0xE5, 0xD0, 0x84, 0xA1, 0xCC, 0xE8, 0x9F, 0x13, 0x40, 0xF4, 0x06, 0x01, 0xFE, 
0x3B, 0x5D, 0x02, 0xF2, 0xD3, 0x8F, 0x77, 0x65, 0x88, 0x23, 0x61, 0x50, 0x95, 0xA0, 0x01, 0x25, 
0xCC, 0x07, 0x40, 0x84, 0x62, 0x0F, 0xFA, 0x4C, 0x7F, 0xAB, 0x65, 0x5F, 0xA8, 0x87, 0x83, 0x75, 
0x72, 0x77, 0xA5, 0x63, 0xCF, 0xF7, 0xB0, 0x83, 0xB4, 0xC4, 0x32, 0x8B, 0x93, 0x43, 0x1C, 0x25, 
0x3B, 0xFC, 0x35, 0x04, 0xE2, 0x00, 0x9C, 0x85, 0x43, 0x95, 0x66, 0xD4, 0x85, 0xCF, 0x7D, 0x18, 
0xC0, 0x6A, 0x18, 0x34, 0x44, 0x47, 0x83, 0x2F, 0xF8, 0x21, 0x2A, 0x30, 0x80, 0xFA, 0x61, 0x64, 
0x35, 0xC2, 0x6A, 0x01, 0xD0, 0xC1, 0x4D, 0xC8, 0x68, 0x81, 0xD2, 0x10, 0x04, 0xE0, 0x99, 0x22, 
0xF3, 0xE5, 0x30, 0xC3, 0x0D, 0x91, 0x63, 0x01, 0x57, 0x97, 0x01, 0x68, 0x05, 0x51, 0x90, 0x6A, 
0x95, 0x6C, 0x01, 0x33, 0x90, 0x37, 0xD3, 0x99, 0x33, 0x1F, 0xA2, 0x12, 0x35, 0xB6, 0x0C, 0xD9, 
0xDD, 0xCC, 0x3D, 0x8B, 0x44, 0x19, 0xE5, 0x51, 0xB6, 0x39, 0xFD, 0x41, 0xF1, 0x88, 0x3B, 0xAB, 
0x56, 0x40, 0x38, 0x4C, 0x19, 0x24, 0x78, 0x04, 0x3E, 0xE2, 0x15, 0x57, 0x6C, 0xC3, 0x09, 0x6F, 
0x00, 0x13, 0xD3, 0xD9, 0x00, 0x60, 0xC8, 0x34, 0xD3, 0x47, 0x31, 0xFB, 0x96, 0x1A, 0x85, 0xAA, 
0x1C, 0x58, 0x06, 0xC8, 0xD2, 0x99, 0x72, 0x37, 0xAD, 0x32, 0x7A, 0xC8, 0x65, 0x03, 0x3D, 0x14, 
0x3A, 0x70, 0xDA, 0x62, 0xCE, 0xB2, 0x05, 0x73, 0xA7, 0xE8, 0xC4, 0x12, 0x46, 0xE5, 0x8B, 0x96, 
0x19, 0x8B, 0x90, 0xA6, 0xFE, 0x9D, 0x03, 0x08, 0x08, 0x6D, 0x8E, 0x5C, 0x50, 0x44, 0xC8, 0x02, 
0xAF, 0x65, 0x09, 0x01, 0x03, 0x26, 0x04, 0x0C, 0xBA, 0x1A, 0x57, 0xB0, 0xC3, 0x72, 0xE4, 0xCC, 
0x17, 0xD4, 0x9F, 0x74, 0xC5, 0x30, 0x0B, 0x13, 0x0C, 0x7E, 0x66, 0xC9, 0x6A, 0x01, 0xDE, 0x6D, 
0x9E, 0xB8, 0x0B, 0x31, 0x50};

    int len_u8aRadiotap = sizeof(u8aRadiotap);

	int num_dev = 1;
    unsigned char tx_buf_dev[num_dev][4096];
    //unsigned char tx_buf_dev2[4096];
	unsigned char dev_name[num_dev];
	dev_name[0] = 0x6a; 

    //存储sniff到的packets
    pcap_dumper_t * t;
    if (save_not)   t = pcap_dump_open(pcap, "tmp.pcap");
	
	int pcap_rx;
	int i = 0;
    int index_start;
    int len_head = 8*3;
    int seq_num_action[num_dev];
    int seq_num = 0;
    int len_packet[num_dev];
	int flags[num_dev];
	int i_dev=0;
	for(i_dev=0; i_dev < num_dev; i_dev++){
		seq_num_action[i_dev] = 0;
		len_packet[i_dev] = 0;
		flags[i_dev] = 0;
	}
	i_dev = 0;
	int snr[num_dev];
	snr[0] = 0x7c; 

    unsigned char token = 0;
	while(i<2e5)
	{		
		if (app_stopped)  break;
		//int loop_do;
		do{	
			if (app_stopped)  break;
			int pcap_rx = pcap_next_ex(pcap, &pkh, (const unsigned char**)  &h80211_rx);
			index_start = h80211_rx[2];

		}while(! (h80211_rx[index_start] == 0xe0) );
	

		if(h80211_rx[index_start+1] == 0x08) {
			std::cout << "skip "<< std::endl;	
			continue;
		}


        printf("index: %d, type: %x,  \n", i, h80211_rx[index_start]);
        if (save_not) pcap_dump((u_char *) t, pkh, h80211_rx);

		memcpy(tx_buf_dev[i_dev], u8aRadiotap, len_u8aRadiotap);
		memcpy(tx_buf_dev[i_dev] + len_u8aRadiotap, &h80211_rx[index_start], pkh->caplen-index_start - 4);
		tx_buf_dev[i_dev][len_u8aRadiotap+1] = 0x08; 
		
		//usleep(200);
		re_beamforming(&h80211_rx[index_start+len_head+7], &tx_buf_dev[i_dev][len_u8aRadiotap+len_head+7]);
		//memcpy(tx_buf_dev[i_dev] + len_u8aRadiotap + 24+5, &test_bfi_report[5],332-5);
		len_packet[i_dev] = pkh->caplen-index_start+len_u8aRadiotap - 4;
		int res_inject = pcap_inject(send_handle, tx_buf_dev[i_dev], len_packet[i_dev]);
    	i++;
        
	}
	/*
	i = 0;
	while(i<100)
	{
		int res_inject = pcap_inject(send_handle, tx_buf_dev[i_dev], len_packet[i_dev]);
		usleep(10000);
	}
	*/

	if (save_not)   pcap_dump_close(t);
	//fclose(f_cap);
	printf("end!\n");
	pcap_close(pcap);
	pcap_close(send_handle);
    return 0;
}
