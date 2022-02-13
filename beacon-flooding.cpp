#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <iostream>

#include "beacon-flooding.h"

void usage() {
	printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
	printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

void DumpHex(const void* data, int size) {
  char ascii[17];
  int i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->file_ = argv[2];
	return true;
}

int parse_ssid(const char* file_, char**ssid_list){
	char temp[512];
	FILE* fp = fopen(file_, "r");

	if(fp == NULL){
		fprintf(stderr, "Error : parse_ssid()\n");
		exit(1);
	}
	int index = 0;
	while(NULL != fgets(temp, sizeof(temp), fp)){
		ssid_list[index] = (char*)malloc(strlen(temp)+1);
		strncpy(ssid_list[index], temp, strlen(temp));
		index++;
	}
	fclose(fp);
	return index;	
}

void set_radiotab_frame(struct ieee80211_radiotap_hdr* radio){
	memset(radio, 0x0, sizeof(radio));
        radio->it_len = 0xc;
}

void set_beacon_frame(struct ieee80211_beacon_hdr* beacon, unsigned char* ap_addr){

	memset(beacon, 0x0, sizeof(beacon));
        
        beacon->frame_subtype = 0x8;

        memset(&beacon->addr1, 0xff, IEEE802_11_MAC_LENGTH);
        memcpy(&beacon->addr2, ap_addr, IEEE802_11_MAC_LENGTH);
        memcpy(&beacon->addr3, ap_addr, IEEE802_11_MAC_LENGTH);

        beacon->numbers = 0x2010;
        beacon->fix.cap_info = 0x0411;
}

void set_tagged_frame(struct tagged_param* tag, const char* ssid) {
	tag->tag_num = 0;
        tag->tag_len = strlen(ssid)-1;
        tag->data = (u_int8_t*)malloc(strlen(ssid)-1);
        memcpy(tag->data, ssid, strlen(ssid)-1);
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	
	char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
                return -1;
        }

	char* ssid_list[20] = {};
	int ssid_num = parse_ssid(param.file_, ssid_list);

	//set radiotab header
	struct ieee80211_radiotap_hdr radio;
	set_radiotab_frame(&radio);

	//set beacon header
	struct ieee80211_beacon_hdr beacon;
	unsigned char ap_addr[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xcb};

	set_beacon_frame(&beacon, ap_addr);
	
	int index = 0;
	while (true) {
		//set tagged header
		struct tagged_param tag;
		set_tagged_frame(&tag, ssid_list[index]);
		
		//construct packet data
		size_t packet_size = sizeof(radio)+sizeof(beacon)+tag.tag_len+2;
		u_char* packet = (u_char*)malloc(packet_size);

		memcpy(packet, &radio, sizeof(radio));
		memcpy(packet+sizeof(radio), &beacon, sizeof(beacon));
		memcpy(packet+sizeof(radio)+sizeof(beacon), &tag, 2);
		memcpy(packet+(packet_size-tag.tag_len), tag.data, tag.tag_len);

		//send packet
		if(pcap_sendpacket(pcap, packet, packet_size) != 0){
                        fprintf(stderr, "pcap_sendpacket(%s) error\n", param.dev_);
                }

                free(packet);
		free(tag.data);

		index = (index+1)%ssid_num;
                sleep(0.1);
	}
		
	
	pcap_close(pcap);
}
