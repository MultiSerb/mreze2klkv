#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"

char* dacenaziv(char* message, char* key);//7 tacka

void dispatcher_handler(unsigned char* fd, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);//packet_handler


int icmpBrojac = 0;//ako treba brojati neke odredjene pakete

int main() {
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	// Open the capture file
	if ((device_handle = pcap_open_offline("example.pcap",error_buffer)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "example.pcap");
		return -1;
	}
	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	pcap_dumper_t* file_dumper = pcap_dump_open(device_handle, "encrypted_packets.pcap");//9 tacka ovde menjas ime ako treba
	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}
    //dovde uvek isto
/*filter nes disovo
	char filter_exp[] = "ip or arp";
	struct bpf_program fcode;
	
	if (pcap_compile(device_handle, &fcode, filter_exp, 1, 0xffffff) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}
	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

*/
	
	pcap_loop(device_handle, 0, dispatcher_handler, (unsigned char*)file_dumper);

    printf("Broj ICMP paketa:%d\n", icmpBrojac);//broj neki odredjenih paketa obicno se trazi u 3 tacki

	
	pcap_close(device_handle);
    

	

	return 0;
}

void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
//printf("Paket pristigao:%ld:%ld\n", packet_header->ts.tv_sec,packet_header->ts.tv_usec);//vreme pristizanja paketa

    char copy[10000];
	memset(copy, 0, packet_header->len * sizeof(char));

    //printf("\n\nPacket length: %ld bytes", packet_header->len);//duzina zaglavlja izrazena u bajtima
    ethernet_header* eh = (ethernet_header*)packet_data;
	memcpy(copy, eh, sizeof(ethernet_header) * sizeof(char));
/*
    printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eh->dest_address[0], eh->dest_address[1], eh->dest_address[2],
		eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);
*///fizicka adresa primaoca -ovde ide ako oces za svaki dole ako oces posebno za neki-ovde ako je 1 tacka

//printf("\nSource MAC: %x\nDestination MAC: %x\n", eh->src_address, eh->dest_address); posiljalac i primaoc



//printf("Logicka adresa primaoca: %d.%d.%d.%d\n", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);

//printf("Source IP Address: %d.%d.%d.%d \n", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);

//trazis sta ti treba 2 tacka
    if (ntohs(eh->type) == 0x806)//ARP
	{
		printf("Protokol: ARP");
    }
    else  if (ntohs(eh->type) == 0x0800) //IPv4 
	{
         ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));
		memcpy(copy + sizeof(ethernet_header), ih, (ih->header_length * 4) * sizeof(char));//za ipv4

		printf("Source IP Address: %d.%d.%d.%d \n", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);//logicka adresa posiljaoca
		printf("TTL: %d\n", ih->ttl);//timetolive vrednost
		printf("Header size: %d\n", ih->header_length * 4);//vrednost duzina zaglavlja u bajtovima(zato je *4)

        switch (ih->next_protocol) {
		case 6: /*TCP*/ {
			printf("\nType:TCP");

			tcp_header* th = (tcp_header*)(packet_data + sizeof(ethernet_header) + ih->header_length * 4);

			printf("\nSrc port: %u\nDest port: %u\n", th->src_port, th->dest_port);//ispisni port 

			printf("ACK number: %d", th->ack_num);//  broj potvrde
            //printf("Window size: %u\n", ntohs(th->windows_size));velicina prozora

/*
if (th->flags == 16 && th->sequence_num == 0) {sinhronacioni bit i br sekvenci=0
				printf("ACK flag detected and seq num=0;\n");
				printf("Source port: %u\n", ntohs(th->src_port));
			}

*/
/*
if (ntohs(th->src_port) == 80 || ntohs(th->dest_port) == 80) {da bude u asciii formatu ako je  tpc i http
				printf("HTTP protocol, data: \n");

				char* app_data = (char*)((unsigned char*)th + th->header_length * 4);
				for (int i = 0; i < 16; i++) {
					printf("%c", app_data[i]);
				}
				printf("\n");


*/
/*
for (int i = 0;i < th->header_length * 4; i++) {sirov oblik
				printf("%.2x", th[i]);
				if ((i + 1) % 16 == 0)
					printf("\n");
			}


*/


			if (th->dest_port == 443 || th->src_port == 443) { //TLS/SSL on 443  broji tls protokol
				printf("TCP segment has TLS protocol.");
				tlsBrojac++;
				/*PLACE TO SEARCH FOR CONTENT TYPE INSIDE HEADER*/
			}
			break;
		}
		case 17:/*UDP*/ {
			printf("\nType:UDP");
			udp_header* uh = (udp_header*)(packet_data + sizeof(ethernet_header) + ih->header_length * 4);
			printf("\nSrc port: %u\nDest port: %u\n", uh->src_port, uh->dest_port);//ulaz i izlaz

			memcpy(copy + sizeof(ethernet_header) + ih->header_length * 4, uh, sizeof(udp_header));

			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));//ovo saljes u kriptovanje
			int app_length = ntohs(uh->datagram_length) - sizeof(udp_header);

            //printf("UDP: Packet size: %u\n", ntohs(uh->datagram_length));-ukupna duzina podataka koji se salju

			printf("Data: ");
			for (int i = 0; i < app_length; i++)
			{
				printf("%x ", app_data[i]);
				if ((i + 1) % 16 == 0)
					printf("\n");
			}
			printf("\n");

			app_data[app_length] = '\0';
			char* encrypted = vigenere(app_data, key);//poziv kript
			printf("\nEncoded: %s\n", encrypted);

			memcpy(copy + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header), encrypted, strlen(encrypted));
			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)copy);

			break;
		}
		default:break;
		}


	}
	else {
		return;
	}
    }

char* vigenere(char* message, char* key) {//viznerov
	int messageLen = strlen(message);
	int keyLen = strlen(key);

	// Ensure key is not empty
	if (keyLen == 0) {
		return "Error: Key should not be empty";
	}

	// Extend the key if it's shorter than the message
	for (int i = 0; i < messageLen; ++i) {
		if (key[i % keyLen] == '\0') {
			key[i % keyLen] = key[i % keyLen - keyLen];
		}
	}

	// Vigenere
	for (int i = 0; i < messageLen; ++i) {
		if (message[i] >= 'A' && message[i] <= 'Z') {
			message[i] = 'A' + (message[i] - 'A' + key[i % keyLen] - 'A') % 26;
		}
		else if (message[i] >= 'a' && message[i] <= 'z') {
			message[i] = 'a' + (message[i] - 'a' + key[i % keyLen] - 'a') % 26;
		}
	}
	message[messageLen] = '\0';

	return message;
}

char* encrypt_data(char* message, char* key) {//cezar+vizner
	// Vigenere algorithm
	size_t messageLen = strlen(message);
	size_t keyLen = strlen(key);

	if (messageLen == 0 || keyLen == 0) {
		return NULL;
	}

	for (size_t i = 0; i < messageLen; ++i) {
		if (message[i] >= 'A' && message[i] <= 'Z') {
			message[i] = 'A' + (message[i] - 'A' + key[i % keyLen] - 'A') % 26;
		}
		else if (message[i] >= 'a' && message[i] <= 'z') {
			message[i] = 'a' + (message[i] - 'a' + key[i % keyLen] - 'a') % 26;
		}
	}

	return message;
}


/*#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* homophone(char* message, int* key);

int main() {//homofon sifra
    int key[] = {3302, 5, 4, 10, 5812, 21, 99, 83, 7101, 6, 47, 91, 12, 22, 1416, 31, 56, 42, 8, 77, 6652, 51, 39, 46, 24, 29};

    char message[] = "HELLO";
    printf("Original Message: %s\n", message);

    homophone(message, key);

    printf("Encrypted Message: ");
    for (int i = 0; i < strlen(message); i++) {
        printf("%d ", message[i]);
    }

    return 0;
}

char* homophone(char* message, int* key) {


	for (int i = 0; i < strlen(message); i++) {
		if (message[i] == 'A' || message[i] == 'E' || message[i] == 'I' || message[i] == 'O' || message[i] == 'U') {
			int randomInteger = rand();
			// Scale the random integer to a floating-point number in the range [0, 1)
			double randomFloat = (double)randomInteger / RAND_MAX;
			if (randomFloat >= 0.5) {
				message[i] = key[message[i] - 'A'] % 100; //higher portion
			}
			else {
				message[i] = key[message[i] - 'A'] / 100; //lower portion
			}
		}
		else {
			message[i] = key[message[i] - 'A']; //getting a number between 0 and 25 and mapping key value to it
		}
	}
	return message;
}*/


const char* plejfer(char* poruka) {
	int x1 = -1, x2 = -1, y1 = -1, y2 = -1;

	int duzinaPoruke = strlen(poruka);

	char neutralniKarakter = 'T'; // Pozicija [3][3]
	
	char kriptovanaPoruka[200];

	for (int i = 0;i < duzinaPoruke;i++) {
		if (poruka[i] == 'J') {
			poruka[i] = 'I';
		}
	}

	for (int i = 0;i < duzinaPoruke;i += 2) {

		for (int j = 0;j < 5;j++) {
			for (int k = 0;k < 5;k++) {
				if (kljuc[j][k] == poruka[i]) {
					x1 = j;
					y1 = k;
				}if (kljuc[j][k] == poruka[i + 1]) {
					x2 = j;
					y2 = k;
				}
			}
		}

		if (i == duzinaPoruke-1) {
			x2 = 3;
			y2 = 3;
		}

		if (x1 == x2 && y1 == y2) {
			kriptovanaPoruka[i] = poruka[i];
			kriptovanaPoruka[i + 1] = 'X';
		}
		else {
			if (x1 == x2) {
				if (y1 == 4) {
					kriptovanaPoruka[i] = kljuc[x1][0];
				}
				else {
					kriptovanaPoruka[i] = kljuc[x1][y1 + 1];
				}
				if (y2 == 4) {
					kriptovanaPoruka[i + 1] = kljuc[x2][0];
				}
				else {
					kriptovanaPoruka[i + 1] = kljuc[x2][y2 + 1];
				}
			}
			else if (y1 == y2) {
				if (x1 == 4) {
					kriptovanaPoruka[i] = kljuc[0][y1];
				}
				else {
					kriptovanaPoruka[i] = kljuc[x1 + 1][y1];
				}if (x2 == 4) {
					kriptovanaPoruka[i + 1] = kljuc[0][y2];
				}
				else {
					kriptovanaPoruka[i + 1] = kljuc[x2 + 1][y2];
				}
			}
			else {
				kriptovanaPoruka[i] = kljuc[x1][y2];
				kriptovanaPoruka[i + 1] = kljuc[x2][y1];
			}

		}
	}
	kriptovanaPoruka[duzinaPoruke] = '\0';
	return kriptovanaPoruka;
}