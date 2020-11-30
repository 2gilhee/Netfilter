#include <iostream>
#include <iomanip>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <bits/stdc++.h>

using namespace std;

void hextoAscii(uint8_t* data, int length);
void printLine();
void printByHexData(u_int8_t *printArr, int length);
void getError(string error);
static int callback(struct nfq_q_handle *qhandle, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data);

int main(int argc, char *argv[]) {
    struct nfq_handle* handle = nfq_open();

    /*open lib handle*/
    if(!handle)
        getError("error during nfq_open()");

    /*unbinding existing nf_queue handler for AF_INET*/
    if(nfq_unbind_pf(handle,AF_INET) < 0)
        getError("error during nfq_unbind_pf()");

    /*binding nfnetlink_queue as nf_queue handler for AF_INET*/
    if(nfq_bind_pf(handle,AF_INET) < 0)
        getError("error during nfq_bind_pf()");

    /*binding this socket to queue '0'*/
    struct nfq_q_handle* qhandle = nfq_create_queue(handle, 0, &callback, 0); //you can give user defined parameter at last parameter. (e.g., nfq_create_queue(handle,0,&callback,&userClass);)
    if(!qhandle)
        getError("error during nfq_create_queue()");

    /*setting copy_packet mode*/

    if(nfq_set_mode(qhandle, NFQNL_COPY_PACKET, 0xffff) < 0)
        getError("can't set packet_copy mode");

    int fd = nfq_fd(handle);
    int rv=0;
    char buf[4096] __attribute__ ((aligned));


    while (true) {
        if((rv=recv(fd,buf,sizeof(buf),0))>=0) //if recv success
            nfq_handle_packet(handle,buf,rv); //call callback method
    }
    return 0;
}

void hextoAscii(uint8_t* data, int length) {
  char temp[length] = {0,};
  for(int i=0; i<length; i++){
    if(data[i] == 0x0d && data[i+1] == 0x0a){
      // cout << "i: " << i << endl;
      cout << temp << endl;
      sprintf(temp, "%s", "");
      i++;
    } else {
      // cout << "i: " << i << endl;
      sprintf(temp, "%s%c", temp, data[i]);
    }
  }
}

void _hextoAscii(uint8_t* data, int length) {
  char temp[length] = {0,};
  for(int i=0; i<length; i++) {
    if(data[i] == 0x0d && data[i+1] == 0x0a){
      // cout << "i: " << i << endl;
      cout << temp << endl;
      cout << temp[0] << endl;
      sprintf(temp, "%s", "");
      i++;
    } else {
      // cout << "i: " << i << endl;
      sprintf(temp, "%s%c", temp, data[i]);
    }
  }
}

void hostname(uint8_t* data, int length, char* temp) {
  // char temp[length] = {0,};
  for(int i=0; i<length; i++) {
    if(data[i] == 0x0d && data[i+1] == 0x0a){
      // cout << "test" << endl;
      break;
    } else {
      // cout << "i: " << i << endl;
      sprintf(temp, "%s%c", temp, data[i]);
    }
  }
  // sprintf(temp, "%s%x", temp, 0x00);
  // cout << temp << endl;
}

// void toAscii(uint8_t* data, int length) {
//   char temp[length] = {0,};
//   for(int i=0; i<length; i++) {
//     cout << "test: " << data[i] << " " << data[i+1] << endl;
//     if(data[i] == 0x0d && data[i+1] == 0x0a){
//       cout << "test" << endl;
//       break;
//     } else {
//       // cout << "i: " << i << endl;
//       sprintf(temp, "%s%c", temp, data[i]);
//     }
//   }
//   // sprintf(temp, "%s%x", temp, 0x00);
//   cout << temp << endl;
// }

void httpData(uint8_t* data, int length, char* temp) {
  //{'h', 'o', 's', 't', ':', 0x00};
  //{0x48, 0x6f, 0x73, 0x74, 0x3a, 0x00};
  uint8_t test[] = {'H', 'o', 's', 't', ':', 0x00};
  // printf("%02x %02x %02x %02x %02x\n", test[0], test[1], test[2], test[3], test[4]);
  int num = 1;
  for(int i=0; i<length-5; i++) {
    // toAscii(data+i, 5);
    num = memcmp(data+i, test, 5);
    if(num == 0) {
      // printf("%02x %02x %02x %02x %02x\n", data[i], data[i+1], data[i+2], data[i+3], data[i+4]);
      // printf("%02x %02x %02x %02x %02x\n", test[0], test[1], test[2], test[3], test[4]);
      // cout << "SAME!!" << endl;
      // char temp[20] = {0,};
      hostname(data+i+6, 50, temp);
      // cout << "OUT: " << temp << endl;
      break;
    }
  }
}

void getError(string error) {
    perror(error.c_str());
    exit(1);
}

static u_int32_t checkPacket(nfq_data *tb, int &flag) {
    int id = 0;
    int protocol = 0;
    int hook = 0;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        protocol = ntohl(ph->hw_protocol);
        hook = ph->hook;
      }
      // printf("packet_id: %02x\n", id);
      // printf("protocol: %02x\n", protocol);
      // printf("hook: %02x\n", hook);


    uint8_t* data;
    int ret = nfq_get_payload(tb, &data);
    // cout << ret << endl;
    // printByHexData(data, ret);

    struct ip* ipHeader;

    ipHeader = (struct ip*)data;
    int ipHeaderLength = ipHeader->ip_hl * 4;
    // printByHexData((uint8_t*)ipHeader, ipHeaderLength);

    // printf("ip_protocol: %02x\n", ipHeader->ip_p);

    if(ipHeader->ip_p == IPPROTO_TCP) {
      // cout << "it's TCP packet" << endl;

      struct tcphdr* tcpHeader;
      data += ipHeaderLength;
      tcpHeader = (struct tcphdr*)data;
      int tcpHeaderLength = tcpHeader->doff*4;
      // printByHexData((uint8_t*)tcpHeader, tcpHeaderLength);
      // int sourcePort = htons(tcpHeader->source);
      int destPort = htons(tcpHeader->dest);

      if(destPort == 0x0050){
        // printf("it's TCP packet.\nSource Port: %04x\nIt's HTTP port.\n", sourcePort);

        data += tcpHeaderLength;
        // flag = NF_DROP;

        if((ret-ipHeaderLength-tcpHeaderLength) > 0) {
          // printByHexData(data, ret);
          // flag = NF_DROP;

          printf("it's TCP packet.\nSource Port: %04x\nIt's HTTP port.\n", destPort);
          // printByHexData((uint8_t*)ipHeader, ipHeaderLength);
          // printf("ip_protocol: %02x\n", ipHeader->ip_p);
          // printByHexData((uint8_t*)tcpHeader, tcpHeaderLength);
          // cout << "flag: " << flag << endl;
          // printByHexData(data, ret-ipHeaderLength-tcpHeaderLength);

          char temp[20] = {0,};
          httpData(data, ret-ipHeaderLength-tcpHeaderLength, temp);
          cout << "OUT URL: " << temp << endl;
          char* url = "www.gilgil.net";
          int isURL = strcmp(url, temp);
          // cout << "isURL: " << isURL << endl;
          // cout << url[0] << url[1] << endl;
          // cout << "\nleft length: " << ret-ipHeaderLength-tcpHeaderLength << endl;

          if(isURL == 0) {
            cout << "[gilgil.net]It's " << temp << endl;
            flag = NF_DROP;
            cout << "flag: " << flag << endl;
          } else {
            cout << "It's " << temp << endl;
            flag = NF_ACCEPT;
            cout << "flag: " << flag << endl;
          }

        } else {
          flag = NF_ACCEPT;
        }

      } else if(destPort == 0x01bb) {
        // printf("Source Port: %04x\nIt's HTTPS port.\n", sourcePort);
        flag = NF_ACCEPT;
        // cout << "flag: " << flag << endl;
      } else if(destPort == 0xd8b0) {
        // printf("Source Port: %04x\nIt's 55472 port.\n", sourcePort);
        flag = NF_ACCEPT;
        // cout << "flag: " << flag << endl;
      } else {
        flag = NF_ACCEPT;
        // cout << "flag: " << flag << endl;
      }

      printLine();
    } else {
      flag = NF_ACCEPT;
      // cout << "flag: " << flag << endl;
    }

    if(ret<=0) { //no ip packet
        return id;
    }

// FLAG can set as NF_DROP or NF_ACCEPT
//    flag=NF_DROP;
//    flag=NF_ACCEPT;

    return id;
}

void printLine() {
	cout << "-----------------------------------------------" << endl;
}

void printByHexData(u_int8_t *printArr, int length) {
	for(int i=0; i<length; i++) {
		if(i%16 == 0)
			cout << endl;
		cout << setfill('0');
		cout << setw(2) << hex << (int)printArr[i] << " ";
	}
	cout << dec << endl;
	printLine();
}

static int callback(nfq_q_handle *qhandle, nfgenmsg *nfmsg, nfq_data *nfa, void *data)
{
    (void)nfmsg;

    int flag=0;
    u_int32_t id = checkPacket(nfa,flag); //call another method

    // return nfq_set_verdict(qhandle, id, flag, sizeof(nfmsg), NULL);
// gilgil.net
    return nfq_set_verdict(qhandle, id, flag, 0, NULL); //decide Drop or Accept
}
