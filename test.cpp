#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

using namespace std;

int intToAscii(int number) {
   return '0' + number;
}

void hextoAscii(uint8_t* data, int length) {
  char temp[50] = {0,};
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

int main() {
  uint8_t data[] = {0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x00};
   // printf("The ASCII of 5 is %d\n", intToAscii(5));
   // printf("The ASCII of 8 is %d\n", intToAscii(8));

   uint8_t aa[] = {'h', 'o', 's', 't', 0x00};
   cout << &aa << endl;
   cout << &data << endl;
   cout << aa << endl;
   cout << sizeof(aa) << endl;
   cout << strlen((const char*)aa) << endl;

   // cout << sizeof(data) << endl;
   // hextoAscii(data, sizeof(data));
}
