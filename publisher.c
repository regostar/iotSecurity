

/**
*author :- ReGo
*This code is a mqtt client, which publishes to a topic, 
*the beauty is that it publishes encrypted payload
*to compile >>gcc -o encr encr5.c -lmosquitto -lmcrypt
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>//mqtt stack
/*
 * MCrypt API available online:
 * http://linux.die.net/man/3/mcrypt
 */
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#define MQTT_HOSTNAME "127.0.0.1"
#define MQTT_PORT 1883
#define MQTT_USERNAME ""
#define MQTT_PASSWORD ""
#define MQTT_TOPIC "simple"

int encrypt(

    void* buffer,
    int buffer_len, /* Because the plaintext could include null bytes*/
    char* IV, 
    char* key,
    int key_len 
){
 
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

int decrypt( 
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
 
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);

  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

void display(char* ciphertext, int len){
  int v;
  printf("%s \n",ciphertext);
  printf("\n");
}


void mosquitto_routine(char* buffer){
  /*function performs initialize, connect ,publish buffer*/
  struct mosquitto *mosq=NULL;
  mosquitto_lib_init();
  // Create a new Mosquitto runtime instance with a random client ID,  
  mosq = mosquitto_new (NULL, true, NULL);
  if (!mosq)
    {
      fprintf (stderr, "Can't initialize Mosquitto library\n");
      exit (-1);
    }
  //mosquitto_username_pw_set (mosq, MQTT_USERNAME, MQTT_PASSWORD);
  int ret = mosquitto_connect (mosq, MQTT_HOSTNAME, MQTT_PORT, 0);
  if (ret)
    {
      fprintf (stderr, "Can't connect to Mosquitto server\n");
      exit (-1);
    }
  ret = mosquitto_publish (mosq, NULL, MQTT_TOPIC,strlen (buffer), buffer, 0, false);
  if (ret)
    {
      fprintf (stderr, "Can't publish to Mosquitto server\n");
      exit (-1);
    }

}
int main()
{
  //MCRYPT td, td2;
  char * plaintext = "{\"toIpv4\":\"62.195.152.223\",\"fromIpv4\":\"192.168.174.57\",\"payload\":\"810A001B012403E906010000000000FF0275020C0C008000011955\", \"gwid\":\"000B57FFFEA8F9C5\"}";
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = "this_is_my_key03";
  int keysize = 16; /* 128 bits */
  char* buffer;

  int rv;

  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  int plaintext_len=strlen(plaintext);
  int diff=plaintext_len%blocksize;
  buffer = calloc(1, plaintext_len+blocksize-diff);
  strncpy(buffer, plaintext, plaintext_len);
    if(diff!=0)
   {
     
     memset(buffer+plaintext_len,' ',blocksize-diff);
   }
  int buffer_len = strlen(buffer);
  printf("AES Algorithm used is rijndael-128 \n Mode is CBC \n");
  printf(" Plaintext length= %d \n Block length = %d \n Difference= %d \n Buffer length after appending spaces= %d \n ",plaintext_len,blocksize,diff,buffer_len);
  printf("====================================C========================================\n");
  printf("plaintext after appending spaces:   %s end\n", buffer);
  printf("====================================C========================================\n");
  rv=encrypt(buffer, buffer_len, IV, key, keysize); 
  printf("cipher text:  \n");
  display(buffer , buffer_len);
  printf("====================================C========================================\n");

  mosquitto_routine(buffer);



  printf("\n PUBLISHED SUCCESSFULLY\n");

  
  return 0;
}
