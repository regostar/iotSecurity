

/**
*author :- ReGo
*This code is a mqtt client, which subscribes to a topic, 
*the beauty is that it receives encrypted payload and decrypts it
*to compile >>gcc -o encr2 encr5.c -lmosquitto -lmcrypt
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


void decrypt_master(char *buffer)
{
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = "this_is_my_key03";
  int keysize = 16; /* 128 bits */
  int rv;
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  int buffer_len = strlen(buffer);
  printf("AES Algorithm used is rijndael-128 \n Mode is CBC \n");
  display(buffer , buffer_len);
  rv=decrypt(buffer, buffer_len,IV, key, keysize);
  printf("decrypted:\n %s\n", buffer);
}

void my_message_callback(struct mosquitto *mosq, void *obj,
    const struct mosquitto_message *message)
  { 
    //called when a message is received
    char* buffer=(char*)malloc(65536);
    buffer=(char *)message->payload;
    printf ("Got message: %s\n", (char *)message->payload);
    decrypt_master(buffer);
  }


void mqtt_receive(){
  /*function performs initialize, connect, subscribe, set callback on receive buffer*/
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
  mosquitto_subscribe (mosq, NULL, MQTT_TOPIC, 0);

  // Specify the function to call when a new message is received
  mosquitto_message_callback_set (mosq, my_message_callback);
  printf("Waiting for message\n");
  // Wait for new mes0% sages
  mosquitto_loop_forever (mosq, -1, 1); 	
}




int main()
{
  //MCRYPT td, td2;
   
  mqtt_receive();
 
  return 0;
}
