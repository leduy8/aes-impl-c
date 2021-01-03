#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

// Enable both ECB and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DECB=1
#define CBC 1
#define ECB 1

#include "aes.h"

#ifdef AES128
uint8_t len = 16;
#elif defined(AES192)
uint8_t len = 24;
#elif defined(AES256)
uint8_t len = 32;
#endif

static void phex(uint8_t *str);
static void test_ecb_verbose(void);

char *readlinesFromFile(FILE *fPointer)
{
  char *stream = (char *)malloc(17 * sizeof(char));
  char *text = fgets(stream, 17, fPointer);
  return text;
}

void openFile(FILE *fPointer, uint8_t *text, const char *path, const char *mode)
{
  fPointer = fopen(path, mode);

  if (fPointer == NULL)
  {
    fprintf(stderr, "Failed to open file\n");
    exit(1);
  }

  if (strcmp(mode, "r") == 0)
  {
    char *t = readlinesFromFile(fPointer);
    for (int i = 0; i < len; i++)
      text[i] = (uint8_t)t[i];
  }
  else if (strcmp(mode, "w") == 0)
  {
    for (int i = 0; i < len; i++)
      fputc((char)text[i], fPointer);
  }

  fclose(fPointer);
}

int main(void)
{
#ifdef AES128
  printf("\nTesting AES128\n\n");
#elif defined(AES192)
  printf("\nTesting AES192\n\n");
#elif defined(AES256)
  printf("\nTesting AES256\n\n");
#else
  printf("You need to specify a symbol between AES128, AES192 or AES256. Exiting");
  return 0;
#endif

  test_ecb_verbose();

  return 0;
}

// prints string as hex
static void phex(uint8_t *str)
{
  unsigned char i;
  for (i = 0; i < len; ++i)
    printf("%.2x", str[i]);
  printf("\n");
}

static void test_ecb_verbose()
{
  struct timeval startEncrypt, endEncrypt;
  struct timeval startDecrypt, endDecrypt;
  FILE *fPointer = NULL;
  uint8_t *key = (uint8_t *)malloc(len * sizeof(uint8_t));
  uint8_t *plaintext = (uint8_t *)malloc(len * sizeof(uint8_t));
  uint8_t *ciphertext = (uint8_t *)malloc(len * sizeof(uint8_t));
  uint8_t buf[len], buf2[len]; // * buf to store encrypted text, buf2 to store decrypted text
  memset(buf, 0, len);
  memset(buf2, 0, len);

  openFile(fPointer, key, "key.txt", "r");
  printf("key:\n");
  phex(key);
  printf("\n");

  // print text to encrypt, key and IV
  gettimeofday(&startEncrypt, NULL);
  printf("ECB encrypt verbose:\n\n");
  printf("plain text:\n");
  openFile(fPointer, plaintext, "plant_text.txt", "r");
  phex(plaintext);
  printf("\n");

  printf("ciphertext:\n");
  AES_ECB_encrypt(plaintext, key, buf, len);
  phex(buf);
  openFile(fPointer, buf, "encrypted.txt", "w");
  printf("\n");
  gettimeofday(&endEncrypt, NULL);

  gettimeofday(&startDecrypt, NULL);
  printf("\nECB decrypt verbose:\n\n");
  printf("ciphertext:\n");
  openFile(fPointer, ciphertext, "encrypted.txt", "r");
  phex(ciphertext);
  printf("\n");

  printf("plain text:\n");
  AES_ECB_decrypt(ciphertext, key, buf2, len);
  openFile(fPointer, buf2, "decrypted.txt", "w");
  phex(buf2);
  printf("\n");
  gettimeofday(&endDecrypt, NULL);

  printf("Thời gian mã hóa mất %lu us(microseconds)\n", (endEncrypt.tv_sec - startEncrypt.tv_sec) * 1000000 + endEncrypt.tv_usec - startEncrypt.tv_usec);

  printf("Thời gian giải mã mất %lu us(microseconds)\n", (endDecrypt.tv_sec - startDecrypt.tv_sec) * 1000000 + endDecrypt.tv_usec - startDecrypt.tv_usec);
}
