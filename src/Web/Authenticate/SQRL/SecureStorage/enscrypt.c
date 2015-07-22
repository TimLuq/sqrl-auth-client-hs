#include "enscrypt.h"
#include "crypto_scrypt.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define SQRL_ENSCRYPT_OUTPUT_SIZE 32

uint32_t sqrl_enscrypt_time(enscrypt_notify notify, int32_t dtime, uint8_t logn,
			    const uint8_t *salt, size_t saltlen,
			    const uint8_t *pass, size_t passlen,
			    uint8_t *output, size_t outlen)
{
  if (outlen != SQRL_ENSCRYPT_OUTPUT_SIZE) {
    (void) fprintf(stderr, "ffi:sqrl_enscrypt_time: unexpected output size %d.\n", (int) outlen);
    return -2;
  }
  if (saltlen > SQRL_ENSCRYPT_OUTPUT_SIZE) {
    (void) fprintf(stderr, "ffi:sqrl_enscrypt_time: unexpected salt size %d.\n", (int) saltlen);
    return -4;
  }
  memset(output, 0, SQRL_ENSCRYPT_OUTPUT_SIZE);
  time_t current_time = time(NULL);
  time_t start_time = current_time;
  time_t notify_time = current_time;
  if (current_time == ((time_t)-1)) {
    (void) fprintf(stderr, "ffi:sqrl_enscrypt_time: failure to compute the current time.\n");
    return -8;
  }
  time_t goal_time = current_time + dtime;
  uint8_t buff0[SQRL_ENSCRYPT_OUTPUT_SIZE];
  uint8_t buff1[SQRL_ENSCRYPT_OUTPUT_SIZE];
  if (saltlen == SQRL_ENSCRYPT_OUTPUT_SIZE) {
    memcpy(buff0, salt, SQRL_ENSCRYPT_OUTPUT_SIZE);
  } else {
    memcpy(buff0, salt, saltlen);
    memset(buff0+saltlen, 0, SQRL_ENSCRYPT_OUTPUT_SIZE - saltlen);
  }
  memset(buff1, 0, SQRL_ENSCRYPT_OUTPUT_SIZE);
  uint64_t n = ((uint64_t) 1) << logn;
  uint32_t i;
  int j;
  int errcode;

  for (i = 0; 1; i++) {
    if ((i & 3) == 0) {
      if ((current_time = time(NULL)) >= goal_time) break;
      if (current_time != notify_time) notify((int32_t) ((((int32_t) (current_time - start_time)) * 100) / dtime), (int32_t) (goal_time - current_time), i);
    }
    // generate scrypt result from salt and pass -> xor result with output and result is next salt
    errcode = crypto_scrypt(pass, passlen, salt, saltlen, n, 256, 1, buff1, SQRL_ENSCRYPT_OUTPUT_SIZE);
    if (errcode != 0) {
      (void) fprintf(stderr, "ffi:sqrl_enscrypt_time: scrypt error occured (%d).\n", errno);
      return errcode;
    }
    for (j = 0; j < SQRL_ENSCRYPT_OUTPUT_SIZE; j++) {
      output[j] ^= buff1[j];
    }
    i++; // do the same thing but with switched buffers
    errcode = crypto_scrypt(pass, passlen, buff1, SQRL_ENSCRYPT_OUTPUT_SIZE, n, 256, 1, buff0, SQRL_ENSCRYPT_OUTPUT_SIZE);
    if (errcode != 0) {
      (void) fprintf(stderr, "ffi:sqrl_enscrypt_time: scrypt error occured (%d).\n", errno);
      return errcode;
    }
    for (j = 0; j < SQRL_ENSCRYPT_OUTPUT_SIZE; j++) {
      output[j] ^= buff0[j];
    }
    // make new iterations salt the output of this iteration.
    salt = buff0;
    saltlen = SQRL_ENSCRYPT_OUTPUT_SIZE;
  }

  // return number of iterations
  return i;
}



uint32_t sqrl_enscrypt_iter(uint32_t iterations, uint8_t logn,
			    const uint8_t *salt, size_t saltlen,
			    const uint8_t *pass, size_t passlen,
			    uint8_t *output, size_t outlen)
{
  if (outlen != SQRL_ENSCRYPT_OUTPUT_SIZE) {
    (void) fprintf(stderr, "ffi:sqrl_enscrypt_iter: unexpected output size %d.\n", (int) outlen);
    return -2;
  }
  if (saltlen > SQRL_ENSCRYPT_OUTPUT_SIZE) {
    (void) fprintf(stderr, "ffi:sqrl_enscrypt_iter: unexpected salt size %d.\n", (int) saltlen);
    return -4;
  }
  memset(output, 0, SQRL_ENSCRYPT_OUTPUT_SIZE);
  uint8_t buff0[SQRL_ENSCRYPT_OUTPUT_SIZE];
  uint8_t buff1[SQRL_ENSCRYPT_OUTPUT_SIZE];
  if (saltlen == SQRL_ENSCRYPT_OUTPUT_SIZE) {
    memcpy(buff0, salt, SQRL_ENSCRYPT_OUTPUT_SIZE);
  } else {
    memcpy(buff0, salt, saltlen);
    memset(buff0+saltlen, 0, SQRL_ENSCRYPT_OUTPUT_SIZE - saltlen);
  }
  memset(buff1, 0, SQRL_ENSCRYPT_OUTPUT_SIZE);
  uint64_t n = ((uint64_t) 1) << logn;
  uint32_t i;
  int j;
  int errcode;

  for (i = 0; i < iterations; i++) {
    // generate scrypt result from salt and pass -> xor result with output and result is next salt
    errcode = crypto_scrypt(pass, passlen, buff0, saltlen, n, 256, 1, buff1, SQRL_ENSCRYPT_OUTPUT_SIZE);
    if (errcode != 0) {
      (void) fprintf(stderr, "ffi:sqrl_enscrypt_iter: scrypt error occured (%d).\n", errno);
      return errcode;
    }
    for (j = 0; j < SQRL_ENSCRYPT_OUTPUT_SIZE; j++) {
      output[j] ^= buff1[j];
    }
    if (++i == iterations) break; // check if the number of iterations has been reached
    saltlen = SQRL_ENSCRYPT_OUTPUT_SIZE;
    // do the same thing as the beginning of the block but with switched buffers
    errcode = crypto_scrypt(pass, passlen, buff1, SQRL_ENSCRYPT_OUTPUT_SIZE, n, 256, 1, buff0, SQRL_ENSCRYPT_OUTPUT_SIZE);
    if (errcode != 0) {
      (void) fprintf(stderr, "ffi:sqrl_enscrypt_iter: scrypt error occured (%d).\n", errno);
      return errcode;
    }
    for (j = 0; j < SQRL_ENSCRYPT_OUTPUT_SIZE; j++) {
      output[j] ^= buff0[j];
    }
  }

  // return number of iterations
  return i;
}
