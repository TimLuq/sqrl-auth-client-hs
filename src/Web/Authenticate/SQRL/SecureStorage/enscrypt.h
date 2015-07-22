#ifndef SQRL_ENSCRYPT_H
#define SQRL_ENSCRYPT_H

#include <stdint.h>
#include <stddef.h>

typedef void (enscrypt_notify)(int32_t, int32_t, uint32_t);

uint32_t sqrl_enscrypt_time(enscrypt_notify notify, int32_t time, uint8_t logn,
			    const uint8_t *salt, size_t saltlen,
			    const uint8_t *pass, size_t passlen,
			    uint8_t *output, size_t outlen);

uint32_t sqrl_enscrypt_iter(uint32_t iterations, uint8_t logn,
			    const uint8_t *salt, size_t saltlen,
			    const uint8_t *pass, size_t passlen,
			    uint8_t *output, size_t outlen);

#endif
