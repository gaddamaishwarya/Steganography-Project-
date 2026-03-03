/*
Name: Aishwarya Gaddam
Date: 23-01-2026
Description: LSB-based image steganography to securely hide and extract secret data within a BMP image without visible distortion.
Common definitions and types used in encoding and decoding
*/

#ifndef COMMON_H
#define COMMON_H

/* Magic string to identify whether stegged or not */
#define MAGIC_STRING "#*"

/* Status will be used in fn. return type */
typedef enum
{
    failure,
    success
} Status;

typedef enum
{
    unsupported,
    encode,
    decode
} Opr_type;
#endif