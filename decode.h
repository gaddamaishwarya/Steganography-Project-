/*
Name: Aishwarya Gaddam
Date: 23-01-2026
Description: LSB-based image steganography to securely hide and extract secret data within a BMP image without visible distortion.
Decoding functions to extract hidden data from stego images
*/
#ifndef DECODE_H
#define DECODE_H

#include "common.h"

typedef struct DecodeInfo
{
    char *encoded_image_fname;  
    FILE *encode_image_fptr;

    char output_fname[30];
    FILE *output_fptr;

}DecodeInfo;
/* Decoding function prototype */

/* Read and validate Decode args from argv */
Status validate_decode_args(char *argv[], DecodeInfo *decInfo);

/*Core decoding controller function*/
Status do_decoding(char *argv[],DecodeInfo *decInfo);

/*Open encoded image file*/
Status open_image_files(DecodeInfo *decInfo);

/* decode Magic String data to verify stego image */
Status decode_magic_string(const char *magic_string, DecodeInfo *decInfo);

/* decode secret file extenstion */
Status decode_secret_file_extn(DecodeInfo *decInfo);

/* decode secret file data*/
Status decode_secret_file_data(DecodeInfo *decInfo);

/* decode 1 byte from LSB of output image data array */
char decode_1byte_from_lsb(char *buffer_8);

/* decode 4byte(int) from LSB of output image data array */
int decode_4byte_from_lsb(char *buffer_32);

#endif