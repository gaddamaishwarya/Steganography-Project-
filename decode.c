/*
Name: Aishwarya Gaddam
Date: 23-01-2026
Description: LSB-based image steganography to securely hide and extract secret data within a BMP image without visible distortion.
Decoding functions to extract hidden data from stego images
*/
#include <stdio.h>
#include <string.h>
#include "decode.h"

Status do_decoding(char *argv[],DecodeInfo *decInfo)
{
    /*Validate command-line arguments for decoding*/
    if(validate_decode_args(argv,decInfo) == failure)               //Validate decode args
    {
        return failure;                                             //Return failure if validation fails
    }
        
    /*Decode and verify the magic string*/
    printf("## Decoding procedure Started ##\n");                   

    if(decode_magic_string(MAGIC_STRING,decInfo)==failure)              //  Decode magic string
    {
        return failure;
    }
    /*Decode secret file extension and create output file*/
    if(decode_secret_file_extn(decInfo) == failure)                    // Decode secret file extension
    {
        return failure;
    }
    /*Decode actual secret file data*/
    if(decode_secret_file_data(decInfo)== failure)               // Decode secret file data
    {
        return failure;
    }
    return success;
}
Status validate_decode_args(char *argv[], DecodeInfo *decInfo)              //Validate decode arguments
{
    if(argv[2])                                              //Check for encoded image file argument
    {
        char * res = strstr(argv[2],".bmp");                     //Check for .bmp extension           
        if((res == NULL) || (strcmp(res,".bmp") != 0))              
            return failure;
        else 
        {
            decInfo->encoded_image_fname=argv[2];                        //Store encoded image filename  
            printf("It's a %s file\n",decInfo->encoded_image_fname);        //Confirm valid .bmp file
        }
    }
    if(argv[3] == NULL)                                 //Check for output filename argument
    {
        strcpy(decInfo->output_fname,"secretfile");             //Set default output filename
        printf("Output file not mentioned. Creating %s as default\n",decInfo->output_fname);
    }
    else if(argv[3] != NULL)                                //If output filename is provided
    {
        int i=0;
        if(strstr(argv[3],"."))                             //If extension is provided in output filename
        {
            strcpy(decInfo->output_fname,argv[3]);          //Use provided output filename
        }
        else                                                //If no extension is provided
        {
            for(i=0;i<strlen(argv[3]);i++)
            {
                if(argv[3][i]=='.')                         
                    break;
                decInfo->output_fname[i]=argv[3][i];        //Copy filename part
            }
            decInfo->output_fname[i]='\0';                 //Null-terminate filename
        }
    }

    printf("Opening required files\n");

    if(open_image_files(decInfo)==failure)                //Open encoded image file
        return failure;
    return success; 
}
Status open_image_files(DecodeInfo *decInfo)                //Open encoded image file
{
    /*Open encoded image file in read mode*/
    decInfo->encode_image_fptr = fopen(decInfo->encoded_image_fname, "r");          //Open encoded image file

    printf("Opened %s\n",decInfo->encoded_image_fname);                 //Confirm file opened

    if (decInfo->encode_image_fptr == NULL)                             //If file opening fails
    {
    	perror("fopen");
    	fprintf(stderr, "ERROR: Unable to open file %s\n", decInfo->encoded_image_fname);       //Print error message

    	return failure;
    }
    return success;
}
Status decode_magic_string(const char *magic_string, DecodeInfo *decInfo)           //Decode magic string to verify stego image
{
    /*Skip BMP header 54 bytes*/
    fseek(decInfo->encode_image_fptr,54,SEEK_SET);

    /*Read 32 bytes to decode magic string length*/
    char buffer[32];
    fread(buffer,1,32,decInfo->encode_image_fptr);
    int magic_len=decode_4byte_from_lsb(buffer);        //Decode magic string length                    

    if(magic_len < 0)                               //If decoded length is invalid
    {
        printf("Magic String is not decoded successfully\n");
        return 0;
    }

    printf("Decoding Magic String Signature\n");

    /*Decode each character of magic string*/
    char magic_str[magic_len+1];
    char bufferstr[8];

    for(int i=0;i<magic_len;i++)
    {
        fread(bufferstr,1,8,decInfo->encode_image_fptr);            //Read 8 bytes for each character
        magic_str[i]=decode_1byte_from_lsb(bufferstr);              //Decode one character from LSBs
    }
    magic_str[magic_len]='\0';                      //Null-terminate decoded magic string

    if(strcmp(magic_str,MAGIC_STRING)==0)                                  //Compare decoded magic string with expected one
    {
        printf("Done\n");
        return success;
    }
    return failure;
}
Status decode_secret_file_extn(DecodeInfo *decInfo)             //Decode secret file extension
{
    /*Read extension length*/
    printf("Decoding secret file extension from stego image \n");
    char buffer_len[32];
    fread(buffer_len,1,32,decInfo->encode_image_fptr);          //Read 32 bytes for extension length
    int ext_len = decode_4byte_from_lsb(buffer_len);            //Decode extension length

    /*Decode each character of extension*/
    char ext[ext_len+1];                            //Initialize extension array
    char buffer_ext[8];

    for(int i=0;i<ext_len;i++)
    {
        fread(buffer_ext,1,8,decInfo->encode_image_fptr);           //Read 8 bytes for each character
        ext[i]=decode_1byte_from_lsb(buffer_ext);                   //Decode one character from LSBs
    }
    ext[ext_len]='\0';                          //Null-terminate decoded extension
    strcat(decInfo->output_fname,ext);          //Append extension to output filename

    /*Opening the file to write decoded data*/
    decInfo->output_fptr = fopen(decInfo->output_fname,"w");      //Open output file for writing decoded data

    if(decInfo->output_fptr == NULL)
        return failure;

    printf("Opened %s\n",decInfo->output_fname);                //Confirm output file opened    
    printf("Done. Opened all required files\n");

    return success;
}
Status decode_secret_file_data(DecodeInfo *decInfo)             //Decode secret file data
{
    /*Read secret file size*/
    printf("Decoding file size\n");
    char buffer[32];
    fread(buffer,1,32,decInfo->encode_image_fptr);          //Read 32 bytes for secret file size    
    int file_size = decode_4byte_from_lsb(buffer);
    printf("Done\n");

    /*Decode each character of secret data*/
    char bufferstr[8];
    char ch;
    printf("Decoding file data\n");

    for(int i=0;i<file_size;i++)                        //Loop for each byte of secret data
    {
        fread(bufferstr,1,8,decInfo->encode_image_fptr);    //Read 8 bytes for each character
        ch = decode_1byte_from_lsb(bufferstr);              //Decode one character from LSBs
        fwrite(&ch,1,1,decInfo->output_fptr);               //Write decoded character to output file
    }
    printf("Done\n");
    return success; 
}
/*Extract LSBs to reconstruct one character and Return decoded character*/
char decode_1byte_from_lsb(char *buffer_8)              //*Decode one character from LSBs*/
{
    char ch =0;
    for(int i=7;i>=0;i--)                               //Loop through each bit
    {
        ch = ch | (buffer_8[7-i] & 1) << i;             //Extract LSB and set corresponding bit in character
    }
    return ch;
}
/*Extract LSBs to reconstruct integer value and return decoded integer*/
int decode_4byte_from_lsb(char *buffer_32)
{
    int val =0;
    for(int i=31;i>=0;i--)
    {
        val = val | (buffer_32[31-i] & 1) << i;         //Extract LSB and set corresponding bit in integer
    }
    return val;
}
