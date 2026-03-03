/*
Name: Aishwarya Gaddam
Date: 23-01-2026
Description: LSB-based image steganography to securely hide and extract secret data within a BMP image without visible distortion.
Encoding functions to hide data within images
*/
#include <stdio.h>
#include <string.h>
#include "encode.h"

/* Get image size
 * Input: Image file ptr
 * Output: width * height * bytes per pixel (3 in our case)
 * Description: In BMP Image, width is stored in offset 18,
 * and height after that. size is 4 bytes
 */
unsigned int get_image_size_for_bmp(FILE *fptr_image)
{
    unsigned int width, height;
    // Seek to 18th byte
    fseek(fptr_image, 18, SEEK_SET);

    // Read the width (an int)
    fread(&width, sizeof(int), 1, fptr_image);
    //printf("width = %u\n", width);

    // Read the height (an int)
    fread(&height, sizeof(int), 1, fptr_image);
    //printf("height = %u\n", height);

    // Return image capacity
    rewind(fptr_image);
    return width * height * 3;
}

/* 
 * Get File pointers for i/p and o/p files
 * Inputs: Src Image file, Secret file and
 * Stego Image file
 * Output: FILE pointer for above files
 * Return Value: success or failure, on file errors
 */
Status open_files(EncodeInfo *encInfo)
{
    //Open source image file
    encInfo->src_image_fptr = fopen(encInfo->src_image_fname, "r");
    printf("Opened %s\n",encInfo->src_image_fname);

    //Check source image open failure
    if (encInfo->src_image_fptr == NULL)
    {
    	perror("fopen");
    	fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->src_image_fname);

    	return failure;
    }
    
    //Open secret file
    encInfo->secret_fptr = fopen(encInfo->secret_fname, "r");
    printf("Opened %s\n",encInfo->secret_fname);

    if (encInfo->secret_fptr == NULL)
    {
    	perror("fopen");
    	fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->secret_fname);

    	return failure;
    }

    //Open output image file
    encInfo->output_image_fptr = fopen(encInfo->output_image_fname, "w");
    printf("Opened %s\n",encInfo->output_image_fname);

    if (encInfo->output_image_fptr == NULL)
    {
    	perror("fopen");
    	fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->output_image_fname);

    	return failure;
    }
    printf("Done\n");
    return success;
}
Opr_type check_operation(char *option)                              //To check the operation argument is encode/decode type or not
{
    if(!strcmp(option,"-e"))           
        return encode;                                            //Encoding operation
    else if(!strcmp(option,"-d"))      
        return decode;                                  //Decoding operation
    else
        return unsupported;                             //Invalid option
}
//Main encoding controller function
Status do_encoding(char * argv[] ,EncodeInfo*encInfo)
{
    //Validate encoding arguments
    if(validate_encode_args(argv,encInfo)== failure)
        return failure;

    //Copy BMP header to output image
    printf("## Encoding procedure Started ##\n");
    printf("Copying Image Header\n");

    if(copy_bmp_header(encInfo) == failure)
        return failure;

    //Encode magic string to use while decoding
    printf("Encoding Magic String Signature\n");

    if(encode_magic_string(MAGIC_STRING,encInfo) == failure)
        return failure;

    //Encode secret file extension to use while decode
    printf("Encoding secret file extension\n");

    if(encode_secret_file_extn(encInfo) == failure)
        return failure;

    //Encode secret file data to hide in output.bmp
    if(encode_secret_file_data(encInfo) == failure)
        return failure;
    //Copy remaining image bytes unchanged
    printf("Copying Left Over Data\n");

    if(copy_remaining_img_data(encInfo) == failure)
        return failure;
    return success;
}
Status validate_encode_args(char * argv[],EncodeInfo * encInfo)
{
    //Validate source image file extension
    if(argv[2])
    {
        char * res = strstr(argv[2],".bmp");                        //Check for .bmp extension
        if((res == NULL) || (strcmp(res,".bmp") != 0))              //If not .bmp
            return failure;
        else 
        {
            encInfo->src_image_fname=argv[2];               //Store source image filename
            printf("Source file is .bmp\n");                //Confirm valid .bmp file
        }
    }
    //Validate secret file and extract extension
    if(argv[3])                                     //Check for secret file argument
    {
        char * res = strstr(argv[3],".");                     //Find last occurrence of '.' to get extension
        if((res == NULL) ||( strlen(res)==1))           //If no extension found
            return failure;
        else
        {
            encInfo->secret_fname=argv[3];          //Store secret filename
            strcpy(encInfo->secret_extn,res);       //Store extension in struct member
            encInfo->secret_extn_size=strlen(res);  //Store extension size
        }
    }
    //Set default output filename if not provided
    if(argv[4] == NULL)
    {
        encInfo->output_image_fname="output.bmp";       //Default output image filename
        printf("Output file not mentioned. Creating output.bmp as default\n");
    }
    else
    {
       //Validate output image extension
        char * res = strstr(argv[4],".bmp");            //Check for .bmp extension
        if((res == NULL) || (strcmp(res,".bmp")!=0))      //If not .bmp
            return failure;
        else  
        {  
            encInfo->output_image_fname=argv[4];        //Store output image filename
        }
    }
    printf("Opening required files\n");
    if(open_files(encInfo)==failure)            //Open all required files
        return failure;

    //Check if image has enough capacity    
    if(check_capacity(encInfo)==failure)
        return failure;
    return success; 
}

//Get size of a file in bytes
unsigned int get_file_size(FILE * fptr)
{
    printf("Checking secret file size\n");
    fseek(fptr,0,SEEK_END);    //Move to end of file
    if(ftell(fptr)==0)        //Checking if secret file is empty
    {
        printf("Empty\n");
        return 0;
    }
    else    
        printf("Done. Not empty\n");
    long int x =ftell(fptr);   //Get file size
    rewind(fptr);              //Reset file pointer
    return x;
}

//Check if image has enough space to store secret data
Status check_capacity(EncodeInfo*encInfo)
{
    unsigned long int image_capacity=get_image_size_for_bmp(encInfo->src_image_fptr);       //Get image size
    printf("Source image size=%lu\n",image_capacity);                               //Print image size
    encInfo -> secret_file_size = get_file_size(encInfo->secret_fptr);              //Get secret file size
    unsigned int x=encInfo->secret_file_size;                     //Store secret file size  
    //Calculate required bits for encoding  
    unsigned long int encoding_things=(4+strlen(MAGIC_STRING)+4+strlen(encInfo->secret_extn)+4+x)*8;
    printf("Checking source image capacity for encoding\n");

    if(image_capacity<encoding_things)          //  Check if image capacity is less than required bits
        return failure;
    printf("Done. Found Ok\n");
    return success;
}
//Copy BMP header from source image to output image
Status copy_bmp_header(EncodeInfo *encInfo)
{
    char header[54];
    fread(header,1,54,encInfo->src_image_fptr);
    fwrite(header,1,54,encInfo->output_image_fptr);
    printf("Done\n");
    return success;
}
//Encode magic string into output image
Status encode_magic_string(const char *magic_string, EncodeInfo *encInfo)
{
    /*Encode the length of the MAGIC_STRING*/
    char bufferlen[32];
    fread(bufferlen,1,32,encInfo->src_image_fptr);
    encode_4byte_to_lsb(strlen(magic_string),bufferlen);
    fwrite(bufferlen,1,32,encInfo->output_image_fptr);
    /*Encode the MAGIC_STRING characters*/
    char bufferstr[8];
    for(int i=0;i<strlen(magic_string);i++)
    {
        fread(bufferstr,1,8,encInfo->src_image_fptr);
        encode_1byte_to_lsb(magic_string[i],bufferstr);
        fwrite(bufferstr,1,8,encInfo->output_image_fptr);
    }
    printf("Done\n");
    return success;
}

Status encode_secret_file_extn(EncodeInfo *encInfo)         //Encode secret file extension into output image
{
    /*Encode the length of the secret file extension*/
    char bufferlen[32];
    fread(bufferlen,1,32,encInfo->src_image_fptr);
    encode_4byte_to_lsb(encInfo->secret_extn_size,bufferlen);
    fwrite(bufferlen,1,32,encInfo->output_image_fptr);
    
    /*Encode the secret file extension characters*/
    char bufferstr[8];
    for(int i=0;i<encInfo->secret_extn_size;i++)        //Loop through each character of extension
    {
        fread(bufferstr,1,8,encInfo->src_image_fptr);       //Read 8 bytes from source image
        encode_1byte_to_lsb(encInfo->secret_extn[i],bufferstr);     //Encode one character into LSBs
        fwrite(bufferstr,1,8,encInfo->output_image_fptr);           //Write encoded bytes to output image
    }
    printf("Done\n");
    return success;
}

Status encode_secret_file_data(EncodeInfo *encInfo)         //Encode secret file data into output image
{
    /*Encode the size of the secret file data */
    char bufferlen[32];
    printf("Encoding secret.txt File size\n");
    fread(bufferlen,1,32,encInfo->src_image_fptr);
    encode_4byte_to_lsb(encInfo->secret_file_size,bufferlen);       //Encode secret file size into LSBs
    fwrite(bufferlen,1,32,encInfo->output_image_fptr);              //Write encoded size to output image
    printf("Done\n");

    /*Encode the secret file data byte by byte*/
    char image_buf[8];
    char ch;
    printf("Encoding secret.txt File Data\n");

    for(int i=0;i<encInfo->secret_file_size;i++)        //Loop through each byte of secret data
    {
        fread(&ch,1,1,encInfo->secret_fptr);
        fread(image_buf,1,8,encInfo->src_image_fptr);
        encode_1byte_to_lsb(ch,image_buf);
        fwrite(image_buf,1,8,encInfo->output_image_fptr);
    }
    printf("Done\n");
    return success;
}
/*copy remaining image bytes after encoding*/
Status copy_remaining_img_data(EncodeInfo * encInfo)
{
    char ch;
    while(fread(&ch, 1, 1,encInfo->src_image_fptr)==1)
        fwrite(&ch, 1, 1, encInfo->output_image_fptr);
    printf("Done\n");
    return success;
}
/*Encode one character into 8 bytes using LSB technique*/
Status encode_1byte_to_lsb(char data, char *buffer_8)
{
    for(int i=7;i>=0;i--)
    {
        buffer_8[7-i]= (buffer_8[7-i]&(~1)) | ((data & (1<<i)) >> i);
    }
    return success;
}
/*Encode 4-byte integer into 32 bytes using LSB technique*/
Status encode_4byte_to_lsb(int data, char *buffer_32)
{
    for(int i=31;i>=0;i--)
    {
        buffer_32[31-i]=(buffer_32[31-i]&(~1)) | ((data & (1<<i)) >> i);
    }
    return success;
}