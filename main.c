/*  
Name: Aishwarya Gaddam
Date: 23-01-2026
Description: LSB-based image steganography to securely hide and extract secret data within a BMP image without visible distortion.
Main function to handle encoding and decoding operations
*/

#include <stdio.h>
#include "encode.h"
#include "decode.h"

int main(int argc, char *argv[])        
{
    EncodeInfo encodeInfo;              // Structure to hold encoding information
    DecodeInfo decInfo;                 // Structure to hold decoding information
    if( argc == 1 )                     // No arguments provided
    {
        printf("Encoding: ./lsb_steg -e <.bmp file> <.txt file> [output file]\n");              // Usage message for encoding
        printf("Decoding: ./lsb_steg -d <.bmp file> [output file]\n");                // Usage message for decoding
	    return 0;
    }

    int opr = check_operation(argv[1]);                     // Determine operation type (encode/decode)

    if( opr == encode )                                      // Encoding operation
    {
        if(argc < 4 || argc > 5)                            // Validate argument count for encoding
        {
            printf("Encoding: ./lsb_steg -e <.bmp file> <.txt file> [output file]\n");          // Usage message for encoding
            printf("Decoding: ./lsb_steg -d <.bmp file> [output file]\n");
            return 0;
        }
        if (do_encoding(argv,&encodeInfo) == failure)       // Perform encoding and check for failure
        {
            printf("read and validate failed\n");
            return 0;
        }
        else
            printf("## Encoding Done Successfully ##\n");       // Success message for encoding
    }   
    else if( opr == decode )                                    // Decoding operation
    {
        if(argc < 3  || argc > 4)                           // Validate argument count for decoding
        {
            printf("Encoding: ./lsb_steg -e <.bmp file> <.txt file> [output file]\n");
            printf("Decoding: ./lsb_steg -d <.bmp file> [output file]\n");          // Usage message for decoding
            return 0;
        }
        if(do_decoding(argv,&decInfo) == failure)       // Perform decoding and check for failure   
        {
            printf("Decoding FAILED\n");                // Failure message for decoding
            return 0;   
        }
        else
            printf("## Decoding Done Successfully ##\n");           // Success message for decoding
    }
    else
    {
        printf("Invalid option.\n");                        // Error message for invalid option
        printf("Please pass either -e for encoding or -d for decoding.\n");         // Print -> Error + usage msg
    }
    return 0;
}