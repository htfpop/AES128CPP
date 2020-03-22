/********************************************************************
 *  Programmer : Christopher K. Leung (012586444)                   *
 *  Course ID  : CS 4600 - Cryptography and Information Security    *
 *  Due Date   : March 22, 2020                                     *
 *  Project    : AES128-ECB Implementation                          *
 *  Purpose    : This project is an implementation of the Advanced  *
 *               Encryption Standard (AES) using a 128 bit key. The *
 *               Size of each encryption block is also 128 bits     *
 ********************************************************************/


#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "AESEncrypt128.h"

//B2F6CFD21D00AFF9169A1DB80Dd84004
//BEEF4DADBEEF4DADBEEF4DADBEEF4DAD

void pkcs5(t_uint8 dataBlock[], int buffByte);
bool isHex(char character);
bool checkKey(std::string *user);
std::string clearWhiteSpace(std::string *userString);
void initAESByteArray(t_uint8 *keyArr, std::string *userString);
void gBox(t_uint8 *gbox, t_uint8 *keyptr, unsigned int rc);
void xorFunction(t_uint8 *arr1, t_uint8 *arr2, t_uint8 *currentBytePtr);
t_uint8 *genKeySchedule(t_uint8 *key_ptr);
void encryptBlock(unsigned char *dataBlockInput, unsigned char *keys);
void keyAddition(t_uint8 *dataBlock, t_uint8 *currentKey);
int getShiftRowIndex(unsigned int index);
void mixColumns(unsigned char *input);

int main(int argc, char *argv[]) {
    t_uint8 dataBuffer[BUFFSIZE];                                       /* Input buffer from file */
    t_uint8 aesKey[16] = {0};                                           /* Holds key from user byte value */
    t_uint8 *aesKey_Ptr = aesKey;                                      /* Pointer to aes key array */
    std::string userInputKey = "";                                      /* User input string used for parser */
    bool isValidKey = false;                                            /* Used to check valid key */
    char userChoice = '0';

    std::cout << "Hello world" << std::endl;

    if (argc <= 1) {                                                    /* If number of arguments less than req. */
        printf("No file path specified, exiting program");
        exit(-1);                                                /* Exit with status code -1 */
    }

    const char *source = argv[1];                                       /* Take in argv[1] for file*/
    FILE *src = fopen(source, "rb");                               /* Try to open and read binaries of file */
    if (src == NULL)                                                     /* If source cannot be opened then close */
    {
        perror("Cannot open file, Closing Program");
        exit(-1);                                                /* Exit with status code -1 */
    }

    do {
        std::cout << "Please enter your key:";                          /* Prompt user for key */
        getline(std::cin, userInputKey);                        /* Get entire line from user */

        userInputKey = clearWhiteSpace(&userInputKey);                  /* Function to remove white spaces */

        isValidKey = checkKey(&userInputKey);                           /* Check to see if key has all hex */

        if (!isValidKey) {                                                /* if key is incorrect ask user for another */
            std::cout << "\nKey contains error" << std::endl;
            std::cout << "Would you like to enter a new key (y/n)? : ";
            std::cin >> userChoice;
            std::cin.ignore();
        }
    } while (!isValidKey && (userChoice == 'y' || userChoice == 'Y'));     /* do-while user wants to input new keys */
    if (!isValidKey) {                                                    /* if still invalid key exit program */
        std::cout << "Exiting program, cannot use key specified by user" << std::endl;
        exit(0);
    }


    initAESByteArray(aesKey_Ptr, &userInputKey);                        /* Initialize byte array with hex string */
    t_uint8 *keys = genKeySchedule(aesKey_Ptr);

    memset(dataBuffer, 0, sizeof(dataBuffer));                          /* Wipe out garbage data in data buffer */

    fseek(src, 0, SEEK_END);                                             /* fseek() to count # bytes in file */
    int fileSize = ftell(src);                                          /* Determine file size*/
    rewind(src);                                                        /* Reset file pointer*/
    bool extraPadBlock = fileSize % 16 == 0;                              /* Determine if file is multiple of 16 bytes*/

    printf("Filesize is %d bytes\n", fileSize);                          /* Printout for file size*/
    int readFromBuffer = 0;                                             /* Counter for data buffer*/

    std::string mystring = argv[1];
    int pos = mystring.find(".");
    mystring = mystring.substr(0, pos);
    mystring += ".enc";

    FILE *dstfile = fopen(mystring.c_str(), "wb");
    while (!feof(src))                                                   /* While file not end of file*/
    {
        readFromBuffer = fread(dataBuffer, sizeof(t_uint8), BUFFSIZE, src); /* Read 16 bytes to buffer */
        if (readFromBuffer <= BUFFSIZE)                                  /* If bytes read less than buffer size, pad */
            pkcs5(dataBuffer, readFromBuffer);                          /* perform pkcs5 on data buffer to pad */

        encryptBlock(dataBuffer, keys);

        fwrite(dataBuffer, sizeof(char), BUFFSIZE, dstfile);               /* Write out encrypted to file */
    }
    fclose(src);
    fclose(dstfile);
    return 0;
}

void initAESByteArray(t_uint8 *keyArr, std::string *userString) {
    std::string copiedString = *userString;                             /* Copy string */
    int byteArrIndex = 0;                                               /* initialize byte array index to 0*/
    std::string byteString = "";                                        /* Initial byte string is empty*/
    int starting = 0;                                                   /* Starting index to a length*/
    for (int i = 0; i < copiedString.length(); i += 2) {
        starting = i;                                                   /* Starting index to keep track of chars*/
        byteString = copiedString.substr(starting, 2);               /* copy 2 chars into byte string*/
        keyArr[byteArrIndex++] = stoi(byteString, nullptr, 16); /* convert string to int and store in array*/
        byteString.clear();
    }
}

bool checkKey(std::string *user) {
    bool chkSuccess = false;                                             /* Assign bool return value to false */
    std::string copiedString = *user;                                    /* Create a copied string from user */
    int strLength = copiedString.length();                               /* Used for finding string length */
    if (strLength != 32)
        return chkSuccess;                               /* if str is less than 32 chars, return false*/
    for (int index = 0; index < strLength; index++)                       /* Parse entire string for hex chars*/
    {
        if (isHex(copiedString[index]))                                   /* If hex char found then continue */
            continue;
        else return false;                                               /* Else return false bool flag*/
    }
    return true;                                                         /* If nothing found wrong return true */
}

std::string clearWhiteSpace(std::string *userString) {                    /* This Function strips white space */
    std::string copiedString = *userString;                              /* Copy local string var inside function */
    std::string newString = "";                                          /* Init. new empty string */
    for (int strIndex = 0; strIndex < copiedString.length(); strIndex++)  /* Begin parsing */
    {
        if (copiedString[strIndex] == ' ' || copiedString[strIndex] == '\0') /* If found space or null continue */
            continue;
        else {
            newString += toupper(copiedString[strIndex]);                  /* Else copy char as upper case */
        }
    }
    return newString;                                                     /* Return new string */
}

bool isHex(char character) {                                               /* This function determines hex chars*/
    bool checkHex = (character >= 'a' && character <= 'f') ||              /* Return boolean if a hex char */
                    (character >= 'A' && character <= 'F') ||
                    (character >= '0' && character <= '9');
    return checkHex;                                                      /* Return boolean */
}

void pkcs5(t_uint8 dataBlock[], int numBytes) {                           /* This function pads block of plaintext */
    int i = numBytes;                                                     /* assign i to number of bytes read */
    t_uint8 difference = BUFFSIZE - numBytes;                             /* Take difference from buffersize */
    for (i; i < BUFFSIZE; i++) {                                            /* For loop to pad the end of data block */
        dataBlock[i] = difference;
    }
}


/**********************************
 * For data packaging later on    *
 * ********************************/

t_uint8 *genKeySchedule(t_uint8 *key_ptr)                                 /* This Function generates the AES keys*/
{
    static t_uint8 keyArr_bytes[176] = {0};                               /* Init 176 byte unsigned char array */
    t_uint8 *currentBytePtr = keyArr_bytes;                               /* Pointer to reference the array */
    t_uint8 *key_ptr_ptr = key_ptr;                                          /* Used for referencing the key passed in */
    for (int i = 0; i < 16; i++) {                                          /* Copy over first 4 words of key */
        *currentBytePtr++ = *key_ptr_ptr++;                                  /* Copy over key to words 0 - word 3 */
    }

    t_uint8 *w1 = keyArr_bytes;                                              /* Word 1 pointer */
    t_uint8 *w2 = w1 + 4;                                                 /* Word 2 pointer (add 4 bytes to word 1) */
    t_uint8 *w3 = w2 + 4;                                                 /* Word 3 pointer (add 4 bytes to word 2) */
    t_uint8 *w4 = w3 + 4;                                                 /* Word 4 pointer (add 4 bytes to word 3) */

    for (int i = 1; i < 11; i++)                                          /* For loop to iterate over key generation */
    {
        t_uint8 gBoxReturn[4] = {0};                                      /* Holds 4 bytes from gBox output */
        gBox(&gBoxReturn[0], w4,
             i);                                        /* Calculate gBox using word 4 and current round */
        xorFunction(&gBoxReturn[0], w1,
                    currentBytePtr);                  /* gbox ^ first word of current key then write to key arr */
        currentBytePtr += 4;                                              /* Increment the byte pointer by 4 bytes to reference next word */
        w1 += 16;                                                         /* Increment word by 16 bytes to refrence new word */
        xorFunction(w1, w2,
                    currentBytePtr);                              /* First of key ^ second word of key, then write to key arr */
        (currentBytePtr += 4);                                            /* Increment byte pointer by 4 to refrence next word */
        w2 += 16;                                                          /* Increment second word of key by 16 bytes */
        xorFunction(w2, w3,
                    currentBytePtr);                                /* Second word of key ^ third word of key then write to key arr */
        (currentBytePtr += 4);                                            /* Increment byte pointer by 4 bytes */
        w3 += 16;                                                           /* Increment 3rd word pointer by 16 bytes */
        xorFunction(w3, w4,
                    currentBytePtr);                                /* Third word of key ^ fourth word of key then write to key arr */
        (currentBytePtr += 4);                                            /* Increment byte pointer by 4 bytes */
        w4 += 16;                                                           /* Increment 4th word by 16 bytes */
    }
    return &keyArr_bytes[0];                                              /* Return all the keys back to caller */
}

void gBox(t_uint8 *gbox, t_uint8 *keyptr, unsigned int roundKey)          /* This function calculates the gbox for AES*/
{
    gbox[0] = *keyptr;                                                    /* First gBox Index = first byte of word 4 in key */
    gbox[1] = *(keyptr +
                1);                                              /* Second gBox Index = second byte of word 4 in key */
    gbox[2] = *(keyptr +
                2);                                              /* Third gBox Index = Third byte of word 4 in key */
    gbox[3] = *(keyptr +
                3);                                              /* Forth gbox Index = forth byte in word 4 in key */
    t_uint8 temp = gbox[0];                                               /* Temp unsigned char variable to hold first gbox index */

    gbox[0] = gbox[1];                                                    /* Left cyclic byte shift */
    gbox[1] = gbox[2];                                                    /* Left cyclic byte shift */
    gbox[2] = gbox[3];                                                    /* Left cyclic byte shift */
    gbox[3] = temp;                                                       /* Index 4 = first byte in original gbox */

    for (int i = 0; i < 4; i++) {                                           /* For loop to do byte substituion */
        gbox[i] = getSBox(gbox[i]);                                       /* Used loopup table */
    }                                                                     /**/

    gbox[0] ^= rcon[roundKey];                                            /* XOR byte in index 0 with round constant */
}

void xorFunction(t_uint8 *arr1, t_uint8 *arr2,
                 t_uint8 *currentBytePtr)   /* This function calculates XOR of 2 pointers then stores */
{
    t_uint8 *arrPtr1 = arr1;                                              /* Temp pointer to array 1 */
    t_uint8 *arrPtr2 = arr2;                                              /* Temp pointer to array 2 */
    for (int i = 0; i < 4; i++) {                                           /* for loop to xor every individual byte */
        *currentBytePtr = (*arrPtr1++) ^
                          (*arrPtr2++);                    /* Need to derefrence pointer first then perform xor operation */
        currentBytePtr++;                                                 /* Increment pointer to key array */
    }
}

void keyAddition(t_uint8 *dataBlock, t_uint8 *currentKey) {
    t_uint8 *currentQuadWordPtr = dataBlock;
    for (int i = 0; i < 16; i++) {
        *currentQuadWordPtr++ = (*currentQuadWordPtr) ^ (*currentKey++);
    }
}

void encryptBlock(unsigned char *dataBlockInput, unsigned char *keyArr) {
    //t_uint8* dataBlockHead = dataBlockInput;
    t_uint8 tempArray[16] = {0};
    t_uint8 *currentQuadWordPtr = dataBlockInput;                          /* assign ptr to beginning of data block */
    t_uint8 *bytePtr = nullptr;                                                      /* Byte ptr to iterate over all pointers */

    keyAddition(currentQuadWordPtr, keyArr);                                /* conduct key addition w/ first element of data block
 *                                                                            This will increment key index by every byte but not
 *                                                                             the current pointer to the quad word*/

    for (int round = 1; round < 10; round++) {                              /* rounds 1 - 9 */
        bytePtr = currentQuadWordPtr;                                       /* Re-assign byte ptr to current word ptr */
        keyArr += 16;

        for (int byte = 0; byte < 16; byte++) {                             /* Byte substitution on every byte */
            *bytePtr++ = getSBox(
                    *bytePtr);                                 /* Increment byte ptr by 1 every time byte is substituted */
        }

        bytePtr = currentQuadWordPtr;                                       /* re-assign byteptr to head of quad word */
        memcpy(&tempArray, currentQuadWordPtr, 16);

        for (int SRIndex = 0; SRIndex < 16; SRIndex++)                       /* Shift rows performed on every byte */
        {
            *bytePtr++ = tempArray[getShiftRowIndex(
                    SRIndex)];              /* go to lookup table for shift rows, ref. original temp array */
        }                                                                   /* Then increment byteptr */
        mixColumns(dataBlockInput);                                         /* Pass in entire data block to be mixed */

        keyAddition(currentQuadWordPtr,
                    keyArr);                             /* key addition doesnt increment quad ptr */
    }

    /* ROUND 10 ONLY */
    bytePtr = currentQuadWordPtr;                                           /* Re-assign byte ptr to quad word ptr for byte sub */
    keyArr += 16;

    for (int byte = 0;
         byte < 16; byte++) {                                 /* perform byte sub and increment byte ptr */
        *bytePtr++ = getSBox(*bytePtr);
    }

    bytePtr = currentQuadWordPtr;                                           /* used for shift rows operation */
    memcpy(&tempArray, currentQuadWordPtr, 16);

    for (int SRIndex = 0; SRIndex < 16; SRIndex++)                           /* perform shift row operation */
    {
        *bytePtr++ = tempArray[getShiftRowIndex(SRIndex)];
    }
    keyAddition(currentQuadWordPtr, keyArr);                                 /* perform key addition with last block */
}

int getShiftRowIndex(unsigned int index) {
    int lookup[] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
    return lookup[index];
}


void mixColumns(unsigned char *input) {
    unsigned char tmp[16];
    int i;
    for (i = 0; i < 4; ++i) {
        tmp[(i << 2) + 0] = (unsigned char) (mul2[input[(i << 2) + 0]] ^ mul_3[input[(i << 2) + 1]] ^
                                             input[(i << 2) + 2] ^ input[(i << 2) + 3]);
        tmp[(i << 2) + 1] = (unsigned char) (input[(i << 2) + 0] ^ mul2[input[(i << 2) + 1]] ^
                                             mul_3[input[(i << 2) + 2]] ^ input[(i << 2) + 3]);
        tmp[(i << 2) + 2] = (unsigned char) (input[(i << 2) + 0] ^ input[(i << 2) + 1] ^ mul2[input[(i << 2) + 2]] ^
                                             mul_3[input[(i << 2) + 3]]);
        tmp[(i << 2) + 3] = (unsigned char) (mul_3[input[(i << 2) + 0]] ^ input[(i << 2) + 1] ^ input[(i << 2) + 2] ^
                                             mul2[input[(i << 2) + 3]]);
    }

    for (i = 0; i < 16; ++i)
        input[i] = tmp[i];
}