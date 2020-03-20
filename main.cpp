/******************************************************
 *  Christopher K. Leung (012586444)                  *
 *  CS 4600 - Cryptography and Information Security   *
 *  Due - March 22, 2020                              *
 *  AES128-ECB Implementation                         *
 ******************************************************/

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "AESEncrypt128.h"

using namespace std;
//B2 F6 CF D2 1D 00 AF F9 16 9A 1D B8 0D d8 40 04
//B2F6CFD21D00AFF9169A1DB80Dd84004
//BEEF4DADBEEF4DADBEEF4DADBEEF4DAD

void pkcs5(t_uint8 dataBlock[], int buffByte);
bool isHex(char character);
bool checkKey(string* user);
string clearWhiteSpace(string* userString);
void initAESByteArray(t_uint8 * keyArr, string* userString);
void gBox(t_uint8* gbox, t_uint8* keyptr, unsigned int rc);
void xorFunction(t_uint8* arr1, t_uint8* arr2, t_uint8* currentBytePtr);
/**************************
 * for packaging later on *
 **************************/
t_uint8* genKeySchedule(t_uint8* key_ptr);
/**************************
 * for packaging later on *
 **************************/

int main(int argc, char *argv[]) {
    t_uint8 dataBuffer[BUFFSIZE];                                       /* Input buffer from file */
    t_uint8 aesKey[16] = {0};                                           /* Holds key from user byte value */
    t_uint8 * aesKey_Ptr = aesKey;                                      /* Pointer to aes key array */
    string userInputKey = "";                                           /* User input string used for parser */
    bool isValidKey = false;                                            /* Used to check valid key */
    char userChoice = '0';
#if 0
    t_uint8 testing[4] = {0xBE, 0xEF, 0x4D, 0xAD};
    t_uint8* testPtr = testing;
    gBox(testPtr, 1);

#endif
    cout << "Hello world" << endl;

    if (argc <= 1) {                                                    /* If number of arguments less than req. */
        printf("No file path specified, exiting program");
        exit(-1);                                                /* Exit with status code -1 */
    }

    const char *source = argv[1];                                       /* Take in argv[1] for file*/
    FILE* src = fopen(source,"rb");                               /* Try to open and read binaries of file */
    if(src == NULL)                                                     /* If source cannot be opened then close */
    {
        perror("Cannot open file, Closing Program");
        exit(-1);                                                /* Exit with status code -1 */
    }

    do {
        cout << "Please enter your key:";                               /* Prompt user for key */
        getline(cin, userInputKey);                             /* Get entire line from user */

        userInputKey = clearWhiteSpace(&userInputKey);                  /* Function to remove white spaces */

        isValidKey = checkKey(&userInputKey);                           /* Check to see if key has all hex */

        if(!isValidKey){                                                /* if key is incorrect ask user for another */
            cout << "\nKey contains error" << endl;
            cout << "Would you like to enter a new key (y/n)? : ";
            cin >> userChoice;
            cin.ignore();
        }
    }while(!isValidKey && (userChoice == 'y'|| userChoice == 'Y'));     /* do-while user wants to input new keys */
    if(!isValidKey){                                                    /* if still invalid key exit program */
        cout << "Exiting program, cannot use key specified by user" << endl;
        exit(0);
    }


    initAESByteArray(aesKey_Ptr, &userInputKey);                        /* Initialize byte array with hex string */
    genKeySchedule(aesKey_Ptr);

    memset(dataBuffer, 0, sizeof(dataBuffer));                          /* Wipe out garbage data in data buffer */

    fseek(src,0, SEEK_END);                                             /* fseek() to count # bytes in file */
    int fileSize = ftell(src);                                          /* Determine file size*/
    rewind(src);                                                        /* Reset file pointer*/
    bool extraPadBlock = fileSize%16 == 0;                              /* Determine if file is multiple of 16 bytes*/

    printf("Filesize is %d bytes\n",fileSize);                          /* Printout for file size*/
    int readFromBuffer = 0;                                             /* Counter for data buffer*/

    while(!feof(src))                                                   /* While file not end of file*/
    {
        readFromBuffer = fread(dataBuffer, sizeof(t_uint8), BUFFSIZE, src); /* Read 16 bytes to buffer */
        if(readFromBuffer <= BUFFSIZE)                                  /* If bytes read less than buffer size, pad */
            pkcs5(dataBuffer, readFromBuffer);                          /* perform pkcs5 on data buffer to pad */

        encryptBlock(dataBuffer);

        //fwrite(dataBuffer, sizeof(char), BUFFSIZE, dst)               /* Write out encrypted to file */
    }
    fclose(src);
    return 0;
}

void initAESByteArray(t_uint8 * keyArr, string* userString)
{
    string copiedString = *userString;
    int byteArrIndex = 0;
    string byteString = "";
    int starting = 0;
    for(int i = 0; i < copiedString.length(); i+=2)
    {
        starting = i;
        byteString = copiedString.substr(starting, 2);
        keyArr[byteArrIndex++] = stoi(byteString, nullptr, 16);
        byteString.clear();
    }
}

bool checkKey(string* user){
    bool chkSuccess = false;
    string copiedString = *user;
    int strLength = copiedString.length();
    if(strLength != 32) return chkSuccess;
    for(int index = 0; index < strLength; index++)
    {
        if(isHex(copiedString[index]))
            continue;
        else return false;
    }
    return true;
}

string clearWhiteSpace(string* userString){
    string copiedString = *userString;
    string newString = "";
    for(int strIndex = 0; strIndex < copiedString.length(); strIndex++)
    {
        if(copiedString[strIndex] == ' ' || copiedString[strIndex] == '\0')
            continue;
        else{
            newString += toupper(copiedString[strIndex]);
        }
    }
    return newString;
}

bool isHex(char character){
    bool checkHex = (character >= 'a' && character <= 'f')||
            (character >= 'A' && character <= 'F')||
            (character >= '0' && character <= '9');
    return checkHex;
}

void pkcs5(t_uint8 dataBlock[], int numBytes) {
    int i = numBytes;
    t_uint8 difference = BUFFSIZE - numBytes;
    for(i; i < BUFFSIZE; i++){
        dataBlock[i] = difference;
    }
}


/**********************************
 * For data packaging later on    *
 * ********************************/

t_uint8* genKeySchedule(t_uint8* key_ptr)
{

    t_uint8 keyArr_bytes[176] = {0};
    t_uint8* currentBytePtr = keyArr_bytes;
    t_uint8* key_ptr_ptr = key_ptr;
    for(int i = 0; i < 16; i++){                     /* copy over first 4 words of key */
        *currentBytePtr++ = *key_ptr_ptr++;
    }

    t_uint8* w1 = keyArr_bytes;
    t_uint8* w2 = w1 + 4;
    t_uint8* w3 = w2 + 4;
    t_uint8* w4 = w3 + 4;

    for(int i = 1; i < 11; i ++)
    {
        t_uint8 gBoxReturn[4] = {0};
        gBox(&gBoxReturn[0],w4,i);
        xorFunction(&gBoxReturn[0], w1, currentBytePtr);
        currentBytePtr += 4;
        w1 += 16;
        xorFunction(w1, w2, currentBytePtr);
        (currentBytePtr += 4);
        w2+= 16;
        xorFunction(w2,w3,currentBytePtr);
        (currentBytePtr += 4);
        w3+=16;
        xorFunction(w3,w4,currentBytePtr);
        (currentBytePtr += 4);
        w4+=16;

    }
    return &keyArr_bytes[0];

}

void gBox(t_uint8* gbox, t_uint8* keyptr, unsigned int roundKey)
{
    gbox[0] = *keyptr;
    gbox[1] = *(keyptr + 1);
    gbox[2] = *(keyptr + 2);
    gbox[3] = *(keyptr + 3);
    t_uint8 temp = gbox[0];

    gbox[0] = gbox[1];
    gbox[1] = gbox[2];
    gbox[2] = gbox[3];
    gbox[3] = temp;

    for(int i = 0; i < 4; i++)
    {
        gbox[i] = getSBox(gbox[i]);
    }

    gbox[0] ^= rcon[roundKey];

//    t_uint8* current = keyptr;
//    t_uint8* next = keyptr + sizeof(unsigned char);
//    t_uint8 temp = *keyptr;
//
//    for(int i = 0; i < 3; i++)
//    {
//        *current = *next;
//        next++;
//        current++;
//    }
//    *current = temp;
//
//    current -= 3*sizeof(unsigned char);
//
//    for(int i = 0; i < 4;i++)
//    {
//        *current = getSBox(*current);
//        current++;
//    }
//
//    current -= 4*sizeof(unsigned char);
//    *current ^= rcon[roundKey+1];
}

void xorFunction(t_uint8* arr1, t_uint8* arr2, t_uint8* currentBytePtr)
{
    t_uint8* arrPtr1 = arr1;
    t_uint8* arrPtr2 = arr2;
    for(int i = 0; i < 4; i++){
        *currentBytePtr = (*arrPtr1++) ^ (*arrPtr2++);
        currentBytePtr++;
    }
}
