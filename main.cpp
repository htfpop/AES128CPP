#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>
#include <string.h>
#include "AESEncrypt128.h"

void pkcs5(unsigned char dataBlock[], int buffByte);


void keyInput(unsigned char myactualyKey[], unsigned char userString[], int userStringSize);

using namespace std;

int main(int argc, char *argv[]) {
    stringstream iss;
    unsigned char dataBuffer[BUFFSIZE]; // input buffer
    unsigned char myKeyStr[] = {"B2 F6 CF D2 1D 00 AF F9 16 9A 1D B8 0D d8 40 04"};
    string hexkey = "B2 F6 CF D2 1D 00 AF F9 16 9A 1D B8 0D d8 40 04";
    iss << hex << hexkey;
    unsigned char myActualKey[16] = {0};
    unsigned char test1 = 0;
    for(int i = 0; i < sizeof(myKeyStr); i++)
    {
        test1 = (unsigned char) strtoul(hexkey, NULL, 16);
        myActualKey[i] = test1;
    }

//    int c = 0;
//    int index = 0;
//    while(iss >> hex >> c)
//    {
//        myActualKey[index] = c;
//        index++;
//    }
    cout << "Hello world" << endl;

    if (argc <= 1) {
        printf("No file path specified, exiting program");
        exit(0);
    }

    const char *source = argv[1];   //input source file
    FILE* src = fopen(source,"rb");
    if(src == NULL)
    {
        perror("Cannot open file, Closing Program");
        exit(-1);
    }

    unsigned char userString[50] = {0};
    cout << "Please enter your key:";
    cin.getline((char*)userString,sizeof(userString));

    keyInput(myActualKey, userString, sizeof(userString));
    for(int i = 0; i < sizeof(myActualKey); i++)
        printf("%X ", myActualKey[i]);

    memset(dataBuffer, 0, sizeof(dataBuffer)); //initialize buffer with 0

    fseek(src,0, SEEK_END);
    int fileSize = ftell(src);
    rewind(src);
    bool extraPadBlock = fileSize%16 == 0;

    printf("Filesize is %d bytes\n",fileSize);
    int readFromBuffer = 0;

    while(!feof(src))
    {
        readFromBuffer = fread(dataBuffer, sizeof(unsigned char), BUFFSIZE, src);
        if(readFromBuffer <= BUFFSIZE)
            pkcs5(dataBuffer, readFromBuffer);

        encryptBlock(dataBuffer);
    }

    for(int i = 0; i < sizeof(dataBuffer); i++)
        printf("%X ",dataBuffer[i]);
    fclose(src);

    return 0;
}

void keyInput(unsigned char myactualyKey[], unsigned char userString[], int userStringSize) {
    int keyIndex = 0;
    for(int strIndex = 0; strIndex < userStringSize; strIndex++)
    {
        if(userString[strIndex] == ' ' || userString[strIndex] == NULL)
            continue;
        else {
            myactualyKey[keyIndex] = toupper(userString[strIndex]);
            keyIndex++;
        }
    }
}

void pkcs5(unsigned char dataBlock[], int numBytes) {
    int i = numBytes;
    unsigned char difference = BUFFSIZE - numBytes;
    for(i; i < BUFFSIZE; i++){
        dataBlock[i] = difference;
    }
}
