//
// Created by Chris Leung on 3/17/2020.
//

#ifndef AES_AESENCRYPT128_H
#define AES_AESENCRYPT128_H
typedef unsigned char t_uint8;
typedef unsigned int t_uint32;

class AES {
private:
    t_uint32 keys[43] = {0};
    t_uint32 key_ptr = keys[0];

public:
    AES(t_uint8 *initKey){
        genKeySchedule(initKey);
    }
    void genKeySchedule(t_uint8* initialKey)
    {

    }
};

void encryptBlock(unsigned char data []);

const int BUFFSIZE = 16;
#endif //AES_AESENCRYPT128_H
