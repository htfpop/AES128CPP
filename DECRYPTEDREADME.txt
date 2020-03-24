Instructions for encryption
To ensure that this program works, please have AES128_Constants.h and main.cpp in the same directory

compile:  g++ main.cpp -o AES128.exe
Run: ./AES128.exe [absolute file path of file to encrypt]
You will be prompted to put in a key
Output file will be in the same location as original file. File extension will be YOUR_FILE_NAME.enc

Run openssl using YOUR_FILE_NAME.enc and the same key you used to encrypt the file.

File sizes and data should be the same.

