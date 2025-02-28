#include <iostream>
#include <string>
#include <string.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdint>
using namespace std;
//Kian Frawley 2/16/24 CS458

void QuarterRound(uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3); //tested
inline uint64_t rotl(uint32_t x, int n); //tested
void RowRound(uint32_t sequence[16]);//Tested
void ColumnRound(uint32_t sequence[16]);//Tested
void DoubleRound(uint32_t sequence[16]); //Tested
void salsa20Hash(uint32_t sequence[16]);//Tested
void salsa20Expand(uint8_t output[64], const uint8_t *key, size_t keyLen, const uint8_t nonce[16]); //Tested

// Encryption/Decryption function
void salsa20EncryptionDecryption(uint8_t *output, const uint8_t *input, size_t input_len, const uint8_t *key, size_t keyLen, const uint8_t *nonce) {
    uint8_t keyST[64]; uint8_t extended_nonce[16]; uint64_t block_counter = 0; size_t offset = 0;
    
    memcpy(extended_nonce, nonce, 8);//Build the 16-byte nonce
    memset(extended_nonce + 8, 0, 8);

    while (offset < input_len) {//Update the block cntr
        extended_nonce[8]  = block_counter & 0xFF;
        extended_nonce[9]  = (block_counter >> 8) & 0xFF;
        extended_nonce[10] = (block_counter >> 16) & 0xFF;
        extended_nonce[11] = (block_counter >> 24) & 0xFF;
        extended_nonce[12] = (block_counter >> 32) & 0xFF;
        extended_nonce[13] = (block_counter >> 40) & 0xFF;
        extended_nonce[14] = (block_counter >> 48) & 0xFF;
        extended_nonce[15] = (block_counter >> 56) & 0xFF;

        salsa20Expand(keyST, key, keyLen, extended_nonce);//Generate keystr 
        for(size_t i = 0; i < 64 && offset < input_len; i++, offset++) output[offset] = input[offset] ^ keyST[i];//XOR the keystr blk with the input
        block_counter++;
    }
}

void printTmpArr(const uint32_t tmpArr[16]) {
    for (int i = 0; i < 16; i++) std::cout << "tmpArr[" << i << "] = " << std::hex << std::setw(8) << std::setfill('0') << tmpArr[i] << std::endl;
    std::cout << "--------------------------------" << std::endl;
}

//memcpy copies a specified number of bytes from a source memory location to a destination memory location. This is so I do not have to remember the syntax for memcpy
void salsa20Expand(uint8_t output[64], const uint8_t *key, size_t keyLen, const uint8_t nonce[16]) {
    const uint8_t *constants; uint32_t tmpArr[16]; 

    if (keyLen == 32) {//256-bit key (32 bytes)
        static const uint8_t s[16] = {101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107}; //"expand 32-byte k"
        constants = s;
        memcpy(tmpArr, constants, 4);
        //sprinttmpArr(tmpArr);
        memcpy(tmpArr + 1, key, 16);
        //printtmpArr(tmpArr);
        memcpy(tmpArr + 5, constants + 4, 4);
        memcpy(tmpArr + 6, nonce, 16);
        memcpy(tmpArr + 10, constants + 8, 4);
        memcpy(tmpArr + 11, key + 16, 16);
        memcpy(tmpArr + 15, constants + 12, 4);
    } else if (keyLen == 16) {//128-bit key (16 bytes)
        static const uint8_t t[16] = {101, 120, 112, 97, 110, 100, 32, 49, 54, 45, 98, 121, 116, 101, 32, 107};//"expand 16-byte k"
        constants = t;
        memcpy(tmpArr, constants, 4);
        memcpy(tmpArr + 1, key, 16);
        memcpy(tmpArr + 5, constants + 4, 4);
        memcpy(tmpArr + 6, nonce, 16);
        memcpy(tmpArr + 10, constants + 8, 4);
        memcpy(tmpArr + 11, key, 16);
        memcpy(tmpArr + 15, constants + 12, 4);
    } else if (keyLen == 8) {//64-bit key (8 bytes)
        static const uint8_t a[16] = {101, 120, 112, 97, 110, 100, 32, 48, 56, 45, 98, 121, 116, 101, 32, 107};//"expand 08-byte k"
        constants = a;
        memcpy(tmpArr, constants, 4);//For every 4 bytes, new idx val
        //printtmpArr(tmpArr);
        memcpy(tmpArr + 1, key, 8);
        //printtmpArr(tmpArr);
        memcpy(tmpArr + 3, key, 8);
        memcpy(tmpArr + 5, constants + 4, 4);
        memcpy(tmpArr + 6, nonce, 16);
        memcpy(tmpArr + 10, constants + 8, 4);
        memcpy(tmpArr + 11, key, 8);
        memcpy(tmpArr + 13, key, 8);
        memcpy(tmpArr + 15, constants + 12, 4);
    } else {
        cerr << "Invalid key length: " << keyLen << " bytes" << endl; 
        return; 
    }salsa20Hash(tmpArr);
    memcpy(output, tmpArr, 64);
}

vector<uint8_t> hexStringToBytes(const string &hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = stoi(hex.substr(i, 2), nullptr, 16); //stoi is annoying lol
        bytes.push_back(byte);
    }return bytes;
}

string bytesToHexString(const uint8_t *bytes, size_t length) {
    stringstream ss;
    for (size_t i = 0; i < length; i++) ss << hex << setw(2) << setfill('0') << static_cast<int>(bytes[i]);
    return ss.str();
}

int main(int argc, char* argv[]) {
    if(argc != 5){ // Check cmd args
        cout << "Please ensure output follows this format: " << argv[0] << " <key length in bits> <key hex> <nonce hex> <input hex>" << endl;
        return 1;
    }int keyLen_bits = stoi(argv[1]);string keyHex = argv[2]; string nonceHex = argv[3];string inputHex = argv[4];
    
    if (keyLen_bits != 64 && keyLen_bits != 128 && keyLen_bits != 256) {//Validate key len
        cout << "Invalid key len. Must be 64/128/256 bits." << endl;
        return 1;
    }size_t keyLen = keyLen_bits / 8;
    vector<uint8_t> key = hexStringToBytes(keyHex); vector<uint8_t> nonce = hexStringToBytes(nonceHex); vector<uint8_t> input = hexStringToBytes(inputHex);
    
    if(key.size() != keyLen) {//Validate the key and nonce len
        cout << "Key len issue: expected " << keyLen << " bytes, but got " << key.size() << " bytes." << endl;
        return 1;
    }if(nonce.size()!=8){
        cout << "Invalid nonce len as we expected 8 bytes(16 hex digits), but input was " << nonce.size() << " bytes." << endl;
        for (int i = 0; i < nonce.size(); i++)cout << nonce[i] << " ";
        return 1;
    }if(input.size() > 1024) {
        cout << "Input is over 1KB. \n";
        return 1;
    }size_t inputLen = input.size();vector<uint8_t> output(inputLen);
    salsa20EncryptionDecryption(output.data(), input.data(), inputLen, key.data(), keyLen, nonce.data());
    string output_hex = bytesToHexString(output.data(), inputLen);
    cout << output_hex << endl;
    return 0;
}

inline uint64_t rotl(uint32_t x, int n) {
    uint32_t xL = (x << n);
    uint32_t xR = (x >> (32 - n));
    return (xL | xR);
}

void QuarterRound(uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3) {
    uint32_t z[4] = {0,0,0,0};
    z[1] = y1 ^ rotl(y0 + y3, 7);
    z[2] = y2 ^ rotl(z[1] + y0, 9);
    z[3] = y3 ^ rotl(z[2] + z[1], 13);
    z[0] = y0 ^ rotl(z[3] + z[2], 18);
    y0 = z[0]; y1 = z[1]; y2 = z[2]; y3 = z[3];
}

void RowRound(uint32_t sequence[16]) {
    uint32_t temp[16];
    QuarterRound(sequence[0], sequence[1], sequence[2], sequence[3]);
    temp[0] = sequence[0]; temp[1] = sequence[1]; temp[2] = sequence[2]; temp[3] = sequence[3];
    QuarterRound(sequence[5], sequence[6], sequence[7], sequence[4]);
    temp[4] = sequence[4]; temp[5] = sequence[5]; temp[6] = sequence[6]; temp[7] = sequence[7];
    QuarterRound(sequence[10], sequence[11], sequence[8], sequence[9]);
    temp[8] = sequence[8]; temp[9] = sequence[9]; temp[10] = sequence[10]; temp[11] = sequence[11];
    QuarterRound(sequence[15], sequence[12], sequence[13], sequence[14]);
    temp[12] = sequence[12]; temp[13] = sequence[13]; temp[14] = sequence[14]; temp[15] = sequence[15];
    for(int i = 0; i < 16; i++)sequence[i] = temp[i];
}

void ColumnRound(uint32_t sequence[16]) {
    uint32_t temp[16];
    QuarterRound(sequence[0], sequence[4], sequence[8], sequence[12]);
    temp[0] = sequence[0]; temp[4] = sequence[4]; temp[8] = sequence[8]; temp[12] = sequence[12];
    QuarterRound(sequence[5], sequence[9], sequence[13], sequence[1]);
    temp[1] = sequence[1]; temp[5] = sequence[5]; temp[9] = sequence[9]; temp[13] = sequence[13];
    QuarterRound(sequence[10], sequence[14], sequence[2], sequence[6]);
    temp[2] = sequence[2]; temp[6] = sequence[6]; temp[10] = sequence[10]; temp[14] = sequence[14];
    QuarterRound(sequence[15], sequence[3], sequence[7], sequence[11]);
    temp[3] = sequence[3]; temp[7] = sequence[7]; temp[11] = sequence[11]; temp[15] = sequence[15];
    for(int i = 0; i < 16; i++)sequence[i] = temp[i];
}

void DoubleRound(uint32_t sequence[16]) {
    ColumnRound(sequence);
    RowRound(sequence);
}

void salsa20Hash(uint32_t sequence[16]) {
    uint32_t initial[16];
    for(int i = 0; i < 16; i++)initial[i] = sequence[i];
    for(int i = 0; i < 4; i++)DoubleRound(sequence);
    for(int i = 0; i < 16; i++)sequence[i] += initial[i];
}