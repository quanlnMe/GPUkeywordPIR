#ifndef PIR_H
#define PIR_H

#include "CAHEL/cahel.h"
#include "CAHEL/util/uintarithmod.h"
#include<string>
#include<vector>
#include<iostream>
#include "utils.hpp"

using namespace std;

typedef std::vector<CAHELGPUPlaintext> Database;
typedef vector<CAHELGPUCiphertext> PirQuery;
typedef CAHELGPUCiphertext PirReply;

struct PirParams {
    std::int64_t ele_num;
    std::int64_t ele_size;
    std::int64_t k; //  constant-hamming-code k
    std::int64_t m;
    std::int64_t block_num;
    std::int64_t num_plaintexts;
    //std::int64_t h; //the num of ciphertext to store database
};

void gen_encrypt_params(std::int32_t N, std::int32_t logt, EncryptionParameters &enc_params);
void gen_pir_params(int64_t ele_num,int64_t ele_size,PirParams &pirparams);

std::int64_t byte_num_per_coefficient(std::int32_t logt);

//put two bytes into one int64_t,and form coefficients
std::int64_t bytes_to_coeffs(int32_t limit,const std::int8_t *bytes,std::int64_t size);

void coeffs_to_bytes(std::vector<int64_t> coeffs,std::int64_t size,std::int64_t ele_size,std::int8_t *output);

//std::string serialize_galoiskeys(seal::Serializable<seal::GaloisKeys> g);

CAHELGPUGaloisKey* deserialize_galoiskeys(std::string s, std::shared_ptr<cahel::CAHELContext> context);

std::uint64_t invert_mod(uint64_t m,const cahel::Modulus &mod);
#endif
