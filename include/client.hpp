#ifndef CLIENT_H
#define CLIENT_H

#include "pir.hpp"
#include<memory>
#include<vector>

using namespace cahel;
using namespace cahel::util;
using namespace utils;

class PirClient
{
private:
    /* data */
    cahel::EncryptionParameters enc_params;
    PirParams pir_params;
    std::unique_ptr<CAHELGPUSecretKey> secretkey_;
    std::unique_ptr<CAHELGPUPublicKey> publcikey_;
    //std::unique_ptr<CAHELGPUBatchEncoder> encoder_;
    //CAHELGPUContext context_;
public:
    PirClient(const cahel::EncryptionParameters &enc_params,const PirParams &pir_params, CAHELGPUContext &context, CAHELGPUBatchEncoder &encode);
    PirQuery generate_query(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,std::int64_t desire_field,CAHELGPUSecretKey &sk);
    int generate_serialized_query(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,std::int64_t desire_field,std::stringstream &stream);
    int generate_serialized_relinkKey(CAHELGPUContext &context_,std::stringstream &stream);
    vector<int8_t> decode_reply(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,PirReply &reply,CAHELGPUSecretKey &sk);
    std::vector<int64_t> extract_coeffs(CAHELGPUContext &context_,CAHELGPUPlaintext pt);

    void  generate_serialized_rotate_galois(CAHELGPUContext &context_,std::stringstream &stream);

    vector<int64_t> get_binary_string(int64_t num);    
};

#endif

