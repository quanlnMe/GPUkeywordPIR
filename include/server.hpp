#ifndef SERVER_H
#define SERVER_H

#include "pir.hpp"
#include<vector>
#include<memory>
#include<map>

using namespace cahel;
using namespace cahel::util;
using namespace utils;

class PirServer
{
private:
    /* data */
    cahel::EncryptionParameters enc_params;
    PirParams pir_params;
    std::unique_ptr<Database> db_;
    //CAHELGPUGaloisKey galoisKeys_;
    //CAHELGPUGaloisKey rotate_galois_;
    //std::unique_ptr<CAHELGPUBatchEncoder> encoder_;
    //std::shared_ptr<CAHELGPUContext> context_;
    //CAHELGPUBatchEncoder encoder_;
    std::map<int64_t, CAHELGPUPlaintext> map_;
    void multiply_power_of_X(const CAHELGPUCiphertext &encrypted,CAHELGPUCiphertext &destination,std::int32_t index);
    CAHELGPUCiphertext equality_operator(CAHELGPUCiphertext &ct, std::int32_t k);
    std::vector<CAHELGPUPlaintext> get_slot_pt(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_);
    CAHELGPURelinKey relin_keys;

public:
    PirServer(const cahel::EncryptionParameters &enc_params,const PirParams &pir_params, CAHELGPUContext &context, CAHELGPUBatchEncoder &encode);
    void set_database(std::unique_ptr<Database> &&db);
    void set_database(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,const std::unique_ptr<const int8_t[]> &bytes, std::int64_t ele_num, std::int64_t ele_size);
    void process_database();
    //std::vector<cahel::CAHELGPUCiphertext> expand_query(const CAHELGPUCiphertext &encrypted, std::int32_t need_slot);
    void deserialize_relinkkeys(CAHELGPUContext &context_,std::stringstream &stream);
    void deserialized_galois(CAHELGPUContext &context_,std::stringstream &stream);
    //PirQuery deserialize_query(std::stringstream &stream);
    PirReply generate_reply(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,PirQuery query,std::stringstream &stream,CAHELGPUGaloisKey &gal_keys,CAHELGPURelinKey &rel_keys);
    int serialize_reply(CAHELGPUContext &context_,PirReply &reply,std::stringstream &stream);
    //void set_galoiskeys(CAHELGPUGaloisKey galkey);
    //void set_rotate_galois(CAHELGPUGaloisKey galkey);
    //used to unique map from query field to vector<int64_t>
    void single_map(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_);

    
};

#endif
