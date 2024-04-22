#include "client.hpp"
#define USED_SLOT 128
#define VALID_SLOT 124

PirClient::PirClient(const EncryptionParameters &enc_params,const PirParams &pir_params, CAHELGPUContext &context, CAHELGPUBatchEncoder &encode)
                    : enc_params(enc_params), pir_params(pir_params){
    //context_ = make_shared<CAHELGPUContext>(enc_params, true);
    //encoder_ = make_unique<CAHELGPUBatchEncoder>(context);
    secretkey_ = make_unique<CAHELGPUSecretKey>(enc_params);
    publcikey_ = make_unique<CAHELGPUPublicKey>(context);
    secretkey_->gen_secretkey(context);
}

vector<int64_t> PirClient::get_binary_string(int64_t num){
    return constant_weight_map(num,VALID_SLOT,pir_params.k);
}

int PirClient::generate_serialized_query(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,std::int64_t desire_field,std::stringstream &stream){
    vector<int64_t> query = get_binary_string(desire_field);
   // CAHELGPUPlaintext query_(enc_params.poly_modulus_degree(),enc_params.poly_modulus_degree());
    int32_t N = enc_params.poly_modulus_degree();
    int output_size = 0;
    for(int64_t i = 0;i<query.size();i++)
    {
        // if(query[i] == 1)
        // {
        //     query_.data()[i] = invert_mod(USED_SLOT,enc_params.plain_modulus());
        // }
        vector<CAHELGPUCiphertext> query_;
        if(query[i] == 1)
        {
            vector<int64_t> query_vec(N,1);
            CAHELGPUPlaintext pt(context_);
            CAHELGPUCiphertext ct(context_);
            encoder_.encode(context_,query_vec,pt);
            secretkey_->encrypt_symmetric(context_,pt,ct,false);
            //output_size += ct.save(stream);
            ct.save(stream);
	        query_.push_back(ct);
        }
        else
        {
            vector<int64_t> query_vec(N,0);
            CAHELGPUPlaintext pt(context_);
            CAHELGPUCiphertext ct(context_);
            encoder_.encode(context_,query_vec,pt);
            secretkey_->encrypt_symmetric(context_,pt,ct,false);
            //output_size += ct.save(stream);
            ct.save(stream);
	    query_.push_back(ct);
        }
    }
    return output_size;
}

PirQuery PirClient::generate_query(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,std::int64_t desire_field,CAHELGPUSecretKey &sk){
    vector<int64_t> query = get_binary_string(desire_field);
    cout<<"binary string generated"<<endl;
    int32_t N = enc_params.poly_modulus_degree(); 
    vector<CAHELGPUCiphertext> query_;
    for(int64_t i = 0;i<query.size();i++)
    {
        // if(query[i] == 1)
        // {
        //     query_.data()[i] = invert_mod(USED_SLOT,enc_params.plain_modulus());
        // }
        if(query[i] == 1)
        {
            vector<int64_t> query_vec(N,1);
            CAHELGPUPlaintext pt(context_);
            CAHELGPUCiphertext ct(context_);
            encoder_.encode(context_,query_vec,pt);
            //secretkey_->encrypt_symmetric(context_,pt,ct,false);
            sk.encrypt_symmetric(context_,pt,ct,false);
            query_.push_back(ct);
        }
        else
        {
            vector<int64_t> query_vec(N,0);
            CAHELGPUPlaintext pt(context_);
            CAHELGPUCiphertext ct(context_);
            encoder_.encode(context_,query_vec,pt);
            //secretkey_->encrypt_symmetric(context_,pt,ct,false);
            sk.encrypt_symmetric(context_,pt,ct,false);
            query_.push_back(ct);
        }
    }
    
    return query_;
    
}

void PirClient::generate_serialized_rotate_galois(CAHELGPUContext &context_,stringstream &stream){
   // Generate the Galois keys needed for coeff_select.
  CAHELGPUGaloisKey gal_keys(context_);
  secretkey_->create_galois_keys(context_,gal_keys);
  gal_keys.save(stream); 
}


int PirClient::generate_serialized_relinkKey(CAHELGPUContext &context_,std::stringstream &stream)
{
  int output_size = 0;
  CAHELGPURelinKey relin_key(context_);
  secretkey_->gen_relinkey(context_,relin_key);
  //output_size += relin_key.save(stream);
  relin_key.save(stream);
  return output_size;
} 



vector<int8_t> PirClient::decode_reply(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,PirReply &reply,CAHELGPUSecretKey &sk){
    CAHELGPUPlaintext pt(context_);
    vector<int64_t> coeffs;
    vector<int64_t> coeffs_valid;
    //secretkey_->decrypt(context_,reply,pt);
    sk.decrypt(context_,reply,pt);
    encoder_.decode(context_,pt,coeffs);
    int pointer = 0;
    if(coeffs[0]!=0) pointer += pir_params.ele_size / 2;//to find the first item
    for(int i = pointer;i<coeffs.size();i++)
    {
        if(coeffs[i]!=0)
        {
            coeffs_valid.push_back(coeffs[i]); //find the valid result
        }
    }
    vector<int8_t> result_bytes(pir_params.ele_size);
    coeffs_to_bytes(coeffs_valid,coeffs_valid.size(),pir_params.ele_size/2,result_bytes.data());
    return result_bytes;
}
