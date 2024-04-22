#include "server.hpp"
#define USED_SLOT 128
#define VALID_SLOT 124



PirServer::PirServer(const EncryptionParameters &enc_params,
                     const PirParams &pir_params, CAHELGPUContext &context, CAHELGPUBatchEncoder &encode)
    : enc_params(enc_params), pir_params(pir_params) {
  //context_ = make_shared<CAHELGPUContext>(enc_params, true,cahel::sec_level_type::tc128);
  //evaluator_ = make_unique<Evaluator>(context_);
  //encoder_ = make_unique<CAHELGPUBatchEncoder>(context);
  //encoder_ = encode;
  single_map(context,encode);
}

void PirServer::set_database(std::unique_ptr<Database> &&db) {
  db_ = move(db);
}


void PirServer::set_database(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,const std::unique_ptr<const int8_t[]> &bytes, std::int64_t ele_num, std::int64_t ele_size) {
    int32_t logt = floor(log2(enc_params.plain_modulus().value()));
    int32_t N = enc_params.poly_modulus_degree();
    auto result = make_unique<vector<CAHELGPUPlaintext>>();
    int num_CAHELGPUPlaintext = ele_num / N * ele_size / 2;
    vector<vector<int64_t>> coefficients = vector<vector<int64_t>>(num_CAHELGPUPlaintext, vector<int64_t>(N,0));//just see one coefficient contain two bytes
    //vector<int64_t> tag(2020,0);//every byte from 0 - 20
    cout<<"Elements num is "<<ele_num<<endl;
    int offset = 0;
    //guarantee the minum size of CAHELGPUPlaintext
    for(int64_t j = 0;j< 2 * num_CAHELGPUPlaintext/ele_size;j++){ //which slot  column
            for(int64_t i = 0;i< N;i++)  //which slot row
            { 
                for(int64_t k = 0;k<ele_size/2;k++)
                {   
                    int64_t coeff = bytes_to_coeffs(logt,bytes.get()+offset,2);
                    offset += 2;
                    coefficients[k + j* ele_size/2][i] = coeff;
                }
                
            }
    }
    cout<<"database palintexts size is "<<coefficients.size()<<endl;
   //now we can encode these coefficients into CAHELGPUPlaintexts
    for(int64_t i = 0;i< coefficients.size();i++)
    {
        CAHELGPUPlaintext p(context_);
        encoder_.encode(context_,coefficients[i],p);
        result->push_back(move(p));
    }
    //db_ = make_unique<Database>(std::move(result));
    set_database(std::move(result));
}


void PirServer::process_database() {
    
}
void PirServer::single_map(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_)
{
    /* this i represent the data-item,for example , data-item  contains four bytes,
      the field is two bytes,and every bytes is from 00 - 20,so we can represent the two bytes as first byte * 100 and last byte *1,
      and the range is from 0000(0) ~ 2020*/
      cout<<"Map the keywords"<<endl;
    int64_t N = enc_params.poly_modulus_degree();
    vector<vector<int64_t>> coeffcients;
    for(int64_t i = 0;i<=pir_params.ele_num;i++)
    {
        /* generate the unique constant weight map
         and we can map the dataitem to only one codeword 
        */
        vector<int64_t> coeff = constant_weight_map(i,VALID_SLOT,pir_params.k);
        // for(int j = 0;j<coeff.size();j++)
        // {
        //     cout<<coeff[j]<<" ";
        // }
        // cout<<endl;
        coeffcients.push_back(coeff);
    }
    int64_t column = pir_params.ele_num / N;
    vector<vector<int64_t>> result= vector<vector<int64_t>>(column * VALID_SLOT, vector<int64_t>(N,0));
    for(int i = 0;i<column;i++)
    {
        for(int j = 0;j<N;j++)
        {
            for(int k = 0;k<VALID_SLOT;k++){
                result[i * VALID_SLOT + k][j] = coeffcients[j + i*N][k];
            }
        }
    }
    for(int64_t i = 0;i<result.size();i++)
    {
        result[i][N-1] = 1;// prevent all 0
        //cout<<"pt generated"<<endl;
        CAHELGPUPlaintext pt(context_);
        encoder_.encode(context_,result[i],pt);
        //cout<<"pt mapped"<<endl;
        map_[i] = move(pt);
    }
    
}

int PirServer::serialize_reply(CAHELGPUContext &context_,PirReply &reply,std::stringstream &stream)
{
    int output_size = 0;
    mod_switch_to_inplace(context_,reply,context_.cpu_context_->last_parms_id());
    //output_size += reply.save(stream);
    reply.save(stream);
    return output_size;
}
PirReply PirServer::generate_reply(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_,PirQuery query,stringstream &stream,CAHELGPUGaloisKey &gal_keys,CAHELGPURelinKey &rel_keys){
    CAHELGPUGaloisKey rotate_galois_(context_);
    rotate_galois_.load(context_,stream);
    int64_t N = enc_params.poly_modulus_degree();
    vector<CAHELGPUPlaintext> *cur = db_.get();
    //vector<CAHELGPUCiphertext> expanded_query = expand_query(query,USED_SLOT);
    cout<<"Server : expanded over"<<endl;
    int column = (*cur).size()/(pir_params.ele_size/2);
    cout<<"Server: expanded query multiply the keyword"<<endl;
    vector<CAHELGPUCiphertext> keyword_CAHELGPUCiphertexts;
    for(int j = 0;j<column;j++){
        for(int i = 0;i<VALID_SLOT;i++)
        {
            CAHELGPUCiphertext tag(context_);
            multiply_plain(context_,query[i],map_[i + j * VALID_SLOT],tag);
            keyword_CAHELGPUCiphertexts.push_back(tag);
        }
    }
    //add the keyword slot based on block encoding
    cout<<"Server : add the keyword slot based on block encoding"<<endl;
    vector<vector<CAHELGPUCiphertext>> inter;
    
    for(int k = 0;k< column;k++){
        vector<CAHELGPUCiphertext> inter_cipher;
        for(int i = 0;i<pir_params.k;i++)
        {
            CAHELGPUCiphertext temp = keyword_CAHELGPUCiphertexts[i*pir_params.block_num + k * pir_params.m]; //pir_params.m is the keyword CAHELGPUCiphertext in every column
            for (int j = 1; j < pir_params.block_num; j++)
            {
                /* code */
                add_inplace(context_,temp,keyword_CAHELGPUCiphertexts[i * pir_params.block_num + j + k * pir_params.m]);
                
            }
            inter_cipher.push_back(temp);
        }
        inter.push_back(inter_cipher);
    }
    
    
    cout<<"Server: start find the desire slot in keyword codeword"<<endl;
    vector<vector<CAHELGPUCiphertext>> result_db;
    for(int i = 0;i<column;i++)
    {
        CAHELGPUCiphertext result = inter[i][0];
        multiply_many(context_,inter[i],rel_keys,result);
        //CAHELGPUCiphertext temp = inter[i][0];
        cout<<"multiply many over"<<endl;
        cout<<"all will mul_plain times are "<<pir_params.ele_size/2<<endl;
        vector<CAHELGPUCiphertext> temp_db;
        //temp_db.resize(pir_params.ele_size/2);
        for(int j = 0;j<pir_params.ele_size/2;j++)
        {
            CAHELGPUCiphertext vec_result(context_);
            multiply_plain(context_,result,(*cur)[i*pir_params.ele_size/2 + j],vec_result); //multiply the database
            temp_db.push_back(vec_result);
        }
        cout<<"The "<<i<<"-th column over!"<<endl;
        result_db.push_back(temp_db);
    }
    vector<int64_t> vec(N,1);
    vec[N-1] = 0;
    CAHELGPUPlaintext pt(context_);
    encoder_.encode(context_,vec,pt);
    cout<<"next will add database entry !!!"<<endl;
    //database entry add 
    for(int i = 0;i<result_db[0].size();i++)
    {
        for(int j = 1;j<column;j++)
        {
            add_inplace(context_,result_db[0][i],result_db[j][i]);
        }
        multiply_plain_inplace(context_,result_db[0][i],pt);
    }
    for(int i = 0;i<result_db[0].size();i++)
    {
        //cout<<"rotate and add"<<endl;
        //rotate_rows_inplace(context_,result_db[0][i],i,rotate_galois_);
        rotate_rows_inplace(context_,result_db[0][i],i,gal_keys);
    }
    CAHELGPUCiphertext result_in_all = result_db[0][0];
    for(int i = 1;i<result_db[0].size();i++)
    {
        add_inplace(context_,result_in_all,result_db[0][i]);
    }
    return result_in_all;
    
}

/*
inline vector<CAHELGPUCiphertext> PirServer::expand_query(const CAHELGPUCiphertext &encrypted,int32_t need_slot)
{
    CAHELGPUGaloisKeys &galkey = galoisKeys_;

    // Assume that m is a power of 2. If not, round it to the next power of 2.
    int32_t logm = ceil(log2(need_slot));
    CAHELGPUPlaintext two("2");

    vector<int> galois_elts;
    auto n = enc_params.poly_modulus_degree();
    if (logm > ceil(log2(n))) {
        throw logic_error("m > n is not allowed.");
    }
    for (int i = 0; i < ceil(log2(n)); i++) {
        galois_elts.push_back((n + exponentiate_int(2, i)) /
                            exponentiate_int(2, i));
    }

    vector<CAHELGPUCiphertext> temp;
    temp.push_back(encrypted);
    CAHELGPUCiphertext tempctxt;
    //rotated / shifted /rotatedshifted ???
    CAHELGPUCiphertext tempctxt_rotated;
    CAHELGPUCiphertext tempctxt_shifted;
    CAHELGPUCiphertext tempctxt_rotatedshifted;
    //section 3.3 in Sealpir's paper,figure 3
    for (int32_t i = 0; i < logm - 1; i++) {
        vector<CAHELGPUCiphertext> newtemp(temp.size() << 1);
        // temp[a] = (j0 = a (mod 2**i) ? ) : Enc(x^{j0 - a}) else Enc(0).  With
        // some scaling....
        int index_raw = (n << 1) - (1 << i);
        int index = (index_raw * galois_elts[i]) % (n << 1);

        for (int32_t a = 0; a < temp.size(); a++) {

        evaluator_->apply_galois(temp[a], galois_elts[i], galkey,
                                tempctxt_rotated);

        // cout << "rotate " <<
        // client.decryptor_->invariant_noise_budget(tempctxt_rotated) << ", ";

        evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
        multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);

        // cout << "mul by x^pow: " <<
        // client.decryptor_->invariant_noise_budget(tempctxt_shifted) << ", ";
        
        multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);

        // cout << "mul by x^pow: " <<
        // client.decryptor_->invariant_noise_budget(tempctxt_rotatedshifted) <<
        // ", ";

        // Enc(2^i x^j) if j = 0 (mod 2**i).
        evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted,
                        newtemp[a + temp.size()]);
        }
        temp = newtemp;
        /*
        cout << "end: ";
        for (int h = 0; h < temp.size();h++){
            cout << client.decryptor_->invariant_noise_budget(temp[h]) << ", ";
        }
        cout << endl;
        
    }
    // Last step of the loop
    vector<CAHELGPUCiphertext> newtemp(temp.size() << 1);
    int index_raw = (n << 1) - (1 << (logm - 1));
    int index = (index_raw * galois_elts[logm - 1]) % (n << 1);
    for (int32_t a = 0; a < temp.size(); a++) {
        if (a >= (need_slot - (1 << (logm - 1)))) { // corner case.
        evaluator_->multiply_plain(temp[a], two,
                                    newtemp[a]); // plain multiplication by 2.
        // cout << client.decryptor_->invariant_noise_budget(newtemp[a]) << ", ";
        } else {
        evaluator_->apply_galois(temp[a], galois_elts[logm - 1], galkey,
                                tempctxt_rotated);
        evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
        multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);
        multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);
        evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted,
                        newtemp[a + temp.size()]);
        }
    }

    vector<CAHELGPUCiphertext>::const_iterator first = newtemp.begin();
    vector<CAHELGPUCiphertext>::const_iterator last = newtemp.begin() + need_slot;
    vector<CAHELGPUCiphertext> newVec(first, last);

    return newVec;
}
*/

// PirQuery PirServer::deserialize_query(stringstream &stream)
// {
//   PirQuery q;
//   /*
//   int32_t ctx = ceil((pir_params_.num_ofCAHELGPUPlaintexts + 0.0)/enc_params_.poly_modulus_degree());
//   vector<CAHELGPUCiphertext> cs;
//   for(int32_t i=0; i<ctx; i++)
//   {
//     CAHELGPUCiphertext c;
//     c.load(context_,stream);
//     cs.push_back(c);
//   }
//   q = cs;
//   */
//   vector<CAHELGPUCiphertext> c ;
//   c.load(context_,stream);
//   q=c;
//   return q;
// }

void PirServer::deserialize_relinkkeys(CAHELGPUContext &context_,stringstream &stream)
{
  this->relin_keys.load(context_,stream);
}
/*
inline void PirServer::multiply_power_of_X(const CAHELGPUCiphertext &encrypted, CAHELGPUCiphertext &destination, int32_t index){
    auto coeff_mod_count = enc_params.coeff_modulus().size() - 1;
    auto coeff_count = enc_params.poly_modulus_degree();
    auto encrypted_count = encrypted.size();

    // cout << "coeff mod count for power of X = " << coeff_mod_count << endl;
    // cout << "coeff count for power of X = " << coeff_count << endl;

    // First copy over.
    destination = encrypted;

    // Prepare for destination
    // Multiply X^index for each CAHELGPUCiphertext polynomial
    for (int i = 0; i < encrypted_count; i++) {
        for (int j = 0; j < coeff_mod_count; j++) {
        negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count),
                                        coeff_count, index,
                                        enc_params.coeff_modulus()[j],
                                        destination.data(i) + (j * coeff_count));
        }
    }
}
*/
/*CAHELGPUCiphertext PirServer::equality_operator(CAHELGPUCiphertext &ct, int32_t k){
   // cout<<"equality_operator k is"<<k<<endl;
    int64_t m = 1;
    for(int32_t i=k; i >0;i--)
    {
        m *= i;
    }
    int64_t inverse = 0;
    inverse = invert_mod(m, enc_params.plain_modulus());
    vector<CAHELGPUCiphertext> cts;
    for(int64_t i = 0; i < k;i++)
    {
        CAHELGPUPlaintext pt(int_to_hex_string(&i,std::size_t(1)));
        CAHELGPUCiphertext ct1;
        evaluator_->sub_plain(ct, pt, ct1);
        cts.push_back(ct1);
    }
    CAHELGPUCiphertext result;
    evaluator_->multiply_many(cts, relin_keys,result);
  //  cout<<"multiply many finish"<<endl;
    CAHELGPUPlaintext pt1(int_to_hex_string(&inverse,std::size_t(1)));
    evaluator_->multiply_plain_inplace(result, pt1);
    return result;
}*/

   vector<CAHELGPUPlaintext> PirServer::get_slot_pt(CAHELGPUContext &context_,CAHELGPUBatchEncoder &encoder_)
    {
        vector<CAHELGPUPlaintext> pts;
        for(int i =0;i<2020;i++)
        {
            vector<int64_t> vec(enc_params.poly_modulus_degree(),0);
            vec[i] = 1;
            CAHELGPUPlaintext pt(context_);
            encoder_.encode(context_,vec, pt);
            pts.push_back(pt);
        }
        return pts;
    }

   /* void PirServer::deserialized_galois(stringstream &stream)
    {
        rotate_galois_.load(stream);
    }*/
