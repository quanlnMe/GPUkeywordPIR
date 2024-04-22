#include "pir.hpp"
#include "client.hpp"
#include <iostream>
#include "server.hpp"
#include <random>
#include "CAHEL/cahel.h"
#include <chrono>

using namespace std;
using namespace std::chrono;

int main(int argc, char *argv[]){
    int64_t number_of_itmes = 262144;   
    int32_t logt = 20;
    int64_t size_per_item = 1024;
    int32_t N = 8192;

    EncryptionParameters enc_params(scheme_type::bfv);
    PirParams pir_params;
    cout<<"Main : Generating SEAL PArameters"<<endl;
    gen_encrypt_params(N, logt, enc_params);
    gen_pir_params(number_of_itmes,size_per_item,pir_params);
    auto context_ = CAHELGPUContext(enc_params,true,cahel::sec_level_type::tc128);
    CAHELGPUSecretKey sk(enc_params);
    sk.gen_secretkey(context_);
    CAHELGPURelinKey rlk(context_);
    sk.gen_relinkey(context_,rlk);
    CAHELGPUGaloisKey glk(context_);
    sk.create_galois_keys(context_,glk);
    CAHELGPUBatchEncoder encoder_(context_);

    PirClient pir_client(enc_params,pir_params,context_, encoder_);
    cout<<"Main : Generating galois_keys"<<endl;
    stringstream gal_stream;
    //CAHELGPUGaloisKey rotate_galois = pir_client.generate_rotate_galois();
    pir_client.generate_serialized_rotate_galois(context_,gal_stream);
    cout<<"Initializing server"<<endl;
    PirServer pir_server(enc_params,pir_params,context_, encoder_);
    //pir_server.set_rotate_galois(rotate_galois);
    //pir_server.deserialized_galois(stream);
    cout<<"Initializing database"<<endl;
    cout<<"Main: Creating the database with random data "<<endl;

    auto db(make_unique<int8_t[]>(number_of_itmes*size_per_item));

    random_device rd;
    for(int64_t i = 0;i<number_of_itmes;i++)
    {
        for(int64_t j = 0;j<size_per_item;j++)
        {
            int8_t val = rd() % 255;
            db.get()[i*size_per_item+j] = val;
        }
    }
    cout<<"Main: Starting to process the database"<<endl;
    pir_server.process_database();
    pir_server.set_database(context_,encoder_,move(db),number_of_itmes,size_per_item);
    cout<<"database generated!"<<endl;

    cout<<"Generate random query keyword"<<endl;
    // int64_t field1 = (int64_t)db.get()[rd() % (number_of_itmes * size_per_item)];
    // cout<<field1<<endl;
    // int64_t field2 = (int64_t)db.get()[rd() % (number_of_itmes * size_per_item)];
    // int64_t field = field1 *100+ field2;
    int64_t field = rd() % number_of_itmes;
    cout<<"Main : You want to fuzzy query all items containing "<<field<<endl;

    auto time_query_s = high_resolution_clock::now();
    PirQuery query = pir_client.generate_query(context_,encoder_,field,sk);
    auto time_query_e = high_resolution_clock::now();
    auto time_query = duration_cast<microseconds>(time_query_e - time_query_s);
    cout<<"query generated!"<<endl;
    //cout<<"Main : Query time is "<<time_query.count()<<endl;

    stringstream client_stream;
    stringstream server_stream;
    stringstream relink_stream;

    int relink_size = pir_client.generate_serialized_relinkKey(context_,relink_stream);
    cout<<"Main : Relink size is "<<relink_size<<endl;
    pir_server.deserialize_relinkkeys(context_,relink_stream);

    auto time_s_query_s = high_resolution_clock::now();
    int query_size = pir_client.generate_serialized_query(context_,encoder_,field,client_stream);
    auto time_s_query_e = high_resolution_clock::now();
    auto time_s_query = duration_cast<microseconds>(time_s_query_e - time_s_query_s);
    cout<<"query serialized!"<<endl;
    //cout<<"Main : Serialization time is "<<time_s_query.count()<<endl;

    auto time_desierial_s = high_resolution_clock::now();
    //PirQuery query2 = pir_server.deserialize_query(client_stream);
    auto time_desierial_e = high_resolution_clock::now();
    auto time_desierial = duration_cast<microseconds>(time_desierial_e - time_desierial_s);
    cout<<"Query deserialized!"<<endl;
    //cout<<"Main : Deserialization time is "<<time_desierial.count()<<endl;
   

   auto time_server_s = high_resolution_clock::now();
   PirReply reply = pir_server.generate_reply(context_,encoder_,query,gal_stream,glk,rlk);
   auto time_server_e = high_resolution_clock::now();
   auto time_server = duration_cast<microseconds>(time_server_e - time_server_s);
   cout<<"Reply generated!"<<endl;
   //cout<<"Main : Server time is "<<time_server.count()<<endl;

   int reply_size = pir_server.serialize_reply(context_,reply,server_stream);

    vector<int8_t> elems = pir_client.decode_reply(context_,encoder_,reply,sk);
    for(int64_t i = 0;i<elems.size();i++)
    {
        cout<<(int)elems[i]<<" ";
    }
    cout<<endl;

   cout<<"Main: PIR result conrrect!"<<endl;
   cout<<"------------------GPU :-------------------"<<endl;
   cout<<"Main: PIRClient query time is "<<ceil(time_query.count()/1000)<<endl;
   cout<<"Main: PIRClient serialization time is "<<ceil(time_s_query.count()/1000)<<endl;
   cout<<"Main: PIRClient deserialization time is "<<std::ceil(time_desierial.count()/1000)<<endl;
   cout<<"Main: PIRServer reply time is "<<ceil(time_server.count()/1000)<<endl;


   return 0;



}
