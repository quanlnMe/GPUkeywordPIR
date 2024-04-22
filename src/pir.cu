#include "pir.hpp"
#define VALID_SLOT 124
using namespace cahel;
using namespace cahel::util;


void gen_encrypt_params(int32_t N, std::int32_t logt, EncryptionParameters &enc_params){
  enc_params.set_poly_modulus_degree(N);
  enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(N));
  enc_params.set_plain_modulus(PlainModulus::Batching(N, logt + 1));
  //const vector<int> galois_steps = {1,2};
  //auto galois_elts = get_elts_from_steps(galois_steps, N);
  //enc_params.set_galois_elts(galois_elts);

  // the +1 above ensures we get logt bits for each plaintext coefficient.
  // Otherwise the coefficient modulus t will be logt bits, but only floor(t) =
  // logt-1 (whp) will be usable (since we need to ensure that all data in the
  // coefficient is < t).
}

void gen_pir_params(int64_t number_of_itmes,int64_t size_per_item,PirParams &pirparams){
  pirparams.ele_num = number_of_itmes;
  pirparams.ele_size = size_per_item;
  pirparams.k = 4;
  pirparams.m = VALID_SLOT;
  pirparams.block_num = pirparams.m / pirparams.k;

}

std::int64_t byte_num_per_coefficient(std::int32_t logt)
{
    return floor(logt / 8);
}

std::int64_t bytes_to_coeffs(int32_t limit,const int8_t *bytes, int64_t size)
{
  //cout<<"PIR:start to convert bytes to coefficients"<<endl;
    int64_t ele_size = byte_num_per_coefficient(limit);
    int64_t coeffs;
    for(int64_t i = 0; i < size; i++)
    {
        coeffs <<= 8;
        coeffs |= bytes[i];
    }
    //cout<<"One converted"<<endl;
    return coeffs;
}

void coeffs_to_bytes(std::vector<int64_t> coeffs, int64_t size,int64_t ele_size, int8_t *output)
{
    //output = new uint8_t[size * ele_size];
    for(int64_t i = 0; i < size; i++)
    {
        for(int64_t j = 0; j < 2; j++) //every coefficient contains two bytes
        {
            output[i * 2 + j] = coeffs[i] >> (8 * j);
        }
    }
}

uint64_t invert_mod(uint64_t m, const cahel::Modulus &mod) {
  if (mod.uint64_count() > 1) {
    cout << "Mod too big to invert";
  }
  uint64_t inverse = 0;
  if (!cahel::util::try_invert_uint_mod(m, mod.value(), inverse)) {
    cout << "Could not invert value";
  }
  return inverse;
}
