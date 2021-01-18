// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"
#include "13b_MS-SEAL.h"

using namespace std;
using namespace seal;

void MatrixTranspose(size_t poly_modulus_degree, int dimension){
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 60}));
    SEALContext context(params);
    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);
    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);
    // Create Scale and U_transpose Dimension
    double scale = pow(2.0, 80);
    int dimensionSq = pow(dimension, 2);
    // Create input matrix
    vector<vector<double>> pod_matrix1_set1(dimension, vector<double>(dimension));
    // Fill input matrices
    // double r = ((double)rand() / (RAND_MAX));
    double filler = 1;
    // Matrix 1
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix1_set1[i][j] = filler;
            filler++;
            // r = ((double)rand() / (RAND_MAX));
        }
    }
    cout << "Matrix 1:" << endl;
    print_matrix(pod_matrix1_set1, 0);
    // Get U_tranposed
    vector<vector<double>> U_transposed = get_U_transpose(pod_matrix1_set1);
    cout << "U_tranposed:" << endl;
    print_matrix(U_transposed, 0);
    // Get diagonals for U_transposed
    vector<vector<double>> U_transposed_diagonals = get_all_diagonals(U_transposed);
    // --------------- ENCODING ----------------
    // Encode U_transposed_diagonals
    vector<Plaintext> U_transposed_diagonals_plain(dimensionSq);
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_transposed_diagonals[i], scale, U_transposed_diagonals_plain[i]);
    }
    // Encode Matrix 1
    vector<Plaintext> plain_matrix1_set1(dimension);
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix1_set1[i], scale, plain_matrix1_set1[i]);
    }
    // --------------- ENCRYPTING ----------------
    // Encrypt Matrix 1
    vector<Ciphertext> cipher_matrix1_set1(dimension);
    for (int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix1_set1[i], cipher_matrix1_set1[i]);
    }
    vector<Ciphertext> cipher_U_transposed_diagonals(dimensionSq);
    for (int i = 0; i < dimensionSq; i++)
    {
        encryptor.encrypt(U_transposed_diagonals_plain[i], cipher_U_transposed_diagonals[i]);
    }
    // --------------- MATRIX ENCODING ----------------
    // Matrix Encode Matrix 1
    Ciphertext cipher_encoded_matrix1_set1 = C_Matrix_Encode(cipher_matrix1_set1, gal_keys, evaluator);
    Ciphertext cipher_encoded_U_transposed_diagonals = C_Matrix_Encode(cipher_U_transposed_diagonals, gal_keys, evaluator);
    // --------------- MATRIX TRANSPOSING ----------------
    Ciphertext ct_result = Linear_Transform_Cipher(cipher_encoded_matrix1_set1, cipher_U_transposed_diagonals, gal_keys, evaluator);
    // --------------- DECRYPT ----------------
    Plaintext pt_result;
    decryptor.decrypt(ct_result, pt_result);
    // --------------- DECODE ----------------
    vector<double> result_row;
    ckks_encoder.decode(pt_result, result_row);
    vector<vector<double>> result_mat;
    for(int i = 0; i < dimension; i++){
        vector<double> result;
        for(int j = 0; j < dimension; j++){
            result.push_back(result_row[i*dimension + j]);
        }
        result_mat.push_back(result);
    }
    cout << "Resulting matrix: " << endl;
    print_matrix(result_mat,0);
}

int main()
{
    MatrixTranspose(8192 * 2, 4);
    return 0;
}
