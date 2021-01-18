// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"
#include "13b_MS-SEAL.h"

using namespace std;
using namespace seal;

void Matrix_Subtraction(size_t poly_modulus_degree, int width, int height)
{
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 60}));
    SEALContext context(params);
    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);
    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);
    // Create Scale
    double scale = pow(2.0, 40);
    vector<vector<double>> matrix1(height, vector<double>(width));
    vector<vector<double>> matrix2(height, vector<double>(width));
    // Fill input matrices
    // double r = ((double)rand() / (RAND_MAX));
    double filler = 1;
    // Matrix 1
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; j++)
        {
            matrix1[i][j] = filler;
            filler++;
            // r = ((double)rand() / (RAND_MAX));
        }
    }
    cout << "Matrix 1:" << endl;
    print_matrix(matrix1, 0);
    filler = 2;
    // Matrix 2
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; j++)
        {
            matrix2[i][j] = filler;
            // r = ((double)rand() / (RAND_MAX));
            filler++;
        }
    }
    cout << "Matrix 2:" << endl;
    print_matrix(matrix2, 0);
    vector<vector<Plaintext>> plain_matrix1(height, vector<Plaintext>(width));
    vector<vector<Plaintext>> plain_matrix2(height, vector<Plaintext>(width));
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; j++)
        {
            ckks_encoder.encode(matrix1[i][j], scale, plain_matrix1[i][j]);
            ckks_encoder.encode(matrix2[i][j], scale, plain_matrix2[i][j]);
        }
    }
    vector<vector<Ciphertext>> cipher_matrix1(height, vector<Ciphertext>(width));
    vector<vector<Ciphertext>> cipher_matrix2(height, vector<Ciphertext>(width));
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; j++)
        {
            encryptor.encrypt(plain_matrix1[i][j], cipher_matrix1[i][j]);
            encryptor.encrypt(plain_matrix2[i][j], cipher_matrix2[i][j]);
        }
    }
    vector<vector<Ciphertext>> cipher_result_subtraction(height, vector<Ciphertext>(width));
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; j++)
        {
            evaluator.sub(cipher_matrix1[i][j], cipher_matrix2[i][j], cipher_result_subtraction[i][j]);
        }
    }
    // Decrypt
    vector<vector<Plaintext>> plain_result_subtraction(height, vector<Plaintext>(width));
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; j++)
        {
            decryptor.decrypt(cipher_result_subtraction[i][j], plain_result_subtraction[i][j]);
        }
    }
    // Decode
    vector<vector<double>> result_subtraction(height, vector<double>(width));
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; j++)
        {
            vector<double> result;
            ckks_encoder.decode(plain_result_subtraction[i][j], result);
            result_subtraction[i][j] = result[0];
        }
    }
    print_matrix(result_subtraction,0);
}
int main()
{
    Matrix_Subtraction(8192 * 2, 4, 5);
    return 0;
}
