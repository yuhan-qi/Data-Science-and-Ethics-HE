// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"
#include "13b_MS-SEAL.h"

using namespace std;
using namespace seal;

void Matrix_Multiplication(size_t poly_modulus_degree, vector<vector<double>> matrix1, vector<vector<double>> matrix2)
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
    int r1 = matrix1.size();
    int c1 = matrix1[0].size();
    int r2 = matrix2.size();
    int c2 = matrix2[0].size();
    vector<vector<Plaintext>> plain_matrix1(r1, vector<Plaintext>(c1));
    vector<vector<Plaintext>> plain_matrix2(r2, vector<Plaintext>(c2));
    for (int i = 0; i < r1; i++)
    {
        for (int j = 0; j < c1; j++)
        {
            ckks_encoder.encode(matrix1[i][j], scale, plain_matrix1[i][j]);
        }
    }
    for (int i = 0; i < r2; i++)
    {
        for (int j = 0; j < c2; j++)
        {
            ckks_encoder.encode(matrix2[i][j], scale, plain_matrix2[i][j]);
        }
    }
    vector<vector<Ciphertext>> cipher_matrix1(r1, vector<Ciphertext>(c1));
    vector<vector<Ciphertext>> cipher_matrix2(r2, vector<Ciphertext>(c2));
    for (int i = 0; i < r1; i++)
    {
        for (int j = 0; j < c1; j++)
        {
            encryptor.encrypt(plain_matrix1[i][j], cipher_matrix1[i][j]);
        }
    }
    for (int i = 0; i < r2; i++)
    {
        for (int j = 0; j < c2; j++)
        {
            encryptor.encrypt(plain_matrix2[i][j], cipher_matrix2[i][j]);
        }
    }
    vector<vector<Ciphertext>> cipher_result_mult(r1, vector<Ciphertext>(c2));
    for (int i = 0; i < r1; i++)
    {
        for (int j = 0; j < c2; j++)
        {
            vector<Ciphertext> temp(c1);
            for(int k = 0; k < c1; k++)
            {
                evaluator.multiply(cipher_matrix1[i][k], cipher_matrix2[k][j], temp[k]);
            }
            evaluator.add_many(temp, cipher_result_mult[i][j]);
        }
    }
    // Decrypt
    vector<vector<Plaintext>> plain_result_mult(r1, vector<Plaintext>(c2));
    for (int i = 0; i < r1; i++)
    {
        for (int j = 0; j < c2; j++)
        {
            decryptor.decrypt(cipher_result_mult[i][j], plain_result_mult[i][j]);
        }
    }
    // Decode
    vector<vector<double>> result_mult(r1, vector<double>(c2));
    for (int i = 0; i < r1; i++)
    {
        for (int j = 0; j < c2; j++)
        {
            vector<double> result;
            ckks_encoder.decode(plain_result_mult[i][j], result);
            result_mult[i][j] = result[0];
        }
    }
    cout << "Resulting Matrix:" << endl;
    print_matrix(result_mult,0);
}
int main()
{
    int r1 = 4;
    int c1 = 5;
    int r2 = 5;
    int c2 = 4;
    vector<vector<double>> matrix1 = initMatrixRand(r1, c1);
    cout << "Matrix 1:" << endl;
    print_matrix(matrix1,2);
    vector<vector<double>> matrix2 = initMatrixRand(r2, c2);
    cout << "Matrix 2:" << endl;
    print_matrix(matrix2,2);
    Matrix_Multiplication(8192 * 2, matrix1, matrix2);
    return 0;
}
