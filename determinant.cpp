// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"
#include "13b_MS-SEAL.h"

using namespace std;
using namespace seal;

// Recursive function for finding determinant of matrix. n is current dimension of mat[][].
Ciphertext determinantOfMatrix(vector<vector<Ciphertext>> cipher_matrix, int dimension, double scale, Ciphertext cipher_sign,  Ciphertext cipher_sign_c, Evaluator &evaluator, RelinKeys relin_keys, Encryptor &encryptor, CKKSEncoder &ckks_encoder)
{
    //cout << "start" << endl;
    double D = 0.0; // Initialize result
    double result = 0.0;
    Plaintext D_plain;
    Plaintext result_plain;
    ckks_encoder.encode(D, scale, D_plain);
    ckks_encoder.encode(result, scale, result_plain);
    Ciphertext D_cipher;
    Ciphertext result_cipher;
    encryptor.encrypt(D_plain, D_cipher);
    encryptor.encrypt(result_plain, result_cipher);
    int N = cipher_matrix.size();
    vector<vector<Ciphertext>> submat(N, vector<Ciphertext>(N)); // To store cofactors
    //  Base case : if matrix contains single element
    if (dimension == 2)
    {
        Ciphertext sub1;
        evaluator.multiply(cipher_matrix[0][0], cipher_matrix[1][1], sub1);
        evaluator.relinearize_inplace(sub1, relin_keys);
        evaluator.rescale_to_next_inplace(sub1);
        Ciphertext sub2;
        evaluator.multiply(cipher_matrix[1][0], cipher_matrix[0][1], sub2);
        evaluator.relinearize_inplace(sub2, relin_keys);
        evaluator.rescale_to_next_inplace(sub2);
        Ciphertext res;
        evaluator.sub(sub1, sub2, res);
        return res;
    }
    else
    {
        cipher_sign = cipher_sign_c;
        for (int c = 0; c < dimension; c++)
        {
            int subi = 0;
            for (int i = 1; i < dimension; i++)
            {
                int subj = 0;
                for (int j = 0; j < dimension; j++)
                {
                    if(j == c) continue;
                    submat[subi][subj] = cipher_matrix[i][j];
                    subj ++;
                }
                subi++;
            }
            Ciphertext t;
            evaluator.multiply(cipher_sign, cipher_matrix[0][c], t);
            evaluator.relinearize_inplace(t, relin_keys);
            evaluator.rescale_to_next_inplace(t);
            Ciphertext res;
            evaluator.multiply(t, determinantOfMatrix(submat, dimension - 1, scale, cipher_sign, cipher_sign_c, evaluator, relin_keys, encryptor, ckks_encoder), res);
            evaluator.relinearize_inplace(res, relin_keys);
            evaluator.rescale_to_next_inplace(res);
            cout << "res size " << res.size() << endl;
            // terms are to be added with alternate sign
            evaluator.negate(cipher_sign, cipher_sign);
            evaluator.relinearize_inplace(cipher_sign, relin_keys);
            evaluator.rescale_to_next_inplace(cipher_sign);
            cout << "D_cipher size " << D_cipher.size() << endl;
            evaluator.add(res,D_cipher, result_cipher);
        }
    }
    return result_cipher;
}

void Determinant(size_t poly_modulus_degree, vector<vector<double>> matrix)
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
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);
    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);
    // Create Scale
    double scale = pow(2.0, 40);
    int dimension = matrix.size();
    vector<vector<Plaintext>> plain_matrix(dimension, vector<Plaintext>(dimension));
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            ckks_encoder.encode(matrix[i][j], scale, plain_matrix[i][j]);
        }
    }
    vector<vector<Ciphertext>> cipher_matrix(dimension, vector<Ciphertext>(dimension));
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            encryptor.encrypt(plain_matrix[i][j], cipher_matrix[i][j]);
        }
    }
    double sign = 1.0; // To store sign multiplier
    Plaintext plain_sign;
    ckks_encoder.encode(sign, scale, plain_sign);
    Ciphertext cipher_sign_c;
    Ciphertext cipher_sign;
    encryptor.encrypt(plain_sign, cipher_sign);
    encryptor.encrypt(plain_sign, cipher_sign_c);
    Ciphertext cipher_result = determinantOfMatrix(cipher_matrix, dimension, scale, cipher_sign, cipher_sign_c, evaluator, relin_keys, encryptor, ckks_encoder);
    // Decrypt
    Plaintext plain_result;
    decryptor.decrypt(cipher_result, plain_result);
    // Decode
    vector<double> result_vec;
    ckks_encoder.decode(plain_result, result_vec);
    double result = result_vec[0];
    cout << "Resulting Determinant: " << result << endl;
}

void DeterminantByThree(size_t poly_modulus_degree, vector<vector<double>> matrix)
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
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);
    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);
    // Create Scale
    double scale = pow(2.0, 40);
    int dimension = matrix.size();
    vector<vector<Plaintext>> plain_matrix(dimension, vector<Plaintext>(dimension));
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            ckks_encoder.encode(matrix[i][j], scale, plain_matrix[i][j]);
        }
    }
    vector<vector<Ciphertext>> cipher_matrix(dimension, vector<Ciphertext>(dimension));
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            encryptor.encrypt(plain_matrix[i][j], cipher_matrix[i][j]);
        }
    }
    Ciphertext x1;
    evaluator.multiply(cipher_matrix[1][1], cipher_matrix[2][2], x1);
    Ciphertext x2;
    evaluator.multiply(cipher_matrix[2][1], cipher_matrix[1][2], x2);
    Ciphertext x0;
    evaluator.sub(x1, x2, x0);
    Ciphertext x;
    evaluator.multiply(cipher_matrix[0][0], x0, x);
    Ciphertext y1;
    evaluator.multiply(cipher_matrix[1][0], cipher_matrix[2][2], y1);
    Ciphertext y2;
    evaluator.multiply(cipher_matrix[2][0], cipher_matrix[1][2], y2);
    Ciphertext y0;
    evaluator.sub(y1, y2, y0);
    Ciphertext y;
    evaluator.multiply(cipher_matrix[0][1], y0, y);
    Ciphertext z1;
    evaluator.multiply(cipher_matrix[1][0], cipher_matrix[2][1], z1);
    Ciphertext z2;
    evaluator.multiply(cipher_matrix[2][0], cipher_matrix[1][1], z2);
    Ciphertext z0;
    evaluator.sub(z1, z2, z0);
    Ciphertext z;
    evaluator.multiply(cipher_matrix[0][2], z0, z);
    Ciphertext determinant;
    evaluator.sub(x,y,determinant);
    Ciphertext cipher_result;
    evaluator.add(determinant,z,cipher_result);
    // Decrypt
    Plaintext plain_result;
    decryptor.decrypt(cipher_result, plain_result);
    // Decode
    vector<double> result_vec;
    ckks_encoder.decode(plain_result, result_vec);
    double result = result_vec[0];
    cout << "Resulting Determinant: " << result << endl;
}

int main()
{
    vector<vector<double>> matrix1(2, vector<double>(2));
    double filler = 1;
    for (int i = 0; i < 2; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            matrix1[i][j] = filler;
            filler++;
        }
    }
    cout << "Matrix 1:" << endl;
    print_matrix(matrix1, 0);
    Determinant(8192 * 2, matrix1);
    vector<vector<double>> matrix2(3, vector<double>(3));
    filler = 1;
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < 3; j++)
        {
            matrix2[i][j] = filler;
            filler++;
        }
    }    cout << "Matrix 2:" << endl;
    print_matrix(matrix2, 0);
    DeterminantByThree(8192 * 2, matrix2);
    return 0;
}
