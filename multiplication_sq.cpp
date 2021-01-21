// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"
#include "13b_MS-SEAL.h"

using namespace std;
using namespace seal;

Ciphertext CC_Matrix_Multiplication(Ciphertext ctA, Ciphertext ctB, int dimension, vector<Ciphertext> U_sigma_diagonals_cipher, vector<Ciphertext> U_tau_diagonals_cipher, vector<vector<Ciphertext>> V_k_diagonals_cipher, vector<vector<Ciphertext>> W_k_diagonals_cipher, GaloisKeys gal_keys, RelinKeys relin_keys, EncryptionParameters params)
{
    SEALContext context(params);
    Evaluator evaluator(context);
    vector<Ciphertext> ctA_result(dimension);
    vector<Ciphertext> ctB_result(dimension);
    //Step 1
    ctA_result[0] = Linear_Transform_Cipher(ctA, U_sigma_diagonals_cipher, gal_keys, evaluator);
    evaluator.relinearize_inplace(ctA_result[0], relin_keys);
    ctB_result[0] = Linear_Transform_Cipher(ctB, U_tau_diagonals_cipher, gal_keys, evaluator);
    evaluator.relinearize_inplace(ctB_result[0], relin_keys);
    // Step 2
    for (int k = 1; k < dimension; k++)
    {
        ctA_result[k] = Linear_Transform_Cipher(ctA_result[0], V_k_diagonals_cipher[k - 1], gal_keys, evaluator);
        ctB_result[k] = Linear_Transform_Cipher(ctB_result[0], W_k_diagonals_cipher[k - 1], gal_keys, evaluator);
    }
    // Step 3
    for (int i = 1; i < dimension; i++)
    {
        evaluator.rescale_to_next_inplace(ctA_result[i]);
        evaluator.rescale_to_next_inplace(ctB_result[i]);
    }
    Ciphertext ctAB;
    evaluator.multiply(ctA_result[0], ctB_result[0], ctAB);
    // Mod switch CTAB
    evaluator.mod_switch_to_next_inplace(ctAB);
    // Manual scale set
    for (int i = 1; i < dimension; i++)
    {
        ctA_result[i].scale() = pow(2, (int)log2(ctA_result[i].scale()));
        ctB_result[i].scale() = pow(2, (int)log2(ctB_result[i].scale()));
    }
    for (int k = 1; k < dimension; k++)
    {
        Ciphertext temp_mul;
        evaluator.multiply(ctA_result[k], ctB_result[k], temp_mul);
        evaluator.add_inplace(ctAB, temp_mul);
    }
    return ctAB;
}
    
void Matrix_Multiplication_Sq(size_t poly_modulus_degree, vector<vector<double>> matrix1, vector<vector<double>> matrix2)
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
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);
    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);
    // Create Scale
    double scale = pow(2.0, 40);
    int dimension = matrix1.size();
    int dimensionSq = pow(dimension, 2);
    // Get U_sigma for first matrix
    vector<vector<double>> U_sigma = get_U_sigma(matrix1);
    cout << "\nU_sigma:" << endl;
    print_matrix(U_sigma, 0);
    // Get U_tau for second matrix
    vector<vector<double>> U_tau = get_U_tau(matrix1);
    cout << "\nU_tau:" << endl;
    print_matrix(U_tau, 0);
    // Get V_k (3D matrix)
    vector<vector<vector<double>>> V_k(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));
    for (int i = 1; i < dimension; i++)
    {
        V_k[i - 1] = get_V_k(matrix1, i);
        cout << "\nV_" << to_string(i) << ":" << endl;
        print_matrix(V_k[i - 1], 0);
    }
    // Get W_k (3D matrix)
    vector<vector<vector<double>>> W_k(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));
    for (int i = 1; i < dimension; i++)
    {
        W_k[i - 1] = get_W_k(matrix1, i);
        cout << "\nW_" << to_string(i) << ":" << endl;
        print_matrix(W_k[i - 1], 0);
    }
    
    // Get Diagonals for U_sigma
    vector<vector<double>> U_sigma_diagonals = get_all_diagonals(U_sigma);
    // Get Diagonals for U_tau
    vector<vector<double>> U_tau_diagonals = get_all_diagonals(U_tau);
    // Get Diagonals for V_k
    vector<vector<vector<double>>> V_k_diagonals(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));
    for (int i = 1; i < dimension; i++)
    {
        V_k_diagonals[i - 1] = get_all_diagonals(V_k[i - 1]);
    }
    // Get Diagonals for W_k
    vector<vector<vector<double>>> W_k_diagonals(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));
    for (int i = 1; i < dimension; i++)
    {
        W_k_diagonals[i - 1] = get_all_diagonals(W_k[i - 1]);
    }
    // --------------- ENCODING ----------------
    // Encode U_sigma diagonals
    vector<Plaintext> U_sigma_diagonals_plain(dimensionSq);
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_sigma_diagonals[i], scale, U_sigma_diagonals_plain[i]);
    }
    // Encode U_tau diagonals
    vector<Plaintext> U_tau_diagonals_plain(dimensionSq);
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_tau_diagonals[i], scale, U_tau_diagonals_plain[i]);
    }
    // Encode V_k diagonals
    vector<vector<Plaintext>> V_k_diagonals_plain(dimension - 1, vector<Plaintext>(dimensionSq));
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            ckks_encoder.encode(V_k_diagonals[i - 1][j], scale, V_k_diagonals_plain[i - 1][j]);
        }
    }
    // Encode W_k
    vector<vector<Plaintext>> W_k_diagonals_plain(dimension - 1, vector<Plaintext>(dimensionSq));
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            ckks_encoder.encode(W_k_diagonals[i - 1][j], scale, W_k_diagonals_plain[i - 1][j]);
        }
    }
    // Encode Matrices
    // Encode Matrix 1
    vector<Plaintext> plain_matrix1_set1(dimension);
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(matrix1[i], scale, plain_matrix1_set1[i]);
    }
    // Encode Matrix 2
    vector<Plaintext> plain_matrix2_set1(dimension);
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(matrix2[i], scale, plain_matrix2_set1[i]);
    }
    // --------------- ENCRYPTING ----------------
    // Encrypt U_sigma diagonals
    vector<Ciphertext> U_sigma_diagonals_cipher(dimensionSq);
    for (int i = 0; i < dimensionSq; i++)
    {
        encryptor.encrypt(U_sigma_diagonals_plain[i], U_sigma_diagonals_cipher[i]);
    }
    // Encrypt U_tau diagonals
    vector<Ciphertext> U_tau_diagonals_cipher(dimensionSq);
    for (int i = 0; i < dimensionSq; i++)
    {
        encryptor.encrypt(U_tau_diagonals_plain[i], U_tau_diagonals_cipher[i]);
    }
    // Encrypt V_k diagonals
    vector<vector<Ciphertext>> V_k_diagonals_cipher(dimension - 1, vector<Ciphertext>(dimensionSq));
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            encryptor.encrypt(V_k_diagonals_plain[i - 1][j], V_k_diagonals_cipher[i - 1][j]);
        }
    }
    // Encrypt W_k
    vector<vector<Ciphertext>> W_k_diagonals_cipher(dimension - 1, vector<Ciphertext>(dimensionSq));
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            encryptor.encrypt(W_k_diagonals_plain[i - 1][j], W_k_diagonals_cipher[i - 1][j]);
        }
    }
    // Encrypt Matrix 1
    vector<Ciphertext> cipher_matrix1_set1(dimension);
    for (int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix1_set1[i], cipher_matrix1_set1[i]);
    }
    // Encrypt Matrix 2
    vector<Ciphertext> cipher_matrix2_set1(dimension);
    for (int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix2_set1[i], cipher_matrix2_set1[i]);
    }
    // --------------- MATRIX ENCODING ----------------
    // Matrix Encode Matrix 1
    Ciphertext cipher_encoded_matrix1_set1 = C_Matrix_Encode(cipher_matrix1_set1, gal_keys, evaluator);
    // Matrix Encode Matrix 2
    Ciphertext cipher_encoded_matrix2_set1 = C_Matrix_Encode(cipher_matrix2_set1, gal_keys, evaluator);
    // --------------- MATRIX MULTIPLICATION ----------------
    Ciphertext ct_result = CC_Matrix_Multiplication(cipher_encoded_matrix1_set1, cipher_encoded_matrix2_set1, dimension, U_sigma_diagonals_cipher, U_tau_diagonals_cipher, V_k_diagonals_cipher, W_k_diagonals_cipher, gal_keys, relin_keys, params);
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
    int dimension = 4;
    vector<vector<double>> matrix1 = initMatrixRand(dimension, dimension);
    cout << "Matrix 1:" << endl;
    print_matrix(matrix1,2);
    vector<vector<double>> matrix2 = initMatrixRand(dimension, dimension);
    cout << "Matrix 2:" << endl;
    print_matrix(matrix2,2);
    Matrix_Multiplication_Sq(8192 * 2, matrix1, matrix2);
    return 0;
}
