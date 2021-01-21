#include <iostream>
#include <cfloat>
#include <limits>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

/*
Initialize new matrix:
= reserve memory only
*/
template <typename T>
vector<vector<T>> initMatrix(unsigned int width, unsigned int height)
{
    vector<vector<T>> init_matrix(height, vector<T>(width));
    return init_matrix;
}

/*
Initialize new matrix:
= reserve memory
= set any value to 0
*/
vector<vector<int>> initMatrixZero(unsigned int width, unsigned int height)
{
    vector<vector<int>> init_matrix_zero(height, vector<int>(width));
    for(int i = 0; i < init_matrix_zero.size(); i++)
    {
        for(int j = 0; j < init_matrix_zero[0].size(); j++)
        {
            init_matrix_zero[i][j] = 0;
        }
    }
    return init_matrix_zero;
}

/*
Initialize new matrix:
= reserve memory
= set any value to random number
*/
vector<vector<double>> initMatrixRand(unsigned int width, unsigned int height)
{
    vector<vector<double>> init_matrix_rand(height, vector<double>(width));
    double r = (double)rand() / (RAND_MAX + 1.0);
    for(int i = 0; i < init_matrix_rand.size(); i++)
    {
        for(int j = 0; j < init_matrix_rand[0].size(); j++)
        {
            init_matrix_rand[i][j] = r*10.0;
            r = ((double)rand() / (RAND_MAX + 1.0));
        }
    }
    return init_matrix_rand;
}

/*
copy a matrix and return its copy
*/
template <typename T>
vector<vector<T>> copyMatrix(vector<vector<T>> toCopy)
{
    vector<vector<T>> copy_matrix(toCopy.size(), vector<T>(toCopy[0].size()));
    for(int i = 0; i < copy_matrix.size(); i++)
    {
        for(int j = 0; j < copy_matrix[0].size(); j++)
        {
            copy_matrix[i][j] = toCopy[i][j];
        }
    }
    return copy_matrix;
}

/*
destroy matrix
= free memory
= set any remaining value to NULL
*/
template <typename T>
void freeMatrix(vector<vector<T>> toDestroy)
{
    toDestroy.clear();
    toDestroy.shrink_to_fit();
}

/*
return entry at position (xPos , yPos) , DBLMAX in case of error
*/
double getEntryAt(vector<vector<double>> a, unsigned int xPos, unsigned int yPos)
{
    if(xPos >= a.size())
    {
        return DBL_MAX;
    }
    if(yPos >= a[0].size())
    {
        return DBL_MAX;
    }
    return a[xPos][yPos];
}

/*
set entry at position (xPos , yPos)
return true in case of success, false otherwise
*/
bool setEntryAt(vector<vector<double>> a, unsigned int xPos, unsigned int yPos, double value)
{
    if(xPos >= a.size())
    {
        return false;
    }
    if(yPos >= a[0].size())
    {
        return false;
    }
    a[xPos][yPos] = value;
    return true;
}

// Print function that prints a matrix (vector of vectors)
template <typename T>
inline void print_matrix(vector<vector<T>> matrix, int precision)
{
    // archieve formatting for cout
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(precision);
    int row_size = matrix.size();
    int col_size = matrix[0].size();
    for (unsigned int i = 0; i < row_size; i++)
    {
        cout << "[";
        for (unsigned int j = 0; j < col_size - 1; j++)
        {
            cout << matrix[i][j] << ", ";
        }
        cout << matrix[i][col_size - 1];
        cout << "]" << endl;
    }
    cout << endl;
    // restore old cout formatting
    cout.copyfmt(old_fmt);
}

// Gets a diagonal from a matrix U
template <typename T>
vector<T> get_diagonal(int position, vector<vector<T>> U)
{
    vector<T> diagonal(U.size());
    int k = 0;
    for (int i = 0, j = position; (i < U.size() - position) && (j < U.size()); i++, j++)
    {
        diagonal[k] = U[i][j];
        k++;
    }
    for (int i = U.size() - position, j = 0; (i < U.size()) && (j < position); i++, j++)
    {
        diagonal[k] = U[i][j];
        k++;
    }
    return diagonal;
}

// Gets all diagonals from a matrix U into a matrix
template <typename T>
vector<vector<T>> get_all_diagonals(vector<vector<T>> U)
{
    vector<vector<T>> diagonal_matrix(U.size());
    for (int i = 0; i < U.size(); i++)
    {
        diagonal_matrix[i] = get_diagonal(i, U);
    }
    return diagonal_matrix;
}

template <typename T>
vector<vector<double>> get_matrix_of_ones(int position, vector<vector<T>> U)
{
    vector<vector<double>> diagonal_of_ones(U.size(), vector<double>(U.size()));
    vector<T> U_diag = get_diagonal(position, U);
    int k = 0;
    for (int i = 0; i < U.size(); i++)
    {
        for (int j = 0; j < U.size(); j++)
        {
            if (U[i][j] == U_diag[k])
            {
                diagonal_of_ones[i][j] = 1;
            }
            else
            {
                diagonal_of_ones[i][j] = 0;
            }
        }
        k++;
    }
    return diagonal_of_ones;
}

template <typename T>
vector<double> pad_zero(int offset, vector<T> U_vec)
{
    vector<double> result_vec(pow(U_vec.size(), 2));
    for (int i = 0; i < offset; i++)
    {
        result_vec[i] = 0;
    }
    for (int i = 0; i < U_vec.size(); i++)
    {
        result_vec[i + offset] = U_vec[i];
    }
    for (int i = offset + U_vec.size(); i < result_vec.size(); i++)
    {
        result_vec[i] = 0;
    }
    return result_vec;
}

// Encodes Ciphertext Matrix into a single vector (Row ordering of a matix)
Ciphertext C_Matrix_Encode(vector<Ciphertext> matrix, GaloisKeys gal_keys, Evaluator &evaluator)
{
    Ciphertext ct_result;
    int dimension = matrix.size();
    vector<Ciphertext> ct_rots(dimension);
    ct_rots[0] = matrix[0];
    for (int i = 1; i < dimension; i++)
    {
        evaluator.rotate_vector(matrix[i], (i * -dimension), gal_keys, ct_rots[i]);
    }
    evaluator.add_many(ct_rots, ct_result);
    return ct_result;
}

// Linear Transformation function between ciphertext matrix and ciphertext vector
Ciphertext Linear_Transform_Cipher(Ciphertext ct, vector<Ciphertext> U_diagonals, GaloisKeys gal_keys, Evaluator &evaluator)
{
    Ciphertext ct_rot;
    evaluator.rotate_vector(ct, -U_diagonals.size(), gal_keys, ct_rot);
    Ciphertext ct_new;
    evaluator.add(ct, ct_rot, ct_new);
    vector<Ciphertext> ct_result(U_diagonals.size());
    evaluator.multiply(ct_new, U_diagonals[0], ct_result[0]);
    for (int l = 1; l < U_diagonals.size(); l++)
    {
        Ciphertext temp_rot;
        evaluator.rotate_vector(ct_new, l, gal_keys, temp_rot);
        evaluator.multiply(temp_rot, U_diagonals[l], ct_result[l]);
    }
    Ciphertext ct_prime;
    evaluator.add_many(ct_result, ct_prime);
    return ct_prime;
}

// U_transpose
template <typename T>
vector<vector<double>> get_U_transpose(vector<vector<T>> U)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> U_transpose(dimensionSq, vector<double>(dimensionSq));
    int tranposed_row = 0;
    for (int i = 0; i < dimension; i++)
    {
        vector<vector<double>> one_matrix = get_matrix_of_ones(i, U);
        for (int offset = 0; offset < dimension; offset++)
        {
            vector<double> temp_fill = pad_zero(offset * dimension, one_matrix[0]);
            U_transpose[tranposed_row] = temp_fill;
            tranposed_row++;
        }
    }
    return U_transpose;
}

// U_sigma
template <typename T>
vector<vector<double>> get_U_sigma(vector<vector<T>> U)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> U_sigma(dimensionSq, vector<double>(dimensionSq));
    int k = 0;
    int sigma_row = 0;
    for (int offset = 0; offset < dimensionSq; offset += dimension)
    {
        vector<vector<double>> one_matrix = get_matrix_of_ones(k, U);
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            vector<double> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
            U_sigma[sigma_row] = temp_fill;
            sigma_row++;
        }
        k++;
    }
    return U_sigma;
}

// U_tau
template <typename T>
vector<vector<double>> get_U_tau(vector<vector<T>> U)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> U_tau(dimensionSq, vector<double>(dimensionSq));
    int tau_row = 0;
    for (int i = 0; i < dimension; i++)
    {
        vector<vector<double>> one_matrix = get_matrix_of_ones(0, U);
        int offset = i * dimension;
        for (int j = 0; j < dimension; j++)
        {
            vector<double> temp_fill = pad_zero(offset, one_matrix[j]);
            U_tau[tau_row] = temp_fill;
            tau_row++;
            if (offset + dimension == dimensionSq)
            {
                offset = 0;
            }
            else
            {
                offset += dimension;
            }
        }
    }
    return U_tau;
}

// V_k
template <typename T>
vector<vector<double>> get_V_k(vector<vector<T>> U, int k)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> V_k(dimensionSq, vector<double>(dimensionSq));
    int V_row = 0;
    for (int offset = 0; offset < dimensionSq; offset += dimension)
    {
        vector<vector<double>> one_matrix = get_matrix_of_ones(k, U);
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            vector<double> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
            V_k[V_row] = temp_fill;
            V_row++;
        }
    }
    return V_k;
}

// W_k
template <typename T>
vector<vector<double>> get_W_k(vector<vector<T>> U, int k)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> W_k(dimensionSq, vector<double>(dimensionSq));
    int W_row = 0;
    vector<vector<double>> one_matrix = get_matrix_of_ones(0, U);
    int offset = k * dimension;
    for (int i = 0; i < dimension; i++)
    {
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            vector<double> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
            W_k[W_row] = temp_fill;
            W_row++;
        }
        if (offset + dimension == dimensionSq)
        {
            offset = 0;
        }
        else
        {
            offset += dimension;
        }
    }
    return W_k;
}
