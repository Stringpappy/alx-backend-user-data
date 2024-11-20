#!/usedef rotate_2d_matrix(matrix):
    """vfunc that rotate a matrix in 90degree"""                                              n = len(matrix)                                                                           for i in range(n):
      7666  for j in range(i + 1, n):
            matrix[i][j], matrix[j][i] = matrix[j][i], matrix[i][j]

    for i in range(n):
        matrix[i]

    for matris in matrix:
        print(matris)
