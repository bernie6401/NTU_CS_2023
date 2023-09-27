import numpy as np
from functools import reduce

def modMatInv(A,p):       # Finds the inverse of matrix A mod p
  n=len(A)
  A=np.matrix(A)
  adj=np.zeros(shape=(n,n))
  for i in range(0,n):
    for j in range(0,n):
      adj[i][j]=((-1)**(i+j)*int(round(np.linalg.det(minor(A,j,i)))))%p
  return (modInv(int(round(np.linalg.det(A))),p)*adj)%p

def modInv(a,p):          # Finds the inverse of a mod p, if it exists
  for i in range(1,p):
    if (i*a)%p==1:
      return i
  raise ValueError(str(a)+" has no inverse mod "+str(p))

def minor(A,i,j):    # Return matrix A with the ith row and jth column deleted
  A=np.array(A)
  minor=np.zeros(shape=(len(A)-1,len(A)-1))
  p=0
  for s in range(0,len(minor)):
    if p==i:
      p=p+1
    q=0
    for t in range(0,len(minor)):
      if q==j:
        q=q+1
      minor[s][t]=A[p][q]
      q=q+1
    p=p+1
  return minor

def mod_inverse(matrix, modulus):
    det = int(round(np.linalg.det(matrix))) % modulus
    det_inverse = pow(det, -1, modulus)
    adjugate = np.round(det_inverse * np.linalg.inv(matrix)).astype(int) % modulus
    return adjugate

def special_dot(m1, m2):
    mr = np.empty((m1.shape[0], m2.shape[1]), dtype = int)
    for i in range(mr.shape[0]):
        for j in range(mr.shape[1]):
            mr[i, j] = reduce(lambda x, y: x ^ y, (m1[i, :] & m2[:, j]))
    return mr

# Define the matrix (make sure it's square)
matrix = np.array([[1, 1, 0]])
matrix = np.vstack([matrix, np.array([0, 1, 1], dtype=int)])
matrix = np.vstack([matrix, np.array([1, 1, 1], dtype=int)])
modulus = 2

inverse_matrix = modMatInv(matrix, modulus)
print(inverse_matrix)
print(special_dot(np.array(inverse_matrix, dtype=int), np.array(matrix, dtype=int)))