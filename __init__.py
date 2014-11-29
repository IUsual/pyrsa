#!/usr/bin/python
# -*- coding:utf-8 -*-

"""
	Easy RSA encryption.

	@Author Usual@Nuaa
	@date Nov 16, 20134
"""

from math import log
from random import choice

class KeyGenerator(object):
	"""
		RSA key generator.
	"""

	def __init__(self, length = 100):
		if length < 3: E = 3
		elif length < 10: E = 17
		else: E = 65537

		P, Q = self.getBigPrime(length), self.getBigPrime(length)

		N, S = P * Q, (P - 1) * (Q - 1)

		D = self.getInverse(E, S)

		self.PUBLIC = {'E': E, 'N': N}
		self.PRIVE = {'D': D, 'N': N}

	def getInverse(self, a, n):
		"""
			Extend Euclid.
		"""
		X = (1, 0, n)
		Y = (0, 1, a)

		while True:

			if Y[2] == 0: return False
			if Y[2] == 1: return Y[1] % n

			Q = int(X[2] / Y[2])

			T = [X[i] - Q * Y[i] for i in range(3)]

			X, Y = Y, T

	def getBigNum(self, length = 100):
		return int("".join([choice("01234567890") for i in range(length)]))

	def getBigPrime(self, length = 100):
		return self.NextPrime(self.getBigNum(length))

	def NextPrime(self, num):
		""" Get a prime after num."""
		if num % 2 == 0: num += 1

		while(not self.isPrime(num)):
			num += 2
		return num

	def isPrime(self, num):
		""" Judge whether num is a prime."""

		for i in range(num - int(log(num)) / 2 - 1, num):
			if (self.witness(num, i)):
				return False

		return True

	def witness(self, n, a):
		"""
			- False: Maybe a prime.
			- True: Must not a prime.
		"""
		b = self.getBinary(n - 1)
		d = 1

		for i in b:
			x, d = d, (d * d) % n

			if d == 1 and x != 1 and x != n - 1:
				return True
			if i == 1:
				d = (d * a) % n

		if d != 1:
			return True
		else:
			return False

	def getBinary(self, n):
		return map(int, bin(n)[2:])

class EasyRSA(object):
	"""
		RSA encrypt class.
	"""

	def getKeys(self, length = 100):
		self.KEY = KeyGenerator(length)
		return {"PRIVE":self.KEY.PRIVE, "PUBLIC":self.KEY.PUBLIC}

	def encrypt(self, plain, pubkey):
		return [v ** pubkey['E'] % pubkey['N'] for v in map(ord, plain)]

	def decrypt(self, cipher, prikey):
		return "".join(map(chr, [v ** prikey['D'] % prikey['N'] for v in cipher]))

rsa = EasyRSA()

print "Plain:\t",
plain = "Hello world!"
print plain

print "Genera keys:\t",
key = rsa.getKeys(3)
print key

print "Encrypt plain:\t",
cipher = rsa.encrypt(plain, key['PUBLIC'])
print cipher

print "Decrypt cipher:\t",
print rsa.decrypt(cipher, key['PRIVE'])