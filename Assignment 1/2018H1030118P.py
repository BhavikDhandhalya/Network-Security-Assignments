"""
Bhavik Dhandhalya
2018H1030118P
Network Security G 513 Assignment
h20180118@pilani.bits-pilani.ac.in
"""

import sys
import collections

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
p_of_letters = [0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,0.06966,0.00153,0.00772,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,0.02758,0.00978,0.0236,0.0015,0.01974,0.00074]

def IOC(cipher_text):
	c_flat = ""

	for x in cipher_text: 
		if x.isalpha(): c_flat+=x.upper()

	N = len(c_flat)
	freqs = collections.Counter( c_flat )
	alphabet = map(chr, range(ord('A'), ord('Z') + 1))
	f_sum = 0.0

	# Do the math
	for letter in alphabet:
	    f_sum += freqs[letter] * (freqs[letter] - 1)

	IC = f_sum/(N * (N-1))
	return IC

def translateMessage(key, message, mode):
    translated = [] # stores the encrypted/decrypted message string
    keyRound = 0
    keyIndex = 0
    key = key.upper()

    for symbol in message: # loop through each character in message
        num = LETTERS.find(symbol.upper())
        if num != -1: # -1 means symbol.upper() was not found in LETTERS
            if mode == 'encrypt':
                num += LETTERS.find(key[keyIndex]) + keyRound 
            elif mode == 'decrypt':
                num -= LETTERS.find(key[keyIndex]) + keyRound 

            num %= len(LETTERS) 

            
            if symbol.isupper():
                translated.append(LETTERS[num])
            elif symbol.islower():
                translated.append(LETTERS[num].lower())

            keyIndex += 1 
            if keyIndex == len(key):
                keyIndex = 0
                keyRound += 1
        else:
            
            translated.append(symbol)

    return ''.join(translated)

# Reading from file
f = open("ciphertext", "r")
a = ""
for x in f:
	a += x
f.close()

key_length = 10
final_key = 0
p = ""
while (key_length > 0):
	ttext = ""
	p = ""
	key_round, cnt = 0, 0
	for x in a:
		num = LETTERS.find(x.upper())

		if num != -1:
			num -= (key_round % len(LETTERS))
			cnt += 1

			if x.isupper():
				if num < 0: num += len(LETTERS)
				num %= 26

			if cnt % key_length == 0: 
				key_round += 1
				ttext += LETTERS[num].upper()
			
			if x.isupper(): p += LETTERS[num]
			elif x.islower(): p += LETTERS[num].lower()
		else: p += x

	ioc = IOC(ttext)
	
	if (ioc >= 0.055):
		final_key = key_length
		break

	key_length -= 1

print "key length is : " + str(final_key)

p = p.upper()

our_key = ""
#lets find key
for i in range(key_length):
	cnt = 0
	match_char = i
	try_text = ""
	for x in p:
		num = LETTERS.find(x.upper())
		if num != -1 and cnt % final_key == match_char:
			try_text += x
		if num != -1: cnt += 1 #bahot mast error tha, 2 hours bigada mera :(

	freq_of_lettere = {}
	max_occ = 0
	for x in try_text:
		if x in freq_of_lettere: freq_of_lettere[x] += 1
		else: freq_of_lettere[x] = 1
		if freq_of_lettere[x] >= max_occ:
			max_occ = freq_of_lettere[x]
			max_char = x

	prob_of_text = [0.0] * 30
	for x in try_text:
		num = LETTERS.find(x.upper())
		prob_of_text[num] = (freq_of_lettere[x])*1.0 / len(try_text)

	max_prob = 0
	max_ind = -1
	for suff_i in range(26):
		cur_prob = 0
		for j in range(26):
			cur_prob += p_of_letters[j] * 1.0 * prob_of_text[(j + suff_i) % 26]
		if cur_prob > max_prob:
			max_prob = cur_prob
			max_ind = suff_i

	if max_ind != -1: our_key += LETTERS[max_ind]
	else: our_key += LETTERS[5]

print "our key is " + our_key

final_decrepted_text = translateMessage(our_key, a, 'decrypt')
#print final_decrepted_text
ff = open('plaintext', 'w')
ff.write(final_decrepted_text)
ff.close()