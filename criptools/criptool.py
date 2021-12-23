import hashlib
import string
import random
import binascii
from cryptography.fernet import Fernet
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes

def sha_512(data_to_hash):
	byte_hash = hashlib.new('sha512',data_to_hash)
	hex_hash = byte_hash.hexdigest()
	return hex_hash

def RSA_generator():
	private_key = RSA.generate(2048)
	public_key = private_key.publickey()
	keys = [private_key, public_key]
	return keys

def RSA_encrypt(text, key):
	msg = text.encode()
	cipherRSA = PKCS1_OAEP.new(key)
	encrypt_msg = cipherRSA.encrypt(msg)
	return binascii.hexlify(encrypt_msg).decode('utf-8')

def RSA_decrypt(crypt, key):
	crypt = binascii.unhexlify(crypt.encode('utf-8'))
	cipherRSA = PKCS1_OAEP.new(key)
	msg = cipherRSA.decrypt(crypt)
	return msg.decode('utf-8')

def RSA_key_cleaner(key):
	key = key.exportKey(format='DER')
	key = binascii.hexlify(key).decode('utf-8')
	return key

def RSA_key_format(key):
	key = RSA.importKey(binascii.unhexlify(key))
	return key

def randomize(length):
	key = ''
	dictionary = string.ascii_letters + string.digits + string.punctuation + string.ascii_uppercase
	for i in range(length):
		key += "".join(random.sample(dictionary,1))
	return key

def encrypt_aes(text):
	cipher = AES.new(bytes('load_key()123456'.encode('utf-8')), AES.MODE_EAX)
	ciphertext, tag = cipher.encrypt_and_digest(str(text))
	return ciphertext

def decrypt_AES(text):
	cipher = AES.new('load_key()123456', AES.MODE_EAX, nonce)
	data = cipher.decrypt_and_verify(ciphertext, tag)
	return

def fernet_encrypt(text):
	key = Fernet(load_key())
	cipher = key.encrypt(text).decode('utf-8')
	return cipher

def fernet_decrypt(text):
	key = Fernet(load_key())
	decipher = key.decrypt(text)
	return decipher

def load_server_key():
	try:
		ret = open ('criptools/server/server_key.key','rb').read()
	except:
		return 'False'
	return ret

def load_key(file):
	try:
		ret = open ('criptools/user/'+str(file)+'.key','rb').read()
		print(ret.decode('utf-8'))
	except:
		print('No se ha encontrado una llave válida para el servidor')
		return 'False'
	return ret

def key_generator():
	key = Fernet.generate_key()
	with open('criptools/clave.key','wb') as file:
		file.write(key)
	file.close()
	return key

def key_server_generator():
	key = Fernet.generate_key()
	with open('criptools/server/server_key.key','wb') as file:
		file.write(key)
	file.close()
	return key
