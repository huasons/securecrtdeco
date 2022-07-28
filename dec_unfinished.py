#!/usr/bin/env python
#from asyncio.windows_events import NULL
import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, Blowfish
import re
import sys

class SecureCRTCrypto:

    def __init__(self):
        '''
        Initialize SecureCRTCrypto object.
        '''
        self.IV = b'\x00' * Blowfish.block_size
        self.Key1 = b'\x24\xA6\x3D\xDE\x5B\xD3\xB3\x82\x9C\x7E\x06\xF4\x08\x16\xAA\x07'
        self.Key2 = b'\x5F\xB0\x45\xA2\x94\x17\xD9\x16\xC6\xC6\xA2\xFF\x06\x41\x82\xB7'

    def Encrypt(self, Plaintext : str):
        '''
        Encrypt plaintext and return corresponding ciphertext.

        Args:
            Plaintext: A string that will be encrypted.

        Returns:
            Hexlified ciphertext string.
        '''
        plain_bytes = Plaintext.encode('utf-16-le')
        plain_bytes += b'\x00\x00'
        padded_plain_bytes = plain_bytes + os.urandom(Blowfish.block_size - len(plain_bytes) % Blowfish.block_size)

        cipher1 = Blowfish.new(self.Key1, Blowfish.MODE_CBC, iv = self.IV)
        cipher2 = Blowfish.new(self.Key2, Blowfish.MODE_CBC, iv = self.IV)
        return cipher1.encrypt(os.urandom(4) + cipher2.encrypt(padded_plain_bytes) + os.urandom(4)).hex()

    def Decrypt(self, Ciphertext : str):
        '''
        Decrypt ciphertext and return corresponding plaintext.

        Args:
            Ciphertext: A hex string that will be decrypted.

        Returns:
            Plaintext string.
        '''

        cipher1 = Blowfish.new(self.Key1, Blowfish.MODE_CBC, iv = self.IV)
        cipher2 = Blowfish.new(self.Key2, Blowfish.MODE_CBC, iv = self.IV)
        ciphered_bytes = bytes.fromhex(Ciphertext)
        if len(ciphered_bytes) <= 8:
            raise ValueError('Invalid Ciphertext.')
        
        padded_plain_bytes = cipher2.decrypt(cipher1.decrypt(ciphered_bytes)[4:-4])
        
        i = 0
        for i in range(0, len(padded_plain_bytes), 2):
            if padded_plain_bytes[i] == 0 and padded_plain_bytes[i + 1] == 0:
                break
        plain_bytes = padded_plain_bytes[0:i]

        try:
            return plain_bytes.decode('utf-16-le')
        except UnicodeDecodeError:
            raise(ValueError('Invalid Ciphertext.'))

class SecureCRTCryptoV2:

    def __init__(self, ConfigPassphrase : str = ''):
        '''
        Initialize SecureCRTCryptoV2 object.

        Args:
            ConfigPassphrase: The config passphrase that SecureCRT uses. Leave it empty if config passphrase is not set.
        '''
        self.IV = b'\x00' * AES.block_size
        self.Key = SHA256.new(ConfigPassphrase.encode('utf-8')).digest()

    def Encrypt(self, Plaintext : str):
        '''
        Encrypt plaintext and return corresponding ciphertext.

        Args:
            Plaintext: A string that will be encrypted.

        Returns:
            Hexlified ciphertext string.
        '''
        plain_bytes = Plaintext.encode('utf-8')
        if len(plain_bytes) > 0xffffffff:
            raise OverflowError('Plaintext is too long.')
        
        plain_bytes = \
            len(plain_bytes).to_bytes(4, 'little') + \
            plain_bytes + \
            SHA256.new(plain_bytes).digest()
        padded_plain_bytes = \
            plain_bytes + \
            os.urandom(AES.block_size - len(plain_bytes) % AES.block_size)
        cipher = AES.new(self.Key, AES.MODE_CBC, iv = self.IV)
        return cipher.encrypt(padded_plain_bytes).hex()

    def Decrypt(self, Ciphertext : str):
        '''
        Decrypt ciphertext and return corresponding plaintext.

        Args:
            Ciphertext: A hex string that will be decrypted.

        Returns:
            Plaintext string.
        '''
        cipher = AES.new(self.Key, AES.MODE_CBC, iv = self.IV)
        padded_plain_bytes = cipher.decrypt(bytes.fromhex(Ciphertext))
        
        plain_bytes_length = int.from_bytes(padded_plain_bytes[0:4], 'little')
        plain_bytes = padded_plain_bytes[4:4 + plain_bytes_length]
        if len(plain_bytes) != plain_bytes_length:
            raise ValueError('Invalid Ciphertext.')

        plain_bytes_digest = padded_plain_bytes[4 + plain_bytes_length:4 + plain_bytes_length + SHA256.digest_size]
        if len(plain_bytes_digest) != SHA256.digest_size:
            raise ValueError('Invalid Ciphertext.')

        if SHA256.new(plain_bytes).digest() != plain_bytes_digest:
            raise ValueError('Invalid Ciphertext.')

        return plain_bytes.decode('utf-8')

def EncryptionRoutine(UseV2 : bool, ConfigPassphrase : str, Plaintext : str):
        try:
            if UseV2:
                print(SecureCRTCryptoV2(ConfigPassphrase).Encrypt(Plaintext))
            else:
                print(SecureCRTCrypto().Encrypt(Plaintext))
            return True
        except:
            print('Error: Failed to encrypt.')
            return False

def DecryptionRoutine(UseV2 : bool, ConfigPassphrase : str, Ciphertext : str):
        try:
            if UseV2:
                print(SecureCRTCryptoV2(ConfigPassphrase).Decrypt(Ciphertext))
            else:
                #print(SecureCRTCrypto().Decrypt(Ciphertext))
                return SecureCRTCrypto().Decrypt(Ciphertext)
            return True
        except:
            print('Error: Failed to decrypt.')
            return False

def decrypt(Ciphertext):        
    cipher = AES.new(SHA256.new('').digest(), AES.MODE_CBC, b'\x00' * AES.block_size)
    padded_plain_bytes = cipher.decrypt(bytes.fromhex(Ciphertext))
    plain_bytes_length = int.from_bytes(padded_plain_bytes[0:4], 'little')
    plain_bytes = padded_plain_bytes[4:4 + plain_bytes_length]
    if len(plain_bytes) != plain_bytes_length:
        raise ValueError('Invalid Ciphertext.')

    plain_bytes_digest = padded_plain_bytes[4 + plain_bytes_length:4 + plain_bytes_length + SHA256.digest_size]
    if len(plain_bytes_digest) != SHA256.digest_size:
        raise ValueError('Invalid Ciphertext.')

    if SHA256.new(plain_bytes).digest() != plain_bytes_digest:
        raise ValueError('Invalid Ciphertext.')
    return plain_bytes.decode('utf-8')


def dirlist(path, allfile):  
    filelist =  os.listdir(path)  
    for filename in filelist:  
        filepath = os.path.join(path, filename)  
        if os.path.isdir(filepath):  
            dirlist(filepath, allfile)  
        else:
            if (filepath.endswith('.ini')):
                allfile.append(filepath)  
    return allfile  



if __name__ == '__main__':
    aa = dirlist("/home/kali/Desktop/tools/llll", [])
    f2 = open("output.txt",'w')
    for entry in aa:
        print(entry)
        with open(entry,'r') as f:
            try:
                data = f.read()
            except:
                continue
            try:
                hostname = re.compile(r'S:"Hostname"=([^\r\n]*)').search(data).group(1)
                port  = int(re.compile(r'D:"\[SSH2\] Port"=([0-9a-f]{8})').search(data).group(1),16)
                username = re.compile(r'S:"Username"=([^\r\n]*)').search(data).group(1)
                passwordcif = re.compile(r'"Password.*?"=(.+)').search(data).group(1)[1:]
    #passwd = decrypt(re.compile(r'"Password.*?"=(.+)').search(data).group(1)[1:])
                passwd = DecryptionRoutine(False, "", passwordcif)
                print(entry + "   success")
                f2.write('%s\t%s\t%s\t%s\n'%(hostname,port,username,passwd))
            #print('\nDecrypt Result:\n\nhostname:%s\nport:%s\nusername:%s\npassword:%s\n'%(hostname,port,username,passwd))
            except:
            #raise
                print(entry + "   faied")
            '''
        try:       
            #print('\nDecrypt Result:\n\nhostname:%s\nport:%s\nusername:%s\npassword:%s\n'%(hostname,port,username,passwd))
            print("1")
        except:
            continue
        '''
