import os
from itertools import product
from multiprocessing import Manager, Process
from time import time

import numpy as np
from Crypto.Hash import SHA1, SHA256, SHA224, SHA384, SHA512, SHA3_224, SHA3_384, SHAKE128, SHAKE256, keccak, BLAKE2b

alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()+'
keys_list = [
    "bd7a198b8b92f4bca0d687d11cd6b6c94c3f85f14e0f5d0a83d2608275b703a7cadfa4c60e8f96be37e7bad999053a18c8ca9a9d9bea136f167d475b3ef5cc0c",
    "0d42cbc4939b23d6eef1c0bb53b68ecc374561c99fb854b64e78f73d8d95f3f8d7103216b94e1c1aa39d2cd99637c4ce42e1dee830afd57c6f48412185ddd09f"]

start = time()


def get_password(combinations, passwords_dict, hashs_dict):
    count = 0
    for combination in combinations:
        possible_password = ''.join(combination)
        pass_hash_SHA1 = SHA1.new(possible_password.encode()).hexdigest()
        pass_hash_SHA256 = SHA256.new(possible_password.encode()).hexdigest()
        pass_hash_SHA224 = SHA224.new(possible_password.encode()).hexdigest()
        pass_hash_SHA384 = SHA384.new(possible_password.encode()).hexdigest()
        pass_hash_SHA512 = SHA512.new(possible_password.encode()).hexdigest()
        pass_hash_SHA512_224 = SHA512.new(truncate="224")
        pass_hash_SHA512_224.update(possible_password.encode())
        pass_hash_SHA512_256 = SHA512.new(truncate="256")
        pass_hash_SHA512_256.update(possible_password.encode())
        pass_hash_SHA3_224 = SHA3_224.new(possible_password.encode()).hexdigest()
        pass_hash_SHA3_384 = SHA3_384.new(possible_password.encode()).hexdigest()
        pass_hash_SHAKE128 = SHAKE128.new().update(possible_password.encode()).read(32).hex()
        pass_hash_SHAKE256 = SHAKE256.new().update(possible_password.encode()).read(32).hex()
        pass_hash_keccak224 = keccak.new(digest_bits=224).update(possible_password.encode()).hexdigest()
        pass_hash_keccak256 = keccak.new(digest_bits=256).update(possible_password.encode()).hexdigest()
        pass_hash_keccak384 = keccak.new(digest_bits=384).update(possible_password.encode()).hexdigest()
        pass_hash_keccak512 = keccak.new(digest_bits=512).update(possible_password.encode()).hexdigest()
        pass_hash_BLACKE2b_256 = BLAKE2b.new(digest_bits=256).update(possible_password.encode()).hexdigest()
        pass_hash_BLACKE2b_512 = BLAKE2b.new(digest_bits=512).update(possible_password.encode()).hexdigest()

        if pass_hash_BLACKE2b_512 in hashs_dict:
            password_dict[
                pass_hash_BLACKE2b_512] = f'possible_password = {possible_password} and algorithm: BLACKE2b_512'
            with open("no_salt_hash.txt", "a+") as f:
                f.writelines(f'possible_password = {possible_password} and algorithm: BLACKE2b_512' + "\n")
            del hashs_dict[pass_hash_BLACKE2b_512]
            break
        if pass_hash_SHA512 in hashs_dict:
            password_dict[pass_hash_SHA512] = f'possible_password = {possible_password} and algorithm: SHA-512'
            with open("no_salt_hash.txt", "a+") as f:
                f.writelines(f'possible_password = {possible_password} and algorithm: SHA-512' + "\n")
            del hashs_dict[pass_hash_SHA512]
            break
        if pass_hash_SHA256 in hashs_dict:
            password_dict[pass_hash_SHA256] = f'possible_password = {possible_password} and algorithm: SHA-256'
            del hashs_dict[pass_hash_SHA256]
            break
        if pass_hash_SHA224 in hashs_dict:
            password_dict[pass_hash_SHA224] = f'possible_password = {possible_password} and algorithm: SHA-224'
            del hashs_dict[pass_hash_SHA224]
            break
        if pass_hash_SHA384 in hashs_dict:
            password_dict[pass_hash_SHA384] = f'possible_password = {possible_password} and algorithm: SHA-384'
            del hashs_dict[pass_hash_SHA384]
            break
        if pass_hash_SHA512_224.hexdigest() in hashs_dict:
            password_dict[
                pass_hash_SHA512_224.hexdigest()] = f'possible_password = {possible_password} and algorithm: SHA-512-224'
            del hashs_dict[pass_hash_SHA512_224.hexdigest()]
            break
        if pass_hash_SHA512_256.hexdigest() in hashs_dict:
            password_dict[
                pass_hash_SHA512_256.hexdigest()] = f'possible_password = {possible_password} and algorithm: SHA-512-256'
            del hashs_dict[pass_hash_SHA512_256.hexdigest()]
            break
        if pass_hash_SHA3_224 in hashs_dict:
            password_dict[pass_hash_SHA3_224] = f'possible_password = {possible_password} and algorithm: SHA3_224'
            del hashs_dict[pass_hash_SHA3_224]
            break
        if pass_hash_SHAKE256 in hashs_dict:
            password_dict[pass_hash_SHAKE256] = f'possible_password = {possible_password} and algorithm: SHAKE256'
            with open("no_salt_hash.txt", "a+") as f:
                f.writelines(f'possible_password = {possible_password} and algorithm: SHA-1' + "\n")
            del hashs_dict[pass_hash_SHAKE256]
            break
        if pass_hash_SHAKE128 in hashs_dict:
            password_dict[pass_hash_SHAKE128] = f'possible_password = {possible_password} and algorithm: SHAKE128'
            with open("no_salt_hash.txt", "a+") as f:
                f.writelines(f'possible_password = {possible_password} and algorithm: SHA-1' + "\n")
            del hashs_dict[pass_hash_SHAKE128]
            break
        if pass_hash_keccak224.hexdigest() in hashs_dict:
            print()
            password_dict[
                pass_hash_keccak224.hexdigest()] = f'possible_password = {possible_password} and algorithm: SHA-512-256'
            del hashs_dict[pass_hash_keccak224.hexdigest()]
            break
        if pass_hash_BLACKE2b_256 in hashs_dict:
            print()
            password_dict[
                pass_hash_BLACKE2b_256] = f'possible_password = {possible_password} and algorithm: SHA-512-256'
            del hashs_dict[pass_hash_BLACKE2b_256]
            break
        if pass_hash_BLACKE2b_512 in hashs_dict:
            print()
            password_dict[
                pass_hash_BLACKE2b_512] = f'possible_password = {possible_password} and algorithm: SHA-512-256'
            del hashs_dict[pass_hash_BLACKE2b_512]
            break


if __name__ == '__main__':
    print(len(alphabet))
    manager = Manager()
    password_dict = manager.dict()
    hashs_dict = manager.dict()
    for key in keys_list:
        hashs_dict[key] = None
    pwd_length = 0
    while hashs_dict:
        jobs = []
        combinations = list(product(alphabet, repeat=pwd_length))
        cpu_count = 1
        sub_combinations = np.array_split(combinations, cpu_count)
        for sub_combination in sub_combinations:
            p = Process(target=get_password, args=(sub_combination, password_dict, hashs_dict))
            jobs.append(p)
            p.start()
        for proc in jobs:
            proc.join()

        pwd_length += 1
        print(pwd_length)
        print(password_dict)
    end = time()
    print(end - start)
