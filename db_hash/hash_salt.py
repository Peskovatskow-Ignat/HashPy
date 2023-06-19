from itertools import product
from multiprocessing import Manager, Process
import os
import numpy as np
from Crypto.Hash import SHA1, SHA256, SHA224, SHA384, SHA512, SHA3_224, SHA3_384, SHAKE128, SHAKE256, keccak, BLAKE2b

alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()+'
salt = "student_494"


def brute_force_password(combinations, passwords_dict, hashes):
    counter = 0
    for combination in combinations:

        possible_password = ''.join(combination)
        pass_hash_SHA1 = SHA1.new((possible_password + salt).encode()).hexdigest()
        pass_hash_SHA256 = SHA256.new(possible_password.encode()).hexdigest()
        pass_hash_SHA224 = SHA224.new(possible_password.encode()).hexdigest()
        pass_hash_SHA384 = SHA384.new((possible_password+salt).encode()).hexdigest()
        pass_hash_SHA512_224 = SHA512.new(truncate="224")
        pass_hash_SHA512_224.update((possible_password + salt).encode())
        pass_hash_SHA512_256 = SHA512.new(truncate="256")
        pass_hash_SHA512_256.update(possible_password.encode())
        pass_hash_SHA3_224 = SHA3_224.new(possible_password.encode()).hexdigest()
        pass_hash_SHA3_384 = SHA3_384.new((possible_password + salt).encode()).hexdigest()
        pass_hash_SHAKE128 = SHAKE128.new().update(possible_password.encode()).read(32).hex()
        pass_hash_SHAKE256 = SHAKE256.new().update(possible_password.encode()).read(32).hex()
        pass_hash_keccak224 = keccak.new(digest_bits=224).update((possible_password+salt).encode())
        pass_hash_keccak256 = keccak.new(digest_bits=256).update((possible_password+salt).encode()).hexdigest()
        pass_hash_keccak384 = keccak.new(digest_bits=384).update(possible_password.encode()).hexdigest()
        pass_hash_keccak512 = keccak.new(digest_bits=512).update(possible_password.encode()).hexdigest()
        pass_hash_BLACKE2b_256 = BLAKE2b.new(digest_bits=256).update((possible_password+salt).encode()).hexdigest()
        pass_hash_BLACKE2b_512 = BLAKE2b.new(digest_bits=512).update(possible_password.encode()).hexdigest()

        counter += 1

        if counter % 100000 == 0:
            print(
                f'possible_password = {possible_password}, hash = {pass_hash_SHA512_224.hexdigest()}')

        if pass_hash_SHA512_224.hexdigest() in hashes:
            print("Password found.")
            with open("salted_password.txt", "a+") as f:
                f.writelines(
                    f"hash = {pass_hash_SHA512_224.hexdigest()}, password = {possible_password}, algorithm: SHA3_384\n")
            passwords_dict[pass_hash_SHA512_224.hexdigest()] = possible_password
            del hashes[pass_hash_SHA512_224.hexdigest()]
            break


if __name__ == "__main__":
    manager = Manager()
    hashes = manager.dict()
    hashes["7403f593da82bbe021dc58389884d7cdb891c6ee82e56d169c912015"] = None
    passwords_dict = manager.dict()
    pwd_length = 1
    while hashes:
        jobs = []
        combinations = list(product(alphabet, repeat=pwd_length))
        cpu_count = os.cpu_count()
        chunks = np.array_split(combinations, cpu_count)
        for chunk in chunks:
            p = Process(target=brute_force_password,
                        args=(chunk, passwords_dict, hashes))
            jobs.append(p)
            p.start()

        for process in jobs:
            process.join()

        pwd_length += 1
    print(passwords_dict)
