from Crypto.Hash import SHA1, SHA256, SHA224, SHA384, SHA512, SHA3_224, SHA3_384, SHAKE128, SHAKE256, keccak, BLAKE2b

possible_passwords = ["KWb(student_532"]
hashes = ["d3723da895f5d20e9cbfdf64124597f30ae18ef6b5a590023046b4061e316729"]

for possible_password in possible_passwords:

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
    pass_hash_keccak224 = keccak.new(digest_bits=224).update(possible_password.encode())
    pass_hash_keccak256 = keccak.new(digest_bits=256).update(possible_password.encode())
    pass_hash_keccak384 = keccak.new(digest_bits=384).update(possible_password.encode())
    pass_hash_keccak512 = keccak.new(digest_bits=512).update(possible_password.encode())
    pass_hash_BLACKE2b_256 = BLAKE2b.new(digest_bits=256).update(possible_password.encode()).hexdigest()
    pass_hash_BLACKE2b_512 = BLAKE2b.new(digest_bits=512).update(possible_password.encode()).hexdigest()

    for hashe in hashes:

        if hashe == pass_hash_SHA1:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA1 \n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHA256:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA256 \n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHA224:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA224\n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHA384:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA384\n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHA512_224.hexdigest():
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA512_224\n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHA512_256.hexdigest():
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA512_256\n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHA3_224:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA3_224\n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHA3_384:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA3_384\n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHAKE128:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SNAKE_128\n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHAKE256:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHAKE_256\n")
            print("found algorithm")
            break
        if hashe == pass_hash_keccak224.hexdigest():
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = keccak_224\n")
            print("found algorithm")
            break
        if hashe == pass_hash_keccak256.hexdigest():
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = keccak_256\n")
            print("found algorithm")
            break
        if hashe == pass_hash_keccak384.hexdigest():
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = keccak_384\n")
            print("found algorithm")
            break
        if hashe == pass_hash_keccak512.hexdigest():
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = keccak_512\n")
            print("found algorithm")
            break
        if hashe == pass_hash_BLACKE2b_256:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = BLACKE2b_256\n")
            print("found algorithm")
            break
        if hashe == pass_hash_BLACKE2b_512:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = BLACKE2b_512\n")
            print("found algorithm")
            break
        if hashe == pass_hash_SHA512:
            with open("aloritm.txt", "a+") as f:
                f.writelines(f"hash = {hashe}, password = {possible_password}, algorithm = SHA512\n")
            print("found algorithm")
