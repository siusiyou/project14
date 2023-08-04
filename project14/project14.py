from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from gmssl import sm2, func

def generate_key_pair():
    # 生成SM2公私钥对
    private_key = sm2.gen_private_key()
    public_key = sm2.get_public_key(private_key)
    return private_key, public_key

def encrypt(plaintext, public_key):
    # 生成AES密钥
    aes_key = func.random_bytes(16)  # 使用16字节作为AES密钥

    # 使用AES对称密码进行加密
    cipher = AES.new(aes_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    # 使用SM2公钥加密AES密钥
    encrypted_aes_key = sm2.sm2_crypt(sm2.C1C2C3_CIPHERTEXT, public_key, aes_key)
    return ciphertext, encrypted_aes_key

def decrypt(ciphertext, private_key, encrypted_aes_key):
    # 解密过程
    decrypted_aes_key = sm2.sm2_decrypt(sm2.C1C2C3_CIPHERTEXT, private_key, encrypted_aes_key)
    decipher = AES.new(decrypted_aes_key, AES.MODE_ECB)
    decrypted_plaintext = decipher.decrypt(ciphertext)
    return decrypted_plaintext.decode()

def sign_message(message, private_key):
    # 使用SHA256哈希和SM2私钥对消息进行签名
    hash_obj = SHA256.new(message)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature

def verify_signature(message, signature, public_key):
    # 使用SHA256哈希和SM2公钥验证签名
    hash_obj = SHA256.new(message)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False

# 生成SM2公私钥对
private_key, public_key = generate_key_pair()

# 待加密的明文数据
plaintext = b'This is a secret message.'

# 加密过程
ciphertext, encrypted_aes_key = encrypt(plaintext, public_key)

print("加密后的数据：", ciphertext)
print("解密后的数据：", decrypt(ciphertext, private_key, encrypted_aes_key))

# 待签名的消息
message = b'This is the message to be signed.'

# 签名过程
signature = sign_message(message, private_key)

# 验证签名过程
is_valid = verify_signature(message, signature, public_key)

print("签名是否有效：", is_valid)
