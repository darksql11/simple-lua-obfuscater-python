import base64
import os
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import string

def random_name(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_key():
    raw = hashlib.sha256((str(os.urandom(16)) + str(random.randint(0, 1000000))).encode()).digest()
    return base64.b64encode(raw).decode('utf-8')

def xor_encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key * (len(data) // len(key) + 1)))

def aes_encrypt(data, key):
    cipher = AES.new(base64.b64decode(key), AES.MODE_CBC, iv=os.urandom(16))
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ct_bytes

lua_file = input("Which .lua file do you want to obfuscate? (example: script.lua): ")
if not os.path.exists(lua_file):
    print("Sorry couldnt find that file!")
    exit(1)

with open(lua_file, 'r', encoding='utf-8') as f:
    original_code = f.read()

xor_key1 = generate_key()
xor_key2 = generate_key()
aes_key1 = generate_key()
aes_key2 = generate_key()

xor_enc1 = xor_encrypt(original_code, xor_key1)
aes_enc1 = aes_encrypt(xor_enc1, aes_key1)
xor_enc2 = xor_encrypt(base64.b64encode(aes_enc1).decode(), xor_key2)
aes_enc2 = aes_encrypt(xor_enc2, aes_key2)
final_encrypted = base64.b64encode(aes_enc2).decode()

junk_code = ""
for _ in range(50):
    r1 = random_name()
    r2 = random_name()
    r3 = random_name()
    junk_func = f"local function {r1}({r2},{r3})local x='{random_name(20)}'return string.len(x)+{r2}*{r3}end "
    junk_code += junk_func

filler = ""
for _ in range(30):
    r4 = random_name()
    r5 = random_name()
    filler += f"local {r4}='{random_name(15)}' for i=1,10 do {r5}={r4}..i end "

obfuscated_lua = (
    f"{junk_code}{filler}local {random_name()}={{}}"
    f"local function {random_name()}(d,k)return ''.join(string.char(bit32.bxor(string.byte(d,i),string.byte(k,(i-1)%#k+1)))for i=1,#d)end "
    f"local function {random_name()}(e,k)local decoded=base64.decode(e)local iv=decoded:sub(1,16)local encrypted=decoded:sub(17)local cipher=AES.new(base64.decode(k),AES.MODE_CBC,iv=iv)return unpad(cipher.decrypt(encrypted),16)end "
    f"local xk1='{xor_key1}'local xk2='{xor_key2}'local ak1='{aes_key1}'local ak2='{aes_key2}'"
    f"local ed='{final_encrypted}'"
    f"local aes_dec2={random_name()}(ed,ak2)local xor_dec2={random_name()}(aes_dec2,xk2)"
    f"local aes_dec1={random_name()}(base64.decode(xor_dec2),ak1)local xor_dec1={random_name()}(aes_dec1,xk1)"
    f"loadstring(xor_dec1)()"
    f"local {random_name()}='{random_name(20)}'local {random_name()}='aB9kP2mX7QzW3e4R5tY6u7I8'"
)

output_file = os.path.join(os.path.dirname(lua_file), "obfuscated.lua")
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(obfuscated_lua.replace('\n', ''))

print(f"Done! Your obfuscated code is saved as '{output_file}'.")
