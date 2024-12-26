from flask import Flask, request, render_template, send_from_directory
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64

app = Flask(__name__)

# Hashing the message using SHA-256
def sha256_hash(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode())
    return digest.finalize()

# AES-256 encryption function
def aes256_encrypt(message, key):
    iv = urandom(16)  # Generate random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# ChaCha20 encryption function
def chacha20_encrypt(message, key):
    nonce = urandom(16)  # Generate random nonce
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message)
    return nonce + ciphertext

# Message encoding and embedding into image
def encode_message(input_image, output_image, secret_message, password):
    img = Image.open(input_image)
    encoded_img = img.copy()
    width, height = img.size
    pixels = encoded_img.load()

    # Step 1: Hash the message for integrity
    hash_value = sha256_hash(secret_message)
    
    # Step 2: Encrypt with AES-256
    aes_key = sha256_hash(password)  # Derive a 256-bit key from the password
    aes_encrypted = aes256_encrypt(hash_value + secret_message.encode(), aes_key)
    
    # Step 3: Encrypt with ChaCha20
    chacha_key = urandom(32)  # Generate a random ChaCha20 key
    doubly_encrypted = chacha20_encrypt(aes_encrypted, chacha_key)
    
    # Convert the encrypted data to binary and add a delimiter
    binary_message = ''.join(format(byte, '08b') for byte in doubly_encrypted) + '1111111111111110'
    
    # Step 4: Embed the encrypted binary message into the image
    idx = 0
    for y in range(height):
        for x in range(width):
            if idx < len(binary_message):
                r, g, b = pixels[x, y]
                r = (r & ~1) | int(binary_message[idx])  # Modify the least significant bit
                idx += 1
                pixels[x, y] = (r, g, b)

    # Save the encoded image
    encoded_img.save(output_image)
    print(f"Message encoded and saved as {output_image}. Keep the ChaCha20 key: {base64.b64encode(chacha_key).decode()}")
    return base64.b64encode(chacha_key).decode()

# AES-256 decryption function
def aes256_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# ChaCha20 decryption function
def chacha20_decrypt(ciphertext, key):
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

# Message decoding from image
def decode_message(stego_image, password, chacha_key):
    img = Image.open(stego_image)
    width, height = img.size
    pixels = img.load()

    # Extract the binary message from the image
    binary_message = ''
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_message += str(r & 1)

    # Convert the binary data to bytes
    binary_message = binary_message.split('1111111111111110')[0]
    encrypted_data = bytes(int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8))
    
    # Step 1: Decrypt with ChaCha20
    chacha_key = base64.b64decode(chacha_key)
    aes_encrypted = chacha20_decrypt(encrypted_data, chacha_key)

    # Step 2: Decrypt with AES-256
    aes_key = sha256_hash(password)  # Derive a 256-bit key from the password
    decrypted_message = aes256_decrypt(aes_encrypted, aes_key)
    
    # Step 3: Verify integrity
    hash_value, original_message = decrypted_message[:32], decrypted_message[32:]
    if sha256_hash(original_message.decode()) != hash_value:
        print("Message integrity compromised!")
        return None
    
    print(f"Decoded message: {original_message.decode()}")
    return original_message.decode()

# Flask routes
@app.route('/')
def home():
    return render_template('home.html') 

@app.route('/team') 
def team():
    return render_template('team.html')

@app.route('/embed') 
def embed():
    return render_template('embed.html')

@app.route('/extract') 
def extract():
    return render_template('extract.html')

@app.route('/encode', methods=['POST'])
def encode():
    if request.method == 'POST':
        file = request.files['image']
        message = request.form['message']
        password = request.form['password']
        input_image = 'static/' + file.filename
        file.save(input_image)
        output_image = 'static/encoded_image.png'

        # Call the encode message function
        chacha_key = encode_message(input_image, output_image, message, password)

        return render_template('encode_result.html', chacha_key=chacha_key, encoded_image=output_image)

@app.route('/decode', methods=['POST'])
def decode():
    if request.method == 'POST':
        file = request.files['stego_image']
        password = request.form['password']
        chacha_key = request.form['chacha_key']
        stego_image = 'static/' + file.filename
        file.save(stego_image)

        # Call the decode message function
        decoded_message = decode_message(stego_image, password, chacha_key)

        return render_template('decode_result.html', decoded_message=decoded_message)

if __name__ == '__main__':
    app.run(debug=True)
