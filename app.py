from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import base64
import binascii
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    print("Starting encrypt function")
    try:
        data = request.get_json()
        print(f"Received data: {data}")
        text = data['text']
        algorithm = data['algorithm']
        key = data.get('key')

        print(f"text type: {type(text)}, algorithm type: {type(algorithm)}")
        if not text or not algorithm:
            return jsonify({"error": "Text and algorithm are required"}), 400

        if algorithm == 'AES':
            if key:
                key = base64.b64decode(key)
                if len(key) not in [16, 24, 32]:
                    return jsonify({"error": "Invalid AES key length."}), 400
            else:
                key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(text.encode('utf-8'), 16))
            return jsonify({
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "key": base64.b64encode(key).decode('utf-8'),
                "iv": base64.b64encode(cipher.iv).decode('utf-8')
            })

        elif algorithm == 'RSA':
            # Generate RSA key pair for the receiver
            receiver_key_pair = RSA.generate(3072)
            receiver_public_key = receiver_key_pair.publickey()
            receiver_public_key_pem = receiver_public_key.export_key().decode('utf-8')
            receiver_private_key_pem = receiver_key_pair.export_key().decode('utf-8')

            # Use the receiver's public key to encrypt the text
            encryptor = PKCS1_OAEP.new(receiver_public_key)
            encrypted = encryptor.encrypt(text.encode('utf-8'))
            ciphertext = binascii.hexlify(encrypted).decode('utf-8')

            return jsonify({
            "ciphertext": ciphertext,
            "receiver_public_key": receiver_public_key_pem,
            "receiver_private_key": receiver_private_key_pem
            })

        elif algorithm == 'ECC':
            print("Entering ECC branch")
            # Generate ECC key pair for sender
            sender_key = ECC.generate(curve='P-256')
            public_key_pem = sender_key.public_key().export_key(format='PEM')
            private_key_pem = sender_key.export_key(format='PEM')
            public_key = public_key_pem.decode('utf-8') if isinstance(public_key_pem, bytes) else public_key_pem
            private_key = private_key_pem.decode('utf-8') if isinstance(private_key_pem, bytes) else private_key_pem

            # Simulate receiver's key pair to derive shared secret
            receiver_key = ECC.generate(curve='P-256')
            receiver_public_key = receiver_key.public_key()

            # Perform ECDH to derive shared secret
            shared_secret_point = receiver_public_key.pointQ * sender_key.d
            shared_secret_bytes = shared_secret_point.x.to_bytes(32, byteorder='big')

            # Derive AES key from shared secret using HKDF
            aes_key = HKDF(shared_secret_bytes, 32, b'', SHA256)
            iv = get_random_bytes(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
            ciphertext = cipher.encrypt(pad(text.encode('utf-8'), 16))

            # Return receiver's public key and private key
            receiver_public_key_pem = receiver_key.public_key().export_key(format='PEM')
            receiver_private_key_pem = receiver_key.export_key(format='PEM')
            receiver_public_key = receiver_public_key_pem.decode('utf-8') if isinstance(receiver_public_key_pem, bytes) else receiver_public_key_pem
            receiver_private_key = receiver_private_key_pem.decode('utf-8') if isinstance(receiver_private_key_pem, bytes) else receiver_private_key_pem

            response = {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "public_key": public_key,
            "private_key": private_key,
            "receiver_public_key": receiver_public_key,
            "receiver_private_key": receiver_private_key_pem,
            "iv": base64.b64encode(iv).decode('utf-8'),
            "aes_key": base64.b64encode(aes_key).decode('utf-8'),
            "shared_secret": base64.b64encode(shared_secret_bytes).decode('utf-8')
            }
            # Print the response before returning it
            print(f"Response before JSON: {response}")
            return app.response_class(
            response=json.dumps(response),
            status=200,
            mimetype='application/json'
            )

        return jsonify({"error": "Invalid algorithm"}), 400

    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        ciphertext = data['text']
        algorithm = data['algorithm']
        key = data.get('key')
        iv = data.get('iv')
        rsaKey = data.get('rsaKey')

        if not ciphertext or not algorithm or (not key and not rsaKey):
            return jsonify({"error": "Ciphertext, algorithm, and key (or private key) are required"}), 400

        if algorithm == 'AES':
            if not iv:
                return jsonify({"error": "IV is required for AES decryption"}), 400
            if not key:
                return jsonify({"error": "AES key is required for decryption"}), 400
            
            try:
                key = base64.b64decode(key)
                if len(key) not in [16, 24, 32]:
                    return jsonify({"error": "Invalid AES key length."}), 400
            except (binascii.Error, ValueError):
                return jsonify({"error": "Invalid AES key. Ensure it is Base64-encoded."}), 400

            try:
                iv = base64.b64decode(iv)
                if len(iv) != 16:
                    return jsonify({"error": "Invalid IV length."}), 400
            except (binascii.Error, ValueError):
                return jsonify({"error": "Invalid IV. Ensure it is Base64-encoded."}), 400
            
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), 16).decode('utf-8')
            return jsonify({"plaintext": plaintext})

        elif algorithm == 'RSA':
            if not rsaKey:
                return jsonify({"error": "RSA private key is required"}), 400

            # Normalize and import the RSA private key
            rsaKey = rsaKey.strip()
            if not rsaKey.startswith('-----BEGIN RSA PRIVATE KEY-----') or not rsaKey.endswith('-----END RSA PRIVATE KEY-----'):
                return jsonify({"error": "RSA private key must be in the correct PEM format"}), 400
            pem_body = rsaKey.replace('-----BEGIN RSA PRIVATE KEY-----', '').replace('-----END RSA PRIVATE KEY-----', '').strip()
            if not pem_body or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n" for c in pem_body):
                return jsonify({"error": "RSA private key contains invalid characters"}), 400
            if not rsaKey.endswith('-----END RSA PRIVATE KEY-----'):
                rsaKey = rsaKey + '\n-----END RSA PRIVATE KEY-----'
            try:
                private_key = RSA.import_key(rsaKey)
            except ValueError as e:
                print(f"Failed to import RSA private key: {str(e)}")
                return jsonify({"error": "Invalid RSA Private Key: " + str(e)}), 400

            # Decrypt the ciphertext using the RSA private key
            decryptor = PKCS1_OAEP.new(private_key)
            try:
                encrypted = binascii.unhexlify(ciphertext)
                plaintext = decryptor.decrypt(encrypted).decode('utf-8')
            except (ValueError, binascii.Error) as e:
                print(f"Decryption failed: {str(e)}")
                return jsonify({"error": "Decryption failed: " + str(e)}), 400

            return jsonify({"plaintext": plaintext})

        elif algorithm == 'ECC':
            if not rsaKey:
                return jsonify({"error": "Receiver's ECC private key is required"}), 400
            if not iv:
                return jsonify({"error": "IV is required for ECC decryption"}), 400
            if not key:
                return jsonify({"error": "Sender's public key is required for ECC decryption"}), 400

            # Normalize and import the receiver's private key
            rsaKey = rsaKey.strip()
            if not rsaKey.startswith('-----BEGIN PRIVATE KEY-----') or not rsaKey.endswith('-----END PRIVATE KEY-----'):
                return jsonify({"error": "ECC private key must be in the correct PEM format"}), 400
            pem_body = rsaKey.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '').strip()
            if not pem_body or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n" for c in pem_body):
                return jsonify({"error": "ECC private key contains invalid characters"}), 400
            if not rsaKey.endswith('-----END PRIVATE KEY-----'):
                rsaKey = rsaKey + '\n-----END PRIVATE KEY-----'
            try:
                private_key = ECC.import_key(rsaKey)
            except ValueError as e:
                print(f"Failed to import ECC private key: {str(e)}")
                return jsonify({"error": "Invalid ECC Private Key: " + str(e)}), 400

            # Normalize and import the sender's public key
            key = key.strip()
            if not key.startswith('-----BEGIN PUBLIC KEY-----') or not key.endswith('-----END PUBLIC KEY-----'):
                return jsonify({"error": "ECC public key must be in the correct PEM format"}), 400
            pem_body = key.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').strip()
            if not pem_body or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n" for c in pem_body):
                return jsonify({"error": "ECC public key contains invalid characters"}), 400
            if not key.endswith('-----END PUBLIC KEY-----'):
                key = key + '\n-----END PUBLIC KEY-----'
            try:
                sender_public_key = ECC.import_key(key)
            except (ValueError, binascii.Error) as e:
                print(f"Failed to import sender's public key: {str(e)}")
                return jsonify({"error": "Invalid Sender's Public Key: " + str(e)}), 400

            # Derive shared secret using ECDH (receiver private key and sender public key)
            shared_secret_point = sender_public_key.pointQ * private_key.d
            shared_secret_bytes = shared_secret_point.x.to_bytes(32, byteorder='big')

            # Derive AES key from shared secret using HKDF
            aes_key = HKDF(shared_secret_bytes, 32, b'', SHA256)
            try:
                iv = base64.b64decode(iv)
                if len(iv) != 16:
                    return jsonify({"error": "Invalid IV length."}), 400
            except (binascii.Error, ValueError):
                return jsonify({"error": "Invalid IV. Ensure it is Base64-encoded."}), 400
            # Decrypt the ciphertext using the derived AES key
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), 16).decode('utf-8')
            return jsonify({"plaintext": plaintext})

        return jsonify({"error": "Invalid algorithm"}), 400

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)