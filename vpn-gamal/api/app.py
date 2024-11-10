from flask import Flask, request, jsonify
from flask_cors import CORS
import MySQLdb
import traceback
from encrypt_gamal import elgamal_encrypt, connect, elgamal_get_keys

# Initialize Flask
app = Flask(__name__)
CORS(app)

# Connect to ElGamal on startup
connect()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        msg = data['msg']  # Get the message from the request body

        # Encrypt the message using ElGamal
        encrypted_msg = elgamal_encrypt(msg)

        # Retrieve the public and private keys from the ElGamal instance
        public_key, private_key = elgamal_get_keys()  # Public key is (p, g, h), private key is x

        # Connect to the MySQL database
        db = MySQLdb.connect(host="mysql-vpn", user="root", passwd="root", db="secret_msg")
        cursor = db.cursor()

        # Store the encrypted message in the `msg_table`
        query_msg = "INSERT INTO msg_table (msg) VALUES (%s)"
        cursor.execute(query_msg, (str(encrypted_msg),))

        # Store the public key and private key in the `elgamal_keys` table
        p, g, h = public_key
        query_key = "INSERT INTO elgamal_keys (prime, generator, h, private_key) VALUES (%s, %s, %s, %s)"
        cursor.execute(query_key, (p, g, h, private_key))

        # Commit all changes
        db.commit()

        return jsonify({"status": "success", "message": "Data encrypted and stored successfully."}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'db' in locals():
            db.close()

@app.route('/signal', methods=['POST'])
def signal():
    try:
        data = request.json
        signal = data.get('signal')

        if signal == 1:
            return jsonify({"status": "success", "message": "Connected to VPN."}), 200
        elif signal == 0:
            return jsonify({"status": "success", "message": "Disconnected from VPN."}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid signal."}), 400

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
