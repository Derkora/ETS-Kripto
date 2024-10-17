from flask import Flask, request, jsonify
from flask_cors import CORS
import MySQLdb
import traceback
from encrypt_rsa import rsa_encrypt, connect, rsa_get_keys

# Inisialisasi Flask
app = Flask(__name__)
CORS(app)

# Connect to RSA on startup
connect()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        msg = data['msg']  # Ambil pesan dari request body

        # Enkripsi pesan
        encrypted_msg = rsa_encrypt(msg)  # Simulasi enkripsi

        # Ambil kunci publik dari instance RSA
        public_key, _ = rsa_get_keys()

        # Koneksi ke database MySQL
        db = MySQLdb.connect(host="mysql", user="root", passwd="root", db="secret_msg")
        cursor = db.cursor()

        # Simpan pesan terenkripsi ke dalam tabel `msg_table`
        query_msg = "INSERT INTO msg_table (msg) VALUES (%s)"
        cursor.execute(query_msg, (str(encrypted_msg),))

        # Simpan kunci publik ke dalam tabel `rsa_keys`
        n, e = public_key
        query_key = "INSERT INTO rsa_keys (modulus, exponent) VALUES (%s, %s)"
        cursor.execute(query_key, (n, e))

        # Commit semua perubahan
        db.commit()

        return jsonify({"status": "success", "message": "Data encrypted and stored successfully, public key saved."}), 200

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
