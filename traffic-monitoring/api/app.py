from flask import Flask, request, jsonify
from flask_cors import CORS
import MySQLdb
import traceback
from aes import aes_encrypt  # Import AES encryption function
from des import des_encrypt  # Import DES encryption function

app = Flask(__name__)
CORS(app)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # Ambil data dari request JSON
        data = request.json
        plate = data['plate']
        brand = data['brand']
        speed = int(data['speed']) 
        date = data['date']

        # Kunci enkripsi
        aes_key = 'FFEEDDCCBBAA99887766554433221100'  
        des_key = '0123456789ABCDEF' 

        # Enkripsi data
        encrypted_plate = aes_encrypt(plate, aes_key)  # Gunakan AES untuk plate
        encrypted_speed = des_encrypt(str(speed), des_key)  # Gunakan DES untuk speed
        encrypted_brand = des_encrypt(brand, des_key)  # Gunakan DES untuk brand

        # Simpan data terenkripsi ke database
        db = MySQLdb.connect(host="mysql", user="root", passwd="root", db="traffic")
        cursor = db.cursor()
        query = "INSERT INTO traffic_data (plate, brand, speed, date) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (encrypted_plate, encrypted_brand, encrypted_speed, date))
        db.commit()

        return jsonify({"status": "success", "message": "Data encrypted and stored successfully."}), 200

    except Exception as e:
        traceback.print_exc()  # Log error ke console untuk debugging
        return jsonify({"status": "error", "message": str(e)}), 500

    finally:
        # Pastikan koneksi database selalu ditutup
        if 'cursor' in locals():
            cursor.close()
        if 'db' in locals():
            db.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
