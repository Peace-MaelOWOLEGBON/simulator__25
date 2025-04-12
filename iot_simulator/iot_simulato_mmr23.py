import random
import time
import json
import sqlite3
import base64
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

# Configuration
DEVICE_ID = "CAPTEUR_001"
SENSOR_TYPE = "renal_monitor"
MQTT_BROKER = "test.mosquitto.org"
MQTT_TOPIC = "iot/health"
AES_KEY = b"thisis32byteslongsecretkey123456"

# --- Génération de données simulées ---
def generate_sensor_data():
    patient_id = f"PATIENT_{random.randint(1000, 9999)}"
    timestamp = datetime.now()
    egfr = random.uniform(30, 120)
    creatinine = random.uniform(0.5, 5.0)
    
    return {
        "device_id": DEVICE_ID,
        "sensor_type": SENSOR_TYPE,
        "patient_id": patient_id,
        "timestamp": timestamp.isoformat(),
        "egfr": round(egfr, 1),
        "creatinine": round(creatinine, 2),
        "blood_pressure": f"{random.randint(120, 180)}/{random.randint(70, 100)}",
        "weight": round(70 + random.uniform(-2, 2), 1),
        "hydration_ml": random.randint(800, 2500),
    }

# --- Fonction de chiffrement AES ---
def encrypt_data_aes(data: dict) -> str:
    json_data = json.dumps(data).encode('utf-8')
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(json_data, AES.block_size))
    encrypted = base64.b64encode(iv + ciphertext).decode('utf-8')
    return encrypted

# --- Fonction de déchiffrement AES ---
def decrypt_data_aes(encrypted_b64: str) -> dict:
    raw = base64.b64decode(encrypted_b64)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return json.loads(plaintext.decode('utf-8'))

# --- Création de la base de données SQLite ---
def create_sqlite_db():
    conn = sqlite3.connect("iot_data.db")
    cursor = conn.cursor()
    
    # Créer une table pour stocker les données MQTT
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sensor_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        sensor_type TEXT,
        patient_id TEXT,
        timestamp TEXT,
        egfr REAL,
        creatinine REAL,
        blood_pressure TEXT,
        weight REAL,
        hydration_ml INTEGER
    )
    """)
    
    conn.commit()
    conn.close()
    print("SQLite Database and table created successfully")

# --- Sauvegarde dans SQLite (données déchiffrées) ---
def save_to_sqlite(data):
    try:
        conn = sqlite3.connect("iot_data.db")
        cursor = conn.cursor()

        # Insérer les données dans la table
        cursor.execute("""
            INSERT INTO sensor_data (device_id, sensor_type, patient_id, timestamp, egfr, creatinine, blood_pressure, weight, hydration_ml)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (data["device_id"], data["sensor_type"], data["patient_id"], data["timestamp"], data["egfr"], data["creatinine"], data["blood_pressure"], data["weight"], data["hydration_ml"]))
        
        conn.commit()
        conn.close()
        print("[SQLite] Data saved successfully")
    except Exception as e:
        print(f"[SQLite] Error saving data: {e}")

# --- Fonction de callback pour les messages MQTT reçus ---
def on_message(client, userdata, msg):
    print(f"[MQTT] Message reçu sur le topic {msg.topic}")
    
    # Déchiffrer les données 
    try:
        encrypted_data = msg.payload.decode('utf-8')
        data = decrypt_data_aes(encrypted_data)  # Déchiffre les données
        
        
        # Insérer les données dans SQLite
        save_to_sqlite(data)
    except Exception as e:
        print(f"[MQTT] Erreur lors de l'insertion dans SQLite: {e}")

# --- Configuration MQTT ---
client = mqtt.Client()

# Associer la fonction de callback pour les messages
client.on_message = on_message

# Connecter le client au broker MQTT
client.connect(MQTT_BROKER, 1883, 60)

# S'abonner au topic
client.subscribe(MQTT_TOPIC)

# Démarrer la boucle pour écouter les messages
client.loop_start()

# Créer la base de données et la table SQLite avant de commencer
create_sqlite_db()

print(f"[MQTT] Listening for messages on topic {MQTT_TOPIC}...")

try:
    while True:
        # Envoi de données simulées de manière périodique via MQTT
        data = generate_sensor_data()
        encrypted_data = encrypt_data_aes(data)  # Chiffrement des données avant l'envoi
        client.publish(MQTT_TOPIC, encrypted_data)  # Envoi des données chiffrées via MQTT
       
        
        time.sleep(5)
except KeyboardInterrupt:
    print("Arrêt du programme.")
    client.loop_stop()
