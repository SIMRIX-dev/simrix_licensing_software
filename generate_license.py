# generate_license.py
import json, os, hashlib, secrets, datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
PRIVATE_KEY_FILE = "C:\\Pranav\\VD Codes\\Licensing Files\\Keys\\private.pem"
PUBLIC_KEY_FILE = "C:\\Pranav\\VD Codes\\Licensing Files\\Keys\\public.pem"

# Utility: canonical JSON for signing (deterministic)
def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

def load_keys():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def compute_machine_hash(system_uuid, motherboard_id, cpu_id):
    raw = (system_uuid or "") + "|" + (motherboard_id or "") + "|" + (cpu_id or "")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def aes_encrypt(plaintext_bytes):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)  # ciphertext includes tag
    return key, iv, ciphertext

def rsa_encrypt_key(public_key, key_bytes):
    encrypted = public_key.encrypt(
        key_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return encrypted

def sign_with_private(private_key, message_bytes):
    signature = private_key.sign(
        message_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def create_license_file():
    # Collect inputs
    name = input("Licensee full name: ").strip()
    expiry = input("Expiry date (YYYY-MM-DD): ").strip()
    try:
        datetime.datetime.strptime(expiry, "%Y-%m-%d")
    except Exception:
        print("Invalid date format")
        return
    features = input("Features (comma-separated): ").strip().split(",")
    features = [f.strip() for f in features if f.strip()]

    print("\nEnter hardware IDs from target machine:")
    system_uuid = input("System UUID: ").strip()
    motherboard_id = input("Motherboard Serial: ").strip()
    cpu_id = input("CPU ID: ").strip()

    # 1) compute machine_hash (unchanged on client if same hardware)
    machine_hash = compute_machine_hash(system_uuid, motherboard_id, cpu_id)

    # 2) create public (client-visible) license body
    public_body = {
        "licensee": name,
        "expiry": expiry,
        "features": features,
        "machine_hash": machine_hash
    }

    # 3) create encrypted payload (full hardware details + metadata)
    payload = {
        "system_uuid": system_uuid,
        "motherboard_id": motherboard_id,
        "cpu_id": cpu_id,
        "issued_on": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    payload_bytes = json.dumps(payload, indent=2).encode("utf-8")

    # 4) load keys
    private_key, public_key = load_keys()

    # 5) AES encrypt payload
    aes_key, iv, ciphertext = aes_encrypt(payload_bytes)

    # 6) RSA-encrypt AES key with public key (only private key holder can decrypt)
    encrypted_aes_key = rsa_encrypt_key(public_key, aes_key)

    # 7) Build the full license structure (excluding signature)
    license_struct = {
        "licensee": public_body["licensee"],
        "expiry": public_body["expiry"],
        "features": public_body["features"],
        "machine_hash": public_body["machine_hash"],

        # Encrypted payload pieces (hex for portability)
        "encrypted_key": encrypted_aes_key.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex()
    }

    # 8) canonical serialize and sign with private key
    message = canonical_json(license_struct).encode("utf-8")
    signature = sign_with_private(private_key, message)

    license_struct["signature"] = signature.hex()

    # 9) save license file
    safe_name = name.replace(" ", "_")
    out_file = f"license_{safe_name}.json"
    with open(out_file, "w") as f:
        json.dump(license_struct, f, indent=2)

    print(f"\nLicense written to {out_file}")
    print("Distribute this license file and public.pem to the client.")

if __name__ == "__main__":
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        print("Missing keys — run generate_keys.py first.")
    else:
        create_license_file()
