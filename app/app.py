from flask import Flask, request, jsonify, send_file
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
import os
import tempfile
import requests

app = Flask(__name__)

# Chemin vers le fichier P12 et la passphrase
P12_FILE_PATH = 'app/certs/application_de_test.p12'
P12_PASSPHRASE = 'password'

@app.route('/sign_document', methods=['POST'])
def sign_document():
    pdf_file = request.files['filereceivefile']
    worker_id = request.form['workerId']
    code_pin = request.form['codePin']

    # Charger le fichier P12
    with open(P12_FILE_PATH, 'rb') as p12_f:
        p12_data = p12_f.read()

    # Charger le PKCS12
    p12 = pkcs12.load_key_and_certificates(p12_data, P12_PASSPHRASE.encode('utf-8'))

    # Extraire le certificat et la clé privée
    cert = p12[1]
    key = p12[0]

    # Sauvegarder le certificat et la clé dans des fichiers temporaires
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as cert_file, \
         tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as key_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))
        key_file.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

        cert_path = cert_file.name
        key_path = key_file.name

    # Créer les données du formulaire
    form_data = {
        'filereceivefile': (pdf_file.filename, pdf_file, 'application/pdf'),
        'workerId': (None, worker_id),
        'codePin': (None, code_pin)
    }

    # URL de l'API
    url = "https://rasign.gainde2000.sn:8443/app_signatureV1.1/signer/v1.1/sign_document/8"

    # Faire la requête POST avec les certificats et la clé
    response = requests.post(
        url,
        files=form_data,
        cert=(cert_path, key_path),
        verify=False  # Désactive la vérification du certificat du serveur
    )

    # Nettoyer les fichiers temporaires
    os.remove(cert_path)
    os.remove(key_path)

    # Vérifier la réponse
    if response.status_code == 200:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as signed_file:
            signed_file.write(response.content)
            signed_path = signed_file.name
        return send_file(signed_path, as_attachment=True, download_name='signed_document.pdf')
    else:
        return jsonify({'error': 'Error signing document', 'message': response.text}), response.status_code

if __name__ == '__main__':
    app.run(debug=True)
