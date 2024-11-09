from PIL import Image
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

# Função para embutir texto em uma imagem usando Steganografia
def embed_text_in_image(input_image_path, output_image_path, text):
    image = Image.open(input_image_path)
    encoded_image = image.copy()
    binary_text = ''.join([format(ord(i), "08b") for i in text])
    data_len = len(binary_text)
    idx = 0

    for y in range(image.height):
        for x in range(image.width):
            pixel = list(encoded_image.getpixel((x, y)))
            for n in range(3):
                if idx < data_len:
                    pixel[n] = pixel[n] & ~1 | int(binary_text[idx])
                    idx += 1
            encoded_image.putpixel((x, y), tuple(pixel))
            if idx >= data_len:
                break
        if idx >= data_len:
            break

    encoded_image.save(output_image_path)
    print("Texto embutido com sucesso na imagem!")

# Função para extrair texto de uma imagem usando Steganografia
def extract_text_from_image(image_path):
    image = Image.open(image_path)
    binary_text = ""
    for y in range(image.height):
        for x in range(image.width):
            pixel = image.getpixel((x, y))
            for n in range(3):
                binary_text += str(pixel[n] & 1)

    bytes_data = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    extracted_text = "".join([chr(int(b, 2)) for b in bytes_data if int(b, 2) != 0])
    print("Texto extraído:", extracted_text)
    return extracted_text

# Função para gerar hash da imagem
def generate_image_hash(image_path):
    with open(image_path, "rb") as f:
        img_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"Hash da imagem {image_path}: {img_hash}")
    return img_hash

# Função para criptografar texto usando chave pública
def encrypt_text(public_key, text):
    encrypted = public_key.encrypt(
        text.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode()

# Função para descriptografar texto usando chave privada
def decrypt_text(private_key, encrypted_text):
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_text),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted.decode()

# Gerar chaves pública e privada
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Função de menu principal
def main_menu():
    private_key, public_key = generate_keys()
    while True:
        print("\nMenu de Opções:")
        print("(1) Embutir texto em imagem usando Steganography")
        print("(2) Recuperar texto de imagem alterada por Steganography")
        print("(3) Gerar hash das imagens para verificar alteração")
        print("(4) Encriptar mensagem com chave pública e privada")
        print("(5) Decriptar mensagem com chave pública e privada")
        print("(S ou s) Sair")
        choice = input("Escolha uma opção: ").strip().lower()

        if choice == '1':
            input_image_path = input("Informe o caminho da imagem original: ")
            output_image_path = input("Informe o caminho para salvar a imagem alterada: ")
            text = input("Digite o texto a ser embutido: ")
            embed_text_in_image(input_image_path, output_image_path, text)

        elif choice == '2':
            image_path = input("Informe o caminho da imagem alterada: ")
            extract_text_from_image(image_path)

        elif choice == '3':
            original_image_path = input("Informe o caminho da imagem original: ")
            altered_image_path = input("Informe o caminho da imagem alterada: ")
            generate_image_hash(original_image_path)
            generate_image_hash(altered_image_path)

        elif choice == '4':
            message = input("Digite a mensagem a ser encriptada: ")
            encrypted_message = encrypt_text(public_key, message)
            print("Mensagem encriptada:", encrypted_message)

        elif choice == '5':
            encrypted_message = input("Digite a mensagem encriptada: ")
            try:
                decrypted_message = decrypt_text(private_key, encrypted_message)
                print("Mensagem decriptada:", decrypted_message)
            except Exception as e:
                print("Erro ao decriptar a mensagem:", e)

        elif choice == 's':
            print("Encerrando aplicação...")
            break
        else:
            print("Opção inválida, tente novamente.")

# Executar o menu principal
main_menu()
