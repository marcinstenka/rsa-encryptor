import os.path
import tkinter as tk
import hashlib as hl
from tkinter import ttk
from tkinter.ttk import *
from tkinter import *
from generator import *
from tkinter.filedialog import askopenfilename
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from xml_generator import *


def enterPIN():
    global entry
    global pinWindow
    pinWindow = Toplevel(win)
    win.eval(f'tk::PlaceWindow {str(pinWindow)} center')
    pinWindow.title("Enter PIN")
    pinWindow.geometry("145x100")
    Label(pinWindow, text="Enter PIN:").grid(row=0, padx=10, pady=(10, 0))
    entry = Entry(pinWindow)
    entry.grid(row=1, pady=0, padx=10)
    Button(pinWindow, text="Generuj", command=generateRSA).grid(row=2, padx=10, pady=(10, 0))


def generateRSA():
    global pinWindow
    global label2
    if len(entry.get()) == 4:
        generate(entry.get())
        pinWindow.destroy()
        label2.config(text="Klucze wygenerowane poprawnie", foreground="green")


def chooseFileAndKey(action):
    global labelFile
    global labelKey
    global fileAndKeyWindow
    global labelError
    global currentAction
    currentAction = action
    Tk().withdraw()
    fileAndKeyWindow = Toplevel(win)
    win.eval(f'tk::PlaceWindow {str(fileAndKeyWindow)} center')
    fileAndKeyWindow.title("Choose File and Key")
    fileAndKeyWindow.geometry("400x100")
    fileAndKeyWindow.columnconfigure(0, weight=1)
    fileAndKeyWindow.columnconfigure(1, weight=1)
    fileAndKeyWindow.columnconfigure(2, weight=1)
    fileAndKeyWindow.rowconfigure(0, weight=1)
    fileAndKeyWindow.rowconfigure(1, weight=1)
    fileAndKeyWindow.rowconfigure(2, weight=1)
    fileAndKeyWindow.rowconfigure(3, weight=1)

    Label(fileAndKeyWindow, text="Wybierz plik oraz klucz").grid(row=0, column=1, pady=(10, 0))
    Button(fileAndKeyWindow, text="Wybierz plik", command=chooseFile).grid(row=1, column=0, padx=10)
    Button(fileAndKeyWindow, text="Wybierz klucz", command=chooseKeyFile).grid(row=1, column=2, padx=10)
    labelFile = Label(fileAndKeyWindow, text=fileString)
    labelFile.grid(row=2, column=0, padx=10, pady=(0, 10))
    labelKey = Label(fileAndKeyWindow, text=keyString)
    labelKey.grid(row=2, column=2, padx=10, pady=(0, 10))

    labelError = Label(fileAndKeyWindow, text="")
    labelError.grid(row=2, column=1, padx=10)
    if currentAction == 'sign':
        Button(fileAndKeyWindow, text="Podpisz", command=encrypt).grid(row=3, column=1, padx=10, pady=(0, 10))
    elif currentAction == 'verify':
        Button(fileAndKeyWindow, text="Weryfikuj", command=verify_signature).grid(row=3, column=1, padx=10, pady=(0, 10))
    elif currentAction == 'encrypt':
        Button(fileAndKeyWindow, text="Szyfruj", command=encrypt_file).grid(row=3, column=1, padx=10, pady=(0, 10))
    elif currentAction == 'decrypt':
        Button(fileAndKeyWindow, text="Deszyfruj", command=decrypt).grid(row=3, column=1, padx=10, pady=(0, 10))


def getPIN():
    global pinToCheck
    checkPinWindow = Toplevel(win)
    win.eval(f'tk::PlaceWindow {str(checkPinWindow)} center')
    checkPinWindow.title("Enter PIN")
    checkPinWindow.geometry("145x100")
    Label(checkPinWindow, text="Enter PIN:").grid(row=0, padx=10, pady=(10, 0))
    pinToCheck = Entry(checkPinWindow)
    pinToCheck.grid(row=1, pady=0, padx=10)
    Button(checkPinWindow, text="Zatwierdź", command=decryptPrivateKey).grid(row=2, padx=10, pady=(10, 0))


def decryptPrivateKey():
    global private_key
    global labelError
    try:
        private_key = load_and_decrypt_private_key(labelKey.cget("text"), str(pinToCheck.get()))
        print("Private key decrypted")
        if currentAction == 'sign':
            signature = sign_file_with_rsa(private_key, filePath)
            save_signature(signature, 'signature.sig')
            labelError.config(text="Plik podpisany pomyślnie!", foreground="green")
            fileAndKeyWindow.destroy()
            xml_signature_path = integrate_xml_signature('signature.xml', filePath)
            print(f"Integrated XML signature: {xml_signature_path}")
        elif currentAction == 'decrypt':
            decrypt_file_with_private_key(filePath, private_key)
            labelError.config(text="Plik odszyfrowany pomyślnie!", foreground="green")
            fileAndKeyWindow.destroy()
    except Exception as e:
        labelError.config(text="Błędny PIN!", foreground="red")
        print(f"Decryption failed: {e}")


def sign_file_with_rsa(private_key, file_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_obj.update(file_data)
    file_hash = hash_obj.finalize()

    signature = private_key.sign(
        file_hash, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def save_signature(signature, output_path):
    with open(output_path, 'wb') as f:
        f.write(signature)


def encrypt():
    global hash_of_file
    global filePath
    if labelFile.cget("text") != "" and labelKey.cget("text"):
        hash_of_file = hashFile()
        print(str(hash_of_file))
        generateXML(filePath, hash_of_file)
        getPIN()
    else:
        labelError.config(text="Wybierz plik oraz klucz przed podpisywaniem", foreground="red")


def verify_signature():
    global hash_of_file
    global filePath
    if labelFile.cget("text") != "" and labelKey.cget("text"):
        hash_of_file = hashFile()
        print(str(hash_of_file))
        generateXML(filePath, hash_of_file)
        labelError.config(text="Weryfikacja podpisu zakończona", foreground="green")
    else:
        labelError.config(text="Wybierz plik oraz klucz przed weryfikacją", foreground="red")


def encrypt_file():
    global hash_of_file
    global filePath
    if labelFile.cget("text") != "" and labelKey.cget("text"):
        hash_of_file = hashFile()
        print(str(hash_of_file))
        generateXML(filePath, hash_of_file)

        with open(labelKey.cget("text"), 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

        encrypt_file_with_public_key(filePath, public_key)
        labelError.config(text="Plik zaszyfrowany pomyślnie!", foreground="green")
    else:
        labelError.config(text="Wybierz plik oraz klucz przed szyfrowaniem", foreground="red")


def decrypt():
    if labelFile.cget("text") != "" and labelKey.cget("text"):
        getPIN()
    else:
        labelError.config(text="Wybierz plik oraz klucz przed deszyfrowaniem", foreground="red")


def encrypt_file_with_public_key(file_path, public_key):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted_data)


def decrypt_file_with_private_key(file_path, private_key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(file_path[:-4], 'wb') as f:
        f.write(decrypted_data)


def hashFile():
    hasher = hl.sha256()
    with open(str(filePath), 'rb') as file:
        chunk = file.read(8192)
        while chunk:
            hasher.update(chunk)
            chunk = file.read(8192)
    return hasher.hexdigest()


def chooseFile():
    global fileString
    global filePath
    filePath = askopenfilename()
    fileString = os.path.basename(filePath)
    labelFile.config(text=fileString)
    labelError.config(text="", foreground="red")
    fileAndKeyWindow.focus_set()


def chooseKeyFile():
    global keyString
    keyPath = askopenfilename()
    keyString = os.path.basename(keyPath)
    labelKey.config(text=keyString)
    labelError.config(text="", foreground="red")
    fileAndKeyWindow.focus_set()


fileString = ""
keyString = ""
win = tk.Tk()
win.geometry("+720+400")
win.title("Signing APP - BSK Project")

win.columnconfigure(0, weight=1)
win.columnconfigure(1, weight=1)
win.columnconfigure(2, weight=1)
win.columnconfigure(3, weight=1)
win.rowconfigure(0, weight=1)
win.rowconfigure(1, weight=1)
win.rowconfigure(2, weight=1)

label1 = ttk.Label(win, text="Signing APP - BSK Project", font=("Arial", 14))
label1.grid(row=0, column=1, pady=10)

button1 = ttk.Button(win, text="Podpisz plik", width=20, command=lambda: chooseFileAndKey('sign'))
button1.grid(row=1, column=0, pady=20, padx=20)

button2 = ttk.Button(win, text="Weryfikuj podpis", width=20, command=lambda: chooseFileAndKey('verify'))
button2.grid(row=1, column=1, pady=20, padx=20)

button3 = ttk.Button(win, text="Szyfruj plik", width=20, command=lambda: chooseFileAndKey('encrypt'))
button3.grid(row=1, column=2, pady=20, padx=20)

button4 = ttk.Button(win, text="Deszyfruj plik", width=20, command=lambda: chooseFileAndKey('decrypt'))
button4.grid(row=1, column=3, pady=20, padx=20)

label2 = ttk.Label(win, text="")
label2.grid(row=2, column=1, pady=(0, 20))

win.mainloop()