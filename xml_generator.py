import xml.etree.ElementTree as xmlGen
import os
import time
from datetime import datetime


def generateXML(pathToFile, hash, filename='signature.xml'):
    Signature = xmlGen.Element("Signature")

    DocumentInfo = xmlGen.Element("DocumentInfo")
    Signature.append(DocumentInfo)

    file_stats = os.stat(pathToFile)
    file_name, file_extension = os.path.splitext(pathToFile)
    Size = xmlGen.SubElement(DocumentInfo, "Size")
    Size.text = str(file_stats.st_size) + " B"
    Extension = xmlGen.SubElement(DocumentInfo, "Extension")
    Extension.text = file_extension
    DateModified = xmlGen.SubElement(DocumentInfo, "DateModified")
    DateModified.text = str(datetime.fromtimestamp(file_stats.st_mtime))

    SigningUser = xmlGen.SubElement(Signature, "SigningUser")
    SigningUser.text = os.getlogin()

    EncryptedHashAlgorithm = xmlGen.SubElement(Signature, "EncryptedHashAlgorithm")
    EncryptedHashAlgorithm.text = "RSA"

    EncryptedHash = xmlGen.SubElement(Signature, "EncryptedHash")
    EncryptedHash.text = str(hash)

    Timestamp = xmlGen.SubElement(Signature, "Timestamp")
    Timestamp.text = str(time.time())

    tree = xmlGen.ElementTree(Signature)

    with open(filename, "wb") as files:
        tree.write(files)

def integrate_xml_signature(xml_signature_path, original_file_path):
    # Wczytaj zawartość pliku XML z podpisem
    xml_tree = xmlGen.parse(xml_signature_path)
    root = xml_tree.getroot()

    # Wczytaj niezbędne informacje z pliku XML
    signing_user = root.find('.//SigningUser').text
    encrypted_hash_algorithm = root.find('.//EncryptedHashAlgorithm').text
    encrypted_hash = root.find('.//EncryptedHash').text
    timestamp = root.find('.//Timestamp').text

    # Zapisz informacje do pliku XML
    xml_signature_info = {
        "SigningUser": signing_user,
        "EncryptedHashAlgorithm": encrypted_hash_algorithm,
        "EncryptedHash": encrypted_hash,
        "Timestamp": timestamp
    }

    # Zintegruj podpis z dokumentem
    integrated_signature_filename = f"{original_file_path}_signed.xml"
    with open(integrated_signature_filename, "wb") as files:
        xml_tree.write(files)

    return integrated_signature_filename