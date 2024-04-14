import xml.etree.ElementTree as xmlGen
import os
import time
from datetime import datetime


def generateXML(pathToFile, filename='signature.xml'):
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
    EncryptedHash.text = "HASH"

    Timestamp = xmlGen.SubElement(Signature, "Timestamp")
    Timestamp.text = str(time.time())

    tree = xmlGen.ElementTree(Signature)

    with open(filename, "wb") as files:
        tree.write(files)