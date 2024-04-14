from xml.dom import minidom
import xml.etree.ElementTree as xml_gen
import os
import time

def generateXML(filename):
    Signature = xml_gen.Element("Signature")

    DocumentInfo = xml_gen.Element("DocumentInfo")
    Signature.append(DocumentInfo)

    Size = xml_gen.SubElement(DocumentInfo, "Size")
    Size.text = "1243 KB"
    Extension = xml_gen.SubElement(DocumentInfo, "Extension")
    Extension.text = "zzzz"
    DateModified = xml_gen.SubElement(DocumentInfo, "DateModified")
    DateModified.text = "xxxx"

    SigningUser = xml_gen.SubElement(Signature, "SigningUser")
    SigningUser.text = os.getlogin()

    EncryptedHashAlgorithm = xml_gen.SubElement(Signature, "EncryptedHashAlgorithm")
    EncryptedHashAlgorithm.text = "RSA"

    EncryptedHash = xml_gen.SubElement(Signature, "EncryptedHash")
    EncryptedHash.text = "HASH"

    Timestamp = xml_gen.SubElement(Signature, "Timestamp")
    Timestamp.text = str(time.time())

    tree = xml_gen.ElementTree(Signature)

    with open(filename, "wb") as files:
        tree.write(files)

generateXML('signature.xml')