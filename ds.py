import os
import json
from lxml import etree
import xmlsec
from cryptography.hazmat.primitives import serialization

# Load the private key from file
def load_private_key(filename):
    with open(filename, 'rb') as pem_in:
        pem = pem_in.read()
    return serialization.load_pem_private_key(pem, password=None)

# Function to convert JSON to XML
def json_to_xml(json_obj, line_padding=""):
    elem_list = []
    for key, value in json_obj.items():
        if isinstance(value, dict):
            elem_list.append(f"{line_padding}<{key}>")
            elem_list.append(json_to_xml(value, line_padding + "  "))
            elem_list.append(f"{line_padding}</{key}>")
        else:
            elem_list.append(f"{line_padding}<{key}>{value}</{key}>")
    return "\n".join(elem_list)

# Load file and determine type
file_path = 'invoice.json'  # Change to your file path
file_extension = os.path.splitext(file_path)[1].lower()

if file_extension == '.json':
    # Load JSON from file
    with open(file_path, 'r') as json_file:
        data = json.load(json_file)
    xml_str = f"<root>\n{json_to_xml(data)}\n</root>"
    xml = etree.ElementTree(etree.fromstring(xml_str))
elif file_extension == '.xml':
    # Load XML from file
    xml = etree.parse(file_path)
else:
    raise ValueError("Unsupported file type")

# Load the private key
private_key = load_private_key('private_key.pem')
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Create Signature Template
signature_node = xmlsec.template.create(
    xml.getroot(), xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256
)
ref = xmlsec.template.add_reference(
    signature_node, xmlsec.Transform.SHA256, uri=""
)
xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
key_info = xmlsec.template.ensure_key_info(signature_node)
xmlsec.template.add_x509_data(key_info)

# Append Signature to XML
xml.getroot().append(signature_node)

# Sign the Document
ctx = xmlsec.SignatureContext()
ctx.key = xmlsec.Key.from_memory(pem_private, xmlsec.constants.KeyDataFormatPem, None)
ctx.sign(signature_node)

# Save Signed XML
signed_xml = etree.tostring(xml, pretty_print=True)
with open('signed_invoice.xml', 'wb') as signed_out:
    signed_out.write(signed_xml)

print("Document signed successfully.")
