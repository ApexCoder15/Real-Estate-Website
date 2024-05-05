import os

from OpenSSL import crypto
from pyhanko.sign import signers
import rsa
import OpenSSL
import os
import time
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from PDFNetPython3.PDFNetPython import *
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, timestamps, fields
from pyhanko.sign.fields import *
from pyhanko_certvalidator import ValidationContext
from pyhanko import stamp
from pyhanko.pdf_utils import text
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
import threading

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def uniquify(path):
    filename, extension = os.path.splitext(path)
    counter = 1

    while os.path.exists(path):
        path = filename + "_" + str(counter) + extension
        counter += 1

    return path

def get_cert_path(user_email):
    return os.path.join('cert_keys/'+user_email+'_certificate.pem')

def get_private_key_path(user_email):
    return os.path.join('user_keys/'+user_email+'_private_key.pem')

def create_self_signed_cert(priv_key, pub_key, signer_name):
    cert = OpenSSL.crypto.X509()   #An X.509 certificate.
    # This creates a new X509Name that wraps the 
    # underlying subject name field on the 
    # certificate. Modifying it will modify 
    # the underlying certificate, and will have 
    # the effect of modifying any other X509Name 
    # that refers to this subject.
    cert.get_subject().CN = signer_name    
    # Serial Number
    cert.set_serial_number(int(time.time() * 10))    
    # Not Before
    cert.gmtime_adj_notBefore(0)  # Not before
    # Not After (Expire after 10 years)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)    
    # Identify issue
    cert.set_issuer((cert.get_subject()))
    cert.set_pubkey(pub_key)   # public key of the certificate holder
    cert.sign(priv_key, 'sha256') # private key of issuing authority
    return cert

def create_cert(signer_name, private_key_path, public_key_path):  # creating keys and certificate    
    # certificate
    with open(private_key_path, 'rb') as f:
        key_data = f.read()
    # Load the .pem file as a PKey object using the FILETYPE_PEM constant
    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
    with open(public_key_path, 'rb') as f:
        key_data = f.read()
    # Load the .pem file as a PKey object using the FILETYPE_PEM constant
    public_key = crypto.load_publickey(crypto.FILETYPE_PEM, key_data)

    cert = create_self_signed_cert(private_key, public_key, signer_name)
    certificate_path = os.path.join("cert_keys/" + signer_name + '_certificate.pem')
    with open(certificate_path, 'wb') as cer:
        cer_str = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        cer.write(cer_str)
    return certificate_path

def sign_pdf(identity, pdf_path,certificate_path, private_key_path):
    #Load certificates and key material from PEM/DER files.
    #Returns A SimpleSigner object initialised with key material loaded from the files provided.
    signer = signers.SimpleSigner.load(private_key_path, certificate_path)
    print(signer)
    field_name = 'Signature' + identity    
    if identity=='Seller':
        sz = (200, 550, 400, 610)
    else:
        sz = (200, 600, 400, 660)    
    with open(pdf_path, 'rb') as inf:
        # Class to incrementally update existing files.
        # Incremental updates to a PDF file append modifications to the end of the file. 
        # This is critical when the original file contents are not to be modified directly
        #  (e.g. when it contains digital signatures). It has the additional advantage of
        #  providing an automatic audit trail of sorts.
        w = IncrementalPdfFileWriter(inf)
        # fields.SigFieldSpec: Description of a signature field to be created.
        fields.append_signature_field(
            w, sig_field_spec=fields.SigFieldSpec(
                field_name, box=sz
            )
        )
        fields.MDPPerm(2)
        meta = signers.PdfSignatureMetadata(field_name)
        #Class to handle PDF signatures in general.
        pdf_signer = signers.PdfSigner(
            meta, signer=signer
        )
        signed_pdf_path = pdf_path.replace('.pdf', '_signed.pdf')
        with open(signed_pdf_path, 'wb') as outf:
            pdf_signer.sign_pdf(w, output=outf)
    os.remove(pdf_path)
    os.rename(signed_pdf_path, pdf_path)
    return pdf_path


def verify_pdf(buyer_certificate_path,seller_certificate_path,signed_pdf_path):
    root_cert1 = load_cert_from_pemder(seller_certificate_path)
    vc1 = ValidationContext(trust_roots=[root_cert1])
    root_cert2 = load_cert_from_pemder(buyer_certificate_path)
    vc2 = ValidationContext(trust_roots=[root_cert2])
    with open(seller_certificate_path, 'rb') as f:
        temp = f.read
        print(temp)
    with open(signed_pdf_path, 'rb') as doc:
        r = PdfFileReader(doc)
        status1 = validate_pdf_signature(r.embedded_signatures[1], vc1)
        status2 = validate_pdf_signature(r.embedded_signatures[1], vc2)
        #print(r.embedded_signatures[0].signer_cert)
        #print(r.embedded_signatures[1])
        (status1.pretty_print_details())
        print(status2.pretty_print_details())


# Function to create a PDF document
def create_pdf(data, filename):
    c = canvas.Canvas(filename, pagesize=letter)
    # Set font and font size
    c.setFont("Helvetica", 12)
    # Add data to the PDF
    for line in data:
        c.drawString(100, 700, line)  # (x, y, text)
    # Save the PDF
    c.save()


