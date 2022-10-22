############################################################################
# JOHN HUETTER, THOMAS CHILTON CALIFORNIA ISO
# 20200320
############################################################################

############################################################################
# Disclaimer of Warranty
# The CAISO API is provided “as is” and CAISO disclaims all warranties, conditions, or representations
# (express, implied, oral or written) with respect to the CAISO API and any support related thereto,
# including all warranties of merchantability, compatibility, fitness for a particular purpose,
# non-infringement, non-interference, accuracy of data, and warranties arising from a course of dealing.
# For further information, see CAISO Privacy Notice and Terms of Use
# (http://www.caiso.com/Pages/PrivacyPolicy.aspx ).
############################################################################

import base64
import os
from uuid import uuid4

import xmlsec
from lxml import etree
from OpenSSL import crypto

"""Functions for WS-Security (WSSE) signature creation and verification.
  Heavily based on test examples in https://github.com/mehcode/python-xmlsec as
  well as the xmlsec documentation at https://www.aleksey.com/xmlsec/.
  Reading the xmldsig, xmlenc, and ws-security standards documents, though
  admittedly painful, will likely assist in understanding the code in this
  module.
"""


class CAISOB2BUtils:

    # ----------------------------------------------------------------------------------------------------
    def __init__(self, log=None):

        if log:
            self.log = log
        else:
            self.log = self.initLogging()

        self.log.debug("CAISOB2BUtils Initialized")

        self.verbose = False
        self.service = None
        self.environment = None
        self.request_body = None
        self.private_key_pfx_filename = None
        self.private_key_pem_filename = None
        self.private_key_pass = None
        self.tmpdirname = None
        self.username = None
        self.issuing_pem_filename = self.private_key_pem_filename
        self.soapaction = None
        self.endpoint = None
        self.openssl_path = None
        self.unpack_retrieve_attachments = None
        self.attachment_file = None

        self.SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
        self.DS_NS = "http://www.w3.org/2000/09/xmldsig#"
        self.ENC_NS = "http://www.w3.org/2001/04/xmlenc#"
        self.WSS_BASE = "http://docs.oasis-open.org/wss/2004/01/"
        self.WSSE_NS = self.WSS_BASE + "oasis-200401-wss-wssecurity-secext-1.0.xsd"
        self.WSU_NS = self.WSS_BASE + "oasis-200401-wss-wssecurity-utility-1.0.xsd"
        self.BASE64B = (
            self.WSS_BASE + "oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        )
        self.X509TOKEN = (
            self.WSS_BASE + "oasis-200401-wss-x509-token-profile-1.0#X509v3"
        )

    # ----------------------------------------------------------------------------------------------------
    def initLogging(self):

        try:

            # Set up logging
            import logging
            from logging import StreamHandler

            # Set up a rotating log
            logger = logging.getLogger("caiso-b2bUtils")
            logger.setLevel(logging.INFO)

            handler = StreamHandler()

            # create formatter and add it to the handlers
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            return logger

        except Exception as err:
            raise Exception("CAISO-800: Problem while initializing logger") from err

    # ----------------------------------------------------------------------------------------------------
    def validate(self):
        self.log.info(__file__ + " validated")

    # ----------------------------------------------------------------------------------------------------
    def ns(self, namespace, tagname):
        return "{%s}%s" % (namespace, tagname)

    # ----------------------------------------------------------------------------------------------------
    def get_unique_id(self):
        return "id-{0}".format(uuid4())

    # ----------------------------------------------------------------------------------------------------
    def ensure_id(self, node):
        """Ensure given node has a wsu:Id attribute; add unique one if not.
        Return found/created attribute value.
        """
        ID_ATTR = self.ns(self.WSU_NS, "Id")

        id_val = node.get(ID_ATTR)
        if not id_val:
            id_val = self.get_unique_id()
            node.set(ID_ATTR, id_val)

        return id_val

    # ----------------------------------------------------------------------------------------------------
    def create_key_info_bst(self, security_token):

        # Create the KeyInfo node.
        key_info = etree.Element(
            self.ns(self.DS_NS, "KeyInfo"), nsmap={"ds": self.DS_NS}
        )

        # Create a wsse:SecurityTokenReference node within KeyInfo.
        sec_token_ref = etree.SubElement(
            key_info, self.ns(self.WSSE_NS, "SecurityTokenReference")
        )
        sec_token_ref.set(
            self.ns(self.WSSE_NS, "TokenType"), security_token.get("ValueType")
        )

        # Add a Reference to the BinarySecurityToken in the SecurityTokenReference.
        bst_id = self.ensure_id(security_token)
        reference = etree.SubElement(sec_token_ref, self.ns(self.WSSE_NS, "Reference"))
        reference.set("ValueType", security_token.get("ValueType"))
        reference.set("URI", "#%s" % bst_id)

        return key_info

    # ----------------------------------------------------------------------------------------------------
    def create_binary_security_token(self):
        try:
            """Create a BinarySecurityToken node containing the x509 certificate.
            Modified from https://github.com/mvantellingen/py-soap-wsse.
            """
            # Create the BinarySecurityToken node with appropriate attributes.
            node = etree.Element(self.ns(self.WSSE_NS, "BinarySecurityToken"))
            node.set("EncodingType", self.BASE64B)
            node.set("ValueType", self.X509TOKEN)

            # Set the node contents.
            with open(self.issuing_pem_filename) as fh:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, fh.read())
                node.text = base64.b64encode(
                    crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
                )

            return node

        except Exception as err:
            raise Exception("CAISO-801: Problem creating BST") from err

    # ----------------------------------------------------------------------------------------------------
    def sign(self, envelope):

        try:

            self.log.debug("Creating BST ...")
            """Sign given SOAP envelope with WSSE sig using given key and cert.
      Sign the wsu:Timestamp node in the wsse:Security header and the soap:Body;
      both must be present.
      Add a ds:Signature node in the wsse:Security header containing the
      signature.
      Use EXCL-C14N transforms to normalize the signed XML (so that irrelevant
      whitespace or attribute ordering changes don't invalidate the
      signature). Use SHA1 signatures.
      Expects to sign an incoming document something like this (xmlns attributes
      omitted for readability):
      <soap:Envelope>
        <soap:Header>
          <wsse:Security mustUnderstand="true">
            <wsu:Timestamp>
              <wsu:Created>2015-06-25T21:53:25.246276+00:00</wsu:Created>
              <wsu:Expires>2015-06-25T21:58:25.246276+00:00</wsu:Expires>
            </wsu:Timestamp>
          </wsse:Security>
        </soap:Header>
        <soap:Body>
          ...
        </soap:Body>
      </soap:Envelope>
      After signing, the sample document would look something like this (note the
      added wsu:Id attr on the soap:Body and wsu:Timestamp nodes, and the added
      ds:Signature node in the header, with ds:Reference nodes with URI attribute
      referencing the wsu:Id of the signed nodes):
      <soap:Envelope>
        <soap:Header>
          <wsse:Security mustUnderstand="true">
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod
                    Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <SignatureMethod
                    Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <Reference URI="#id-d0f9fd77-f193-471f-8bab-ba9c5afa3e76">
                  <Transforms>
                    <Transform
                        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                  </Transforms>
                  <DigestMethod
                      Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>nnjjqTKxwl1hT/2RUsBuszgjTbI=</DigestValue>
                </Reference>
                <Reference URI="#id-7c425ac1-534a-4478-b5fe-6cae0690f08d">
                  <Transforms>
                    <Transform
                        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                  </Transforms>
                  <DigestMethod
                      Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>qAATZaSqAr9fta9ApbGrFWDuCCQ=</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>Hz8jtQb...bOdT6ZdTQ==</SignatureValue>
              <KeyInfo>
                <wsse:SecurityTokenReference>
                  <X509Data>
                    <X509Certificate>MIIDnzC...Ia2qKQ==</X509Certificate>
                    <X509IssuerSerial>
                      <X509IssuerName>...</X509IssuerName>
                      <X509SerialNumber>...</X509SerialNumber>
                    </X509IssuerSerial>
                  </X509Data>
                </wsse:SecurityTokenReference>
              </KeyInfo>
            </Signature>
            <wsu:Timestamp wsu:Id="id-7c425ac1-534a-4478-b5fe-6cae0690f08d">
              <wsu:Created>2015-06-25T22:00:29.821700+00:00</wsu:Created>
              <wsu:Expires>2015-06-25T22:05:29.821700+00:00</wsu:Expires>
            </wsu:Timestamp>
          </wsse:Security>
        </soap:Header>
        <soap:Body wsu:Id="id-d0f9fd77-f193-471f-8bab-ba9c5afa3e76">
          ...
        </soap:Body>
      </soap:Envelope>
      """
            self.log.debug("Reading in XML ...")
            doc = etree.fromstring(envelope)

            # Create the Signature node.
            self.log.debug("Setting signature ...")
            signature = xmlsec.template.create(
                doc,
                xmlsec.Transform.EXCL_C14N,
                xmlsec.Transform.RSA_SHA1,
            )

            # Add a KeyInfo node with X509Data child to the Signature. XMLSec will fill
            # in this template with the actual certificate details when it signs.
            # print("Key info ...")
            # key_info = xmlsec.template.ensure_key_info(signature)
            # x509_data = xmlsec.template.add_x509_data(key_info)
            # x509_issuer_serial = etree.Element(ns(DS_NS, 'X509IssuerSerial'))
            # x509_data.append(x509_issuer_serial)
            # x509_certificate = etree.Element(ns(DS_NS, 'X509Certificate'))
            # x509_data.append(x509_certificate)

            # Load the signing key and certificate.
            self.log.debug("Loading key ...")
            try:
                key = xmlsec.Key.from_file(
                    self.private_key_pem_filename,
                    xmlsec.KeyFormat.PEM,
                    self.private_key_pass,
                )
            except Exception as err:
                raise Exception(
                    "CAISO-802: Problem loading private key -- check file and pass",
                ) from err
            self.log.debug("Loading cert ...")
            key.load_cert_from_file(self.issuing_pem_filename, xmlsec.KeyFormat.PEM)

            # Insert the Signature node in the wsse:Security header.
            self.log.debug("Setting header ...")
            header = doc.find(self.ns(self.SOAP_NS, "Header"))

            self.log.debug("Making sure security element is in the header")
            try:
                security = header.find(self.ns(self.WSSE_NS, "Security"))
                etree.tostring(security)
            except Exception:
                self.log.debug("Security element does not exist, adding ...")
                pass
                try:
                    new_security = etree.Element(self.ns(self.WSSE_NS, "Security"))
                    header.insert(0, new_security)
                    etree.tostring(new_security)
                except Exception:
                    self.log.error("CAISO-816: Could not add new element: Security")
                    pass

            self.log.debug("OK done with that now the header should be there ...")
            security = header.find(self.ns(self.WSSE_NS, "Security"))
            security.insert(0, signature)

            cert_bst = self.create_binary_security_token()
            security.insert(0, cert_bst)

            # Create a ds:KeyInfo node referencing the BinarySecurityToken we just
            # created, and insert it into the EncryptedKey node.

            # Perform the actual signing.
            self.log.debug("Setting ctx ...")
            ctx = xmlsec.SignatureContext()
            ctx.key = key

            self.log.debug("Signing body as it always needs to be signed ...")
            self._sign_node(
                ctx,
                signature,
                doc.find(self.ns("http://schemas.xmlsoap.org/soap/envelope/", "Body")),
            )

            self.log.debug("Signing BinarySecurityToken  ...")
            self._sign_node(
                ctx,
                signature,
                security.find(self.ns(self.WSSE_NS, "BinarySecurityToken")),
            )

            self.log.debug("Signing CAISOWSHeader ...")
            self.log.debug(self.ns(self.SOAP_NS, "Body"))
            self.log.debug(
                self.ns(
                    "http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd",
                    "CAISOWSHeader",
                )
            )

            try:
                self._sign_node(
                    ctx,
                    signature,
                    header.find(
                        self.ns(
                            "http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd",
                            "CAISOWSHeader",
                        )
                    ),
                )
            except Exception:
                self.log.debug("Could not sign CAISOWSHeader (maybe it does not exist)")
                pass

            try:
                self._sign_node(
                    ctx,
                    signature,
                    header.find(
                        self.ns(
                            "http://www.caiso.com/mrtu/soa/schemas/2005/09/attachmenthash",
                            "attachmentHash",
                        )
                    ),
                )
            except Exception:
                self.log.debug(
                    "Could not sign attachmentHash (maybe it does not exist)"
                )
                pass

            try:
                self._sign_node(
                    ctx,
                    signature,
                    header.find(
                        self.ns(
                            "http://www.caiso.com/soa/2006-06-13/StandardAttachmentInfor.xsd",
                            "standardAttachmentInfor",
                        )
                    ),
                )
            except Exception:
                self.log.debug(
                    "Could not sign standardAttachmentInfor (maybe it does not exist)"
                )
                pass

            self.log.debug("Signing last ...")

            keyinfo = self.create_key_info_bst(cert_bst)

            ctx.sign(signature)

            # Check where everything is
            # doc = etree.fromstring(envelope)
            header = doc.find(self.ns(self.SOAP_NS, "Header"))
            security = header.find(self.ns(self.WSSE_NS, "Security"))
            signature = security.find(self.ns(self.DS_NS, "Signature"))

            self.log.debug("Setting token ref ...")
            signature.append(keyinfo)

            """Place the X509 data inside a WSSE SecurityTokenReference within
            KeyInfo. The recipient expects this structure, but we can't rearrange
            like this until after signing, because otherwise xmlsec won't populate
            the X509 data (because it doesn't understand WSSE).
            """

            self.log.debug("Done with signing")
            return etree.tostring(doc)

        except Exception as err:
            raise Exception("CAISO-805: Problem with signing") from err

    # ----------------------------------------------------------------------------------------------------
    def verify(envelope, self):

        self.log.info("Verifying ...")
        """Verify WS-Security signature on given SOAP envelope with given cert.
        Expects a document like that found in the sample XML in the ``sign()``
        docstring.
        Raise SignatureValidationFailed on failure, silent on success.
        """
        doc = etree.fromstring(envelope)
        header = doc.find(self.ns(self.SOAP_NS, "Header"))
        security = header.find(self.ns(self.WSSE_NS, "Security"))
        signature = security.find(self.ns(self.self.DS_NS, "Signature"))

        ctx = xmlsec.SignatureContext()

        # Find each signed element and register its ID with the signing context.
        refs = signature.xpath(
            "ds:SignedInfo/ds:Reference", namespaces={"ds": self.DS_NS}
        )

        for ref in refs:
            # Get the reference URI and cut off the initial '#'
            referenced_id = ref.get("URI")[1:]
            referenced = doc.xpath(
                "//*[@wsu:Id='%s']" % referenced_id,
                namespaces={"wsu": self.WSU_NS},
            )[0]
            ctx.register_id(referenced, "Id", self.WSU_NS)

        key = xmlsec.Key.from_file(
            self.issuing_pem_filename, xmlsec.KeyFormat.CERT_PEM, None
        )
        ctx.key = key

        try:
            ctx.verify(signature)
        except xmlsec.Error as err:
            # Sadly xmlsec gives us no details about the reason for the failure, so
            # we have nothing to pass on except that verification failed.
            raise Exception("CAISO-806: Signature Vertification Failed") from err

    # ----------------------------------------------------------------------------------------------------
    def _sign_node(self, ctx, signature, target):
        """Add sig for ``target`` in ``signature`` node, using ``ctx`` context.
        Doesn't actually perform the signing; ``ctx.sign(signature)`` should be
        called later to do that.
        Adds a Reference node to the signature with URI attribute pointing to the
        target node, and registers the target node's ID so XMLSec will be able to
        find the target node by ID when it signs.
        """
        # Ensure the target node has a wsu:Id attribute and get its value.
        node_id = self.ensure_id(target)
        # Add reference to signature with URI attribute pointing to that ID.
        ref = xmlsec.template.add_reference(
            signature, xmlsec.Transform.SHA1, uri="#" + node_id
        )
        """This is an XML normalization transform which will be performed on the
        target node contents before signing. This ensures that changes to
        irrelevant whitespace, attribute ordering, etc won't invalidate the
        signature.
        """
        xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
        """Unlike HTML, XML doesn't have a single standardized Id. WSSE suggests the
        use of the wsu:Id attribute for this purpose, but XMLSec doesn't
        understand that natively. So for XMLSec to be able to find the referenced
        node by id, we have to tell xmlsec about it using the register_id method.
        """
        ctx.register_id(target, "Id", self.WSU_NS)

    # ----------------------------------------------------------------------------------------------------
    def convert_pfx_pem(self, pfx_file_name, pfx_pass_phrase):

        import subprocess

        try:
            pem_dict = {
                "private_key_pem_filename": self.tmpdirname + "/private.pem",
                "cert_filename": self.tmpdirname + "/cert",
            }

            if os.path.isfile(pfx_file_name) is False:
                self.log.error(
                    "CAISO-702: convert_pfx_pem -- No such PRIVATE KEY PFX file: "
                    + pfx_file_name
                    + ", cannot continue"
                )
                return None
            else:
                self.log.debug("PRIVATE KEY PFX file exists: " + pfx_file_name)

            if os.path.isfile(self.openssl_path) is False:
                self.log.error(
                    "CAISO-703: convert_pfx_pem -- OPENSSL NOT INSTALLED -- Cannot find "
                    + self.openssl_path
                )
                return None
            else:
                self.log.debug(self.openssl_path + " installed and OK")

            # THIS BELOW IS IF WE ARE TRYING TO DO IT WITH UNIX COMMAND LINE
            try:
                command = (
                    self.openssl_path
                    + " pkcs12 -in "
                    + pfx_file_name
                    + " -out "
                    + pem_dict["private_key_pem_filename"]
                    + " -nodes -password pass:"
                    + pfx_pass_phrase
                    + " >/dev/null 2>&1 "
                )
                self.log.debug("Running openssl pfx to pem conversion")
                # Process is not used after this but here it's load-bearing
                process = subprocess.check_output(command, shell=True)
            except OSError:
                self.log.error("CAISO-807: Problem with openssl OSError")
                return None
            except subprocess.CalledProcessError:
                self.log.error("CAISO-808: Problem with openssl CalledProcessError")
                return None
            except Exception:
                self.log.error("CAISO-809: Problem with openssl")
                return None

            # Make sure private_key_pem_filename is there:
            if os.path.isfile(pem_dict["private_key_pem_filename"]) is False:
                self.log.error(
                    "CAISO-704: convert_pfx_pem -- No such PRIVATE KEY PEM file: "
                    + pem_dict["private_key_pem_filename"]
                    + ", cannot continue"
                )
                return None
            else:
                self.log.debug(
                    "CREATED PRIVATE KEY PEM file FROM PKS/P12 OK: "
                    + pem_dict["private_key_pem_filename"]
                )

            pem_dict["cert_filename"] = pem_dict["private_key_pem_filename"]
            return pem_dict

        except Exception as err:
            raise Exception(
                "CAISO-810: Problem while converting PFX cert to PEM"
            ) from err

    # ----------------------------------------------------------------------------------------------------
    def wsse_sign_xml_payload(self, caiso_request_xml_unsigned):

        try:

            # If the cert is a p12 or a pfx:
            if self.private_key_pfx_filename:
                pem_dict = self.convert_pfx_pem(
                    self.private_key_pfx_filename, self.private_key_pass
                )
                if pem_dict is None:
                    return None

                self.private_key_pem_filename = pem_dict["private_key_pem_filename"]
                self.issuing_pem_filename = pem_dict["private_key_pem_filename"]
            elif os.path.isfile(self.private_key_pem_filename) is False:
                self.log.error(
                    "CAISO-711: No file detected at '"
                    + self.private_key_pem_filename
                    + "'"
                )
                return None

            caiso_request_xml_signed = self.sign(caiso_request_xml_unsigned)

            self.log.debug("PEM FILE: " + self.private_key_pem_filename)

            return caiso_request_xml_signed

        except Exception as err:
            raise Exception(
                "CAISO-811: Problem while signing XML payload" + str(err)
            ) from err

    # ----------------------------------------------------------------------------------------------------
    def get_basic_response_xml(self, response):

        try:

            import lxml

            # Run this to make sure what we have is XML
            # -- we aren't doing anything with it but it will bomb if not XML
            root = lxml.etree.fromstring(response.text.encode("utf-8"))
            response_xml = response.text
            if "soapenv" in response_xml:
                self.log.debug("Standardizing 'soapenv' in response as 'SOAP-ENV'")
                response_xml = response_xml.replace("soapenv", "SOAP-ENV")
            return response_xml

        except Exception as err:
            self.log.error(
                "CAISO-812: "
                + self.service
                + " Exception caught in get_basic_response_xml."
                + " This response may not be XML"
            )
            self.log.debug(self.service + " ERROR " + str(err))
            return None

    # ----------------------------------------------------------------------------------------------------
    def get_multipart_parts(self, response):

        try:

            xml_response = None
            uue_response = None

            self.log.debug("Processing multi-part message")

            # Get the boundary:
            response_content_type = response.headers["Content-Type"]
            response_content_type_elements = response_content_type.split(";")
            for element in response_content_type_elements:
                if "boundary=" in element:
                    boundary = "--" + element.split("boundary=")[1].replace('"', "")
            self.log.debug("Boundary: " + boundary)

            elements = response.text.split("\r\n")

            for element in elements:

                if ": " in element:
                    continue

                if boundary in element:
                    continue

                if len(element) < 3:
                    continue

                # If this is the XML
                if "SOAP-ENV" in element or "soapenv" in element:
                    xml_response = element.replace("\r\n", "\n")
                    if (
                        "soapenv" in xml_response
                    ):  # The rest of the program expects SOAP-ENV
                        self.log.debug(
                            "Standardizing 'soapenv' in response as 'SOAP-ENV'"
                        )
                        xml_response = xml_response.replace("soapenv", "SOAP-ENV")
                    continue

                # We got the xml so now this other part must be the UUE
                if xml_response:
                    uue_response = element.replace("\r\n", "\n")

            return xml_response, uue_response

        except Exception as err:
            raise Exception(
                "CAISO-813: Problem while parsing multipart response"
            ) from err

    # ----------------------------------------------------------------------------------------------------
    def xml_to_uue(self, xml_data):

        try:

            import base64
            import hashlib
            import zlib

            bytes = xml_data.encode("utf-8")
            compress = zlib.compressobj(
                zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, 16 + zlib.MAX_WBITS
            )
            compressed_data = compress.compress(bytes) + compress.flush()

            if compressed_data is None:
                return None
            else:
                uue = base64.b64encode(compressed_data)
                hash = base64.b64encode(hashlib.sha1(uue).digest())
                self.log.debug("XML_TO_UUE UUE: " + str(uue))
                self.log.debug("XML_TO_UUE HASH: " + str(hash))
                return uue.decode("utf-8"), hash.decode("utf-8")

        except Exception as err:
            raise Exception("CAISO-814: Problem while converting XML to UUE") from err

    # ----------------------------------------------------------------------------------------------------
    def uue_to_xml(self, uue_data):

        try:
            import base64
            import zlib

            self.log.debug("Trying to uue_to_xml ...")
            gzip_data = base64.b64decode(uue_data)
            if gzip_data is None:
                return None
            else:
                xml = zlib.decompress(gzip_data, 16 + zlib.MAX_WBITS).decode("utf-8")
                return xml

        except Exception as err:
            raise Exception("CAISO-815: Problem while converting UUE to XML") from err

    # ----------------------------------------------------------------------------------------------------
    # We got an HTML or other response from CAISO
    def caiso_parse_response_html(self, response, response_dict):

        try:

            if "CAISO Acceptable Use Policy Violation" in response.text:
                self.log.error(
                    self.service + "CAISO-901: CAISO Acceptable Use Policy Violation"
                )
                response_dict["errors"].append(
                    "CAISO-901: CAISO Acceptable Use Policy Violation"
                )

            if "You are not authorized to access this page." in response.text:
                self.log.error(self.service + "CAISO-902: ACCESS DENIED")
                response_dict["errors"].append("CAISO-902: ACCESS DENIED")

            if response.status_code == 403:
                self.log.error(
                    self.service
                    + " CAISO-903: HTTP 403 ERROR"
                    + " -- ENSURE YOUR CERT HAS ACCESS TO THIS SITE"
                )
                response_dict["errors"].append(
                    "CAISO-903: HTTP 403 ERROR"
                    + " -- ENSURE YOUR CERT HAS ACCESS TO THIS SITE"
                )

            if response.status_code == 404:
                self.log.error(
                    self.service
                    + " CAISO-904: HTTP 404 Check service URL -- 404 NOT FOUND. "
                    + "CHECK CONFIG FOR THE PATH TO THIS SERVICE: "
                    + self.endpoint
                    + ".  TRY LOADING IN BROWSER"
                )
                response_dict["errors"].append(
                    "CAISO-904: HTTP 404 Check service URL -- 404 NOT FOUND. "
                    + "CHECK CONFIG FOR THE PATH TO THIS SERVICE: "
                    + self.endpoint
                    + ".   TRY LOADING IN BROWSER"
                )

            return response_dict

        except Exception as err:
            raise Exception("CAISO-817: Problem while parsing response html") from err

    # ----------------------------------------------------------------------------------------------------
    # We got a proper XML response from CAISO
    def caiso_parse_response_xml(
        self, status_code, response_xml, response_dict, attachment_uue=None
    ):

        try:

            problem_detected = False

            # Look for common reasons why this reponse may have failed and raise them up
            self.log.info(self.service + " Running basic checks on XML response")

            if response_xml is None:
                self.log.error(self.service + "CAISO-907: NO RESPONSE XML TO CHECK")
                response_dict["errors"].append("CAISO-907: NO RESPONSE XML TO CHECK")
                return response_dict

            if "Signature validation status: false" in response_xml:
                self.log.error(
                    "CAISO-908: "
                    + self.service
                    + " MESSAGE WAS NOT SIGNED PROPERLY. ENSURE YOUR PFX or PEM"
                    + " FILE CONTAINS THE PRIVATE KEY AND CHECK PASSWORD."
                )
                response_dict["errors"].append(
                    "CAISO-908: "
                    + self.service
                    + " MESSAGE WAS NOT SIGNED PROPERLY. ENSURE YOUR PFX or PEM"
                    + " FILE CONTAINS THE PRIVATE KEY AND CHECK PASSWORD."
                )

            if "CAISOUsernameToken Validation Error." in response_xml:
                self.log.error(
                    "CAISO-905: "
                    + self.service
                    + " WRONG USERNAME IN XML: "
                    + self.username
                )
                response_dict["errors"].append(
                    "CAISO-905: "
                    + self.service
                    + " WRONG USERNAME IN XML: "
                    + self.username
                )

            if attachment_uue:
                if len(attachment_uue) < 5000:
                    attachment_xml = response_dict["attachment_xml"]
                    if attachment_xml is None:
                        attachment_xml = self.uue_to_xml(attachment_uue)
                        response_dict["attachment_xml"] = attachment_xml

                    if "Invalid role and/or Entity list identifier." in attachment_xml:
                        self.log.error(
                            "CAISO-906: "
                            + self.service
                            + " INVALID ROLE OR ENTITY LIST -- CHECK THAT YOUR"
                            + " CERT HAS ACCESS TO THE ENTITIES OR SCID YOU ARE"
                            + " QUERYING IN THIS ENVIRONMENT. PLEASE ENGAGE YOUR UAA."
                        )
                        response_dict["errors"].append(
                            "CAISO-906: "
                            + self.service
                            + " INVALID ROLE OR ENTITY LIST -- CHECK THAT YOUR"
                            + " CERT HAS ACCESS TO THE ENTITIES OR SCID YOU ARE"
                            + " QUERYING IN THIS ENVIRONMENT. PLEASE ENGAGE YOUR UAA."
                        )

            if status_code == 403:
                self.log.error(
                    "CAISO-903: "
                    + self.service
                    + " HTTP 403 ERROR -- ENSURE YOUR CERT HAS ACCESS TO THIS SITE IN"
                    + " THIS ENVIRONMENT. PLEASE ENGAGE YOUR UAA."
                )
                response_dict["errors"].append(
                    "CAISO-903: "
                    + self.service
                    + " HTTP 403 ERROR -- ENSURE YOUR CERT HAS ACCESS TO THIS SITE IN"
                    + " THIS ENVIRONMENT. PLEASE ENGAGE YOUR UAA."
                )

            elif status_code == 404:
                self.log.error(
                    "CAISO-904: "
                    + self.service
                    + " HTTP 404 ERROR -- Check service URL -- 404 NOT FOUND. CHECK"
                    + " CONFIG FOR THE PATH TO THIS SERVICE: "
                    + self.endpoint
                    + ".  TRY LOADING IN BROWSER"
                )
                response_dict["errors"].append(
                    "CAISO-904: "
                    + self.service
                    + " HTTP 404 ERROR -- Check service URL -- 404 NOT FOUND. CHECK"
                    + " CONFIG FOR THE PATH TO THIS SERVICE: "
                    + self.endpoint
                    + ".  TRY LOADING IN BROWSER"
                )

            elif status_code == 500:

                import lxml.etree

                error_description = None
                root = lxml.etree.fromstring(response_xml.encode("utf-8"))

                try:
                    error_description = root.xpath(
                        "/SOAP-ENV:Envelope/SOAP-ENV:Body/SOAP-ENV:Fault/detail/ns1:outputDataType/ns1:EventLog/ns1:Event/ns1:description",
                        namespaces={
                            "SOAP-ENV": "http://schemas.xmlsoap.org/soap/envelope/",
                            "ns1": "http://www.caiso.com/soa/2006-06-13/StandardOutput.xsd",
                        },
                    )[0].text
                except Exception:
                    # Nothing at this xpath, move on ...
                    pass

                try:
                    error_description = root.xpath(
                        "/SOAP-ENV:Envelope/SOAP-ENV:Body/SOAP-ENV:Fault/detail/StandardOutput/MessagePayload/EventLog/Event/description",
                        namespaces={
                            "SOAP-ENV": "http://schemas.xmlsoap.org/soap/envelope/",
                        },
                    )[0].text
                except Exception:
                    # Nothing at this xpath, move on ...
                    pass

                if error_description:
                    self.log.error(
                        "CAISO-900: " + self.service + " HTTP 500 ERROR IN RESPONSE: "
                    )
                    self.log.error("CAISO-900: " + error_description)
                    self.log.error("CAISO-900: Your request could not be completed")
                    response_dict["errors"].append(
                        "CAISO-900: "
                        + self.service
                        + " HTTP 500 ERROR IN RESPONSE: "
                        + error_description
                        + " Your request could not be completed"
                    )
                else:
                    self.log.error(
                        "CAISO-900: "
                        + self.service
                        + " HTTP 500 ERROR IN RESPONSE BUT COULD NOT BE PARSED "
                    )
                    self.log.error("CAISO-900: Your request could not be completed")
                    response_dict["errors"].append(
                        "CAISO-900: "
                        + self.service
                        + " HTTP 500 ERROR IN RESPONSE BUT COULD NOT BE PARSED "
                        + "Your request could not be completed"
                    )

            return response_dict

        except Exception as err:

            raise Exception("CAISO-818: Problem while parsing XML response") from err
            return problem_detected

    # ----------------------------------------------------------------------------------------------------
    def responseParsing(self, response, response_dict):
        # A response has been received, so let's see what we got
        import hashlib

        import lxml.etree

        if "submit" in self.service:

            self.log.debug(self.service + " CHECKING SUBMIT RESPONSE")

            # Submit responses all look the same for docattach or non-docattach
            # They will not have a multipart MIME structure
            response_xml = self.get_basic_response_xml(response)
            if response_xml:
                response_dict["response_xml"] = response_xml
                self.log.debug(self.service + " Response XML: " + response_xml)

                # Do common check of payloads for errors or interesting messages
                response_dict = self.caiso_parse_response_xml(
                    response.status_code, response_xml, response_dict
                )
            else:
                self.log.error(
                    "CAISO-909: "
                    + self.service
                    + " Did not get a response we could work with"
                    + " -- checking the response HTML"
                )
                response_dict = self.caiso_parse_response_html(response, response_dict)

        elif "retrieve" in self.service:

            self.log.debug(self.service + " CHECKING RETRIEVE RESPONSE")

            if "DocAttach" in self.service:

                # WE ARE DOCATTACH RETRIEVE
                # There will not be a multipart MIME structure, just XML
                response_xml = self.get_basic_response_xml(response)
                if response_xml:
                    if response.status_code == 200:

                        # WE ARE A DOCATTACH RETRIEVE WHICH SUCCEEDED
                        response_dict["response_xml"] = response_xml
                        self.log.debug(
                            self.service + " DOCATTACH RESPONSE XML: " + response_xml
                        )

                        root = lxml.etree.fromstring(response_xml)

                        # Location of attachment when this is a DocAttach request
                        attachment_uue = None
                        try:
                            attachment_uue = root.xpath(
                                "/SOAP-ENV:Envelope/SOAP-ENV:Body/attachment:ISOAttachment/attachment:AttachmentValue",
                                namespaces={
                                    "SOAP-ENV": "http://schemas.xmlsoap.org/soap/envelope/",
                                    "attachment": "http://www.caiso.com/soa/2006-10-26/ISOAttachment.xsd",
                                },
                            )[0].text
                            response_dict["attachment_uue"] = attachment_uue

                            if (
                                self.unpack_retrieve_attachments
                                and response_dict["attachment_xml"] is None
                            ):
                                if response_dict["attachment_xml"] is None:
                                    response_dict["attachment_xml"] = self.uue_to_xml(
                                        attachment_uue.encode("utf-8")
                                    )
                                self.log.debug(
                                    "ATTACHMENT UUE AS XML: "
                                    + response_dict["attachment_xml"]
                                )

                            # Do common check of payloads for errors or interesting messages
                            response_dict = self.caiso_parse_response_xml(
                                response.status_code,
                                response_xml,
                                response_dict,
                                attachment_uue,
                            )
                        except Exception:
                            pass

                    else:

                        # WE ARE A DOCATTACH RETRIEVE WHICH FAILED
                        self.log.debug(self.service + " Response XML: " + response_xml)

                        # Do common check of payloads for errors or interesting messages
                        response_dict = self.caiso_parse_response_xml(
                            response.status_code, response_xml, response_dict
                        )

                else:
                    self.log.error(
                        "CAISO-909: "
                        + self.service
                        + " Did not get a response we could work with"
                        + " -- checking the response HTML"
                    )
                    response_dict = self.caiso_parse_response_html(
                        response, response_dict
                    )

            else:

                # WE ARE NOT DOCATTACH

                if response.status_code == 200:

                    # WE ARE A NON-DOCATTACH RETRIEVE WHICH SUCCEEDED
                    # The response might have a multipart MIME structure
                    response_xml, attachment_uue = self.get_multipart_parts(response)
                    if response_xml:
                        response_dict["response_xml"] = response_xml
                        self.log.debug(
                            self.service + " MULTIPART RESPONSE XML: " + response_xml
                        )
                        if attachment_uue:
                            response_dict["attachment_uue"] = attachment_uue
                            self.log.debug(
                                self.service
                                + " MULTIPART ATTACHMENT UUE: "
                                + attachment_uue
                            )
                            attachment_sha1 = base64.b64encode(
                                hashlib.sha1(attachment_uue.encode("utf-8")).digest()
                            ).decode("utf-8")
                            response_dict["attachment_sha1"] = attachment_sha1
                            root = lxml.etree.fromstring(response_xml.encode("utf-8"))
                            hash_value = root.xpath(
                                "/SOAP-ENV:Envelope/SOAP-ENV:Header/att:attachmentHash/att:hashValue",
                                namespaces={
                                    "SOAP-ENV": "http://schemas.xmlsoap.org/soap/envelope/",
                                    "att": "http://www.caiso.com/mrtu/soa/schemas/2005/09/attachmenthash",
                                },
                            )[0]
                            self.log.debug(
                                self.service
                                + " MULTIPART ATTACHMENT HASH VALUE (IN RESPONSE): "
                                + hash_value.text
                            )
                            self.log.debug(
                                self.service
                                + " MULTIPART ATTACHMENT HASH VALUE (CALCULATED) : "
                                + str(attachment_sha1)
                            )

                            # COMPARE HASH VALUE OF ATTACHMENT vs WHAT IS IN PAYLOAD
                            if hash_value.text == attachment_sha1:
                                self.log.debug(self.service + " sha1 validations OK")
                                if self.unpack_retrieve_attachments:
                                    if response_dict["attachment_xml"] is None:
                                        response_dict[
                                            "attachment_xml"
                                        ] = self.uue_to_xml(attachment_uue)
                                    self.log.debug(
                                        "ATTACHMENT UUE AS XML: "
                                        + response_dict["attachment_xml"]
                                    )

                                # Do common check of payloads for errors or interesting messages
                                response_dict = self.caiso_parse_response_xml(
                                    response.status_code,
                                    response_xml,
                                    response_dict,
                                    attachment_uue,
                                )

                            else:
                                self.log.error(
                                    self.service
                                    + " sha1 attachment validations FAILED -- NOT MATCHING "
                                    + hash_value.text
                                    + " VS "
                                    + str(attachment_sha1)
                                )
                                response_dict["errors"].append(
                                    "sha1 attachment validations FAILED -- NOT MATCHING "
                                    + hash_value.text
                                    + " VS "
                                    + str(attachment_sha1)
                                )

                        else:
                            self.log.info("No attachment")

                    else:
                        self.log.error(
                            "CAISO-909: "
                            + self.service
                            + " Did not get a response we could work with"
                            + " -- checking the response HTML"
                        )
                        response_dict = self.caiso_parse_response_html(
                            response, response_dict
                        )
                else:

                    # WE ARE A NON-DOCATTACH WHICH FAILED
                    response_xml = self.get_basic_response_xml(response)
                    if response_xml:
                        self.log.debug(self.service + " Response XML: " + response_xml)

                        # Do common check of payloads for errors or interesting messages
                        response_dict = self.caiso_parse_response_xml(
                            response.status_code, response_xml, response_dict
                        )
                    else:
                        self.log.error(
                            "CAISO-909: "
                            + self.service
                            + " Did not get a response we could work with"
                            + " -- checking the response HTML"
                        )
                        response_dict = self.caiso_parse_response_html(
                            response, response_dict
                        )

        return response_dict

    # ----------------------------------------------------------------------------------------------------
    def submit(self):

        try:
            import base64
            import datetime
            from datetime import timedelta

            import requests

            # Disable warnings which may fly across the screen unless verbose
            import urllib3

            # If verbose, print more info about the low level transport
            if self.verbose:
                import http.client

                def httpclient_log(*args):
                    self.log.debug("HTTP CLIENT DEBUGGER: " + " ".join(args))

                http.client.print = httpclient_log
                http.client.HTTPConnection.debuglevel = 1
            else:
                urllib3.disable_warnings()

            response_dict = {
                "return_code": None,
                "response_raw": None,
                "response_xml": None,
                "attachment_sha1": None,
                "attachment_uue": None,
                "attachment_xml": None,
                "errors": [],
            }

            # now = datetime.datetime.now()
            now = datetime.datetime.utcnow()
            later = now + timedelta(seconds=900)
            tomorrow = now + timedelta(seconds=86400)
            yesterday = now - timedelta(seconds=86400)
            trade_date_today = now.strftime("%Y-%m-%d")
            trade_date_tomorrow = tomorrow.strftime("%Y-%m-%d")
            trade_date_yesterday = yesterday.strftime("%Y-%m-%d")

            created_string = f'{now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]}Z'
            expires_string = f'{later.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]}Z'
            nonce_string = base64.b64encode(
                f'{now.strftime("%Y%m%d%H%M%S%f")[:-3]}'.encode("utf-8")
            ).decode("utf-8")

            # Common search and replace what not
            self.request_body = self.request_body.replace(
                "TRADE_DATE_TODAY", trade_date_today
            )
            self.request_body = self.request_body.replace(
                "TRADE_DATE_TOMORROW", trade_date_tomorrow
            )
            self.request_body = self.request_body.replace(
                "TRADE_DATE_YESTERDAY", trade_date_yesterday
            )

            from xml.etree import ElementTree as ET

            ET.register_namespace(
                "SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/"
            )
            ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
            ET.register_namespace(
                "caisowshead", "http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd"
            )
            ET.register_namespace(
                "infor",
                "http://www.caiso.com/soa/2006-06-13/StandardAttachmentInfor.xsd",
            )
            ET.register_namespace("att", "standardAttachmentInfor")

            envelope = ET.Element("{http://schemas.xmlsoap.org/soap/envelope/}Envelope")
            header = ET.SubElement(
                envelope, "{http://schemas.xmlsoap.org/soap/envelope/}Header"
            )
            body = ET.SubElement(
                envelope, "{http://schemas.xmlsoap.org/soap/envelope/}Body"
            )

            # If this is a submit give the attachment related stuff
            if "submit" in self.service:

                if os.path.isfile(self.attachment_file):
                    with open(self.attachment_file) as f:

                        file_data = f.read()
                        uue, attachment_sha1 = self.xml_to_uue(file_data)

                        if "DocAttach" in self.service:

                            standardattachmentinfor = ET.SubElement(
                                header,
                                "{http://www.caiso.com/soa/2006-06-13/StandardAttachmentInfor.xsd}standardAttachmentInfor",
                            )

                            isoattachment = ET.SubElement(
                                body,
                                "{http://www.caiso.com/soa/2006-10-26/ISOAttachment.xsd}ISOAttachment",
                            )
                            attachmentvalue = ET.SubElement(
                                isoattachment,
                                "{http://www.caiso.com/soa/2006-10-26/ISOAttachment.xsd}AttachmentValue",
                            )
                            attachmentvalue.text = uue

                        else:

                            standardattachmentinfor = ET.SubElement(
                                header,
                                "{http://www.caiso.com/soa/2006-06-13/StandardAttachmentInfor.xsd}standardAttachmentInfor",
                            )
                            attachment = ET.SubElement(
                                standardattachmentinfor,
                                "{http://www.caiso.com/soa/2006-06-13/StandardAttachmentInfor.xsd}Attachment",
                            )
                            id = ET.SubElement(
                                attachment,
                                "{http://www.caiso.com/soa/2006-06-13/StandardAttachmentInfor.xsd}ID",
                            )
                            id.text = "1"

                            compressmethod = ET.SubElement(
                                attachment,
                                "{http://www.caiso.com/soa/2006-06-13/StandardAttachmentInfor.xsd}compressMethod",
                            )
                            compressmethod.text = "gzip"

                            attachmenthash = ET.SubElement(
                                header,
                                "{http://www.caiso.com/mrtu/soa/schemas/2005/09/attachmenthash}attachmentHash",
                            )
                            hashvalue = ET.SubElement(
                                attachmenthash,
                                "{http://www.caiso.com/mrtu/soa/schemas/2005/09/attachmenthash}hashValue",
                            )
                            hashvalue.text = attachment_sha1
                else:
                    self.log.error(
                        "CAISO-707: "
                        + self.service
                        + " NO SUCH FILE TO USE AS SUBMIT ATTACHMENT: "
                        + self.attachment_file
                        + " Does this dir/file exist?"
                    )
                    return None

            # If this is a retrieve
            elif "retrieve" in self.service:

                request_body_xml = None
                try:
                    request_body_xml = ET.fromstring(self.request_body)
                    body.append(request_body_xml)

                except Exception as err:
                    self.log.error(
                        "CAISO-819: Could not use the request body in the XML"
                        + " -- verify it is well formed: "
                    )
                    self.log.error("CAISO-819: " + str(err))
                    return None

            # Build CAISOWSHeader
            caisowsheader = ET.SubElement(
                header,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}CAISOWSHeader",
            )
            caisousernametoken = ET.SubElement(
                caisowsheader,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}CAISOUsernameToken",
            )

            # Username
            username = ET.SubElement(
                caisousernametoken,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}Username",
            )
            username.text = self.username

            # Nonce
            nonce = ET.SubElement(
                caisousernametoken,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}Nonce",
            )
            nonce.text = nonce_string

            # Created
            created = ET.SubElement(
                caisousernametoken,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}Created",
            )
            created.text = created_string

            # CAISOMessageInfo
            caisomessageinfo = ET.SubElement(
                caisowsheader,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}CAISOMessageInfo",
            )

            # Message ID
            messageid = ET.SubElement(
                caisomessageinfo,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}MessageID",
            )
            messageid.text = nonce_string

            timestamp = ET.SubElement(
                caisomessageinfo,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}Timestamp",
            )

            # Created
            created = ET.SubElement(
                timestamp,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}Created",
            )
            created.text = created_string

            # Expires
            expires = ET.SubElement(
                timestamp,
                "{http://www.caiso.com/soa/2006-09-30/CAISOWSHeader.xsd}Expires",
            )
            expires.text = expires_string

            caiso_request_xml_unsigned = ET.tostring(
                envelope, encoding="utf8", method="xml"
            )

            # SIGN THE MESSAGE
            self.log.debug(self.service + " WSSE signing payload")

            caiso_request_xml_signed = self.wsse_sign_xml_payload(
                caiso_request_xml_unsigned
            )

            if caiso_request_xml_signed is None:
                self.log.error(
                    "CAISO-709: "
                    + self.service
                    + " Could not sign payload"
                    + " -- check private key and pass phrase are correct"
                )
                response_dict["errors"].append(
                    "CAISO-709: " + self.service + " Could not WSSE sign payload"
                )
                return response_dict

            self.log.debug(
                self.service
                + " Signed Payload: "
                + str(caiso_request_xml_signed.decode("utf-8"))
            )
            self.log.info(self.service + " Sending payload to " + self.endpoint)

            # IF REGULAR SUBMIT
            if "submit" in self.service and "DocAttach" not in self.service:

                headers = {}

                myboundary = "=_Part_" + f'{now.strftime("%Y%m%d%H%M%S%f")}'

                multipart_structure = {
                    "payload": caiso_request_xml_signed.decode("utf-8"),
                    "attachment.uue": uue,
                }

                body = (
                    "".join(
                        "--%s\r\n"
                        'Content-Disposition: form-data; name="%s"\r\n'
                        "Content-ID: <%s>\r\n"
                        "\r\n"
                        "%s\r\n" % (myboundary, field, field, value)
                        for field, value in multipart_structure.items()
                    )
                    + "--%s--\r\n" % myboundary
                )

                headers = {
                    "Accept-Encoding": "gzip,deflate",
                    "Content-Type": 'multipart/related; type="text/xml"; start="<payload>"; boundary="'
                    + myboundary
                    + '"',
                    "Soapaction": '"' + self.soapaction + '"',
                    "Mime-Version": "1.0",
                    "Content-Length": str(len(body)),
                    "Connection": "Keep-Alive",
                    "ct-remote-user": self.username,
                }

                try:
                    response = requests.post(
                        self.endpoint,
                        cert=(
                            self.private_key_pem_filename,
                            self.private_key_pem_filename,
                        ),
                        data=body,
                        headers=headers,
                        verify=False,
                    )
                except Exception as err:
                    self.log.error(
                        "CAISO-821: The following error occured while posting request:"
                    )
                    self.log.error("CAISO-821: " + str(err))
                    self.log.error(
                        "CAISO-821: Check your endpoint and environment fields"
                        + " in the config to make sure they are correct"
                    )
                    return

            else:

                headers = {"content-type": "text/xml", "SOAPAction": self.soapaction}

                # EVERYTHING ELSE
                try:
                    response = requests.post(
                        self.endpoint,
                        cert=(
                            self.private_key_pem_filename,
                            self.private_key_pem_filename,
                        ),
                        data=caiso_request_xml_signed,
                        headers=headers,
                        verify=False,
                    )
                except Exception as err:
                    self.log.error(
                        "CAISO-821: The following error occured while posting request:"
                    )
                    self.log.error("CAISO-821: " + str(err))
                    self.log.error(
                        "CAISO-821: Check your endpoint and environment fields"
                        + " in the config to make sure they are correct"
                    )
                    return

            response_dict["return_code"] = response.status_code
            response_dict["response_raw"] = response.text

            self.log.info(
                self.service + " Response HTTP Code: " + str(response.status_code)
            )
            # The response parsing is working well enough that I don't think this is needed
            # self.log.debug(self.service + " Response Text: " + str(response.text))

            # Let's look at the response and see what it contains
            response_dict = self.responseParsing(response, response_dict)

            return response_dict

        except Exception as err:
            self.log.error(
                "CAISO-820: General exception raised while submitting "
                + self.service
                + ":"
            )
            self.log.error("CAISO-820: " + str(err))
