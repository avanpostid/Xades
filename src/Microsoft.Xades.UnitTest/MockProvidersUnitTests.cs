using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Microsoft.Xades.UnitTest
{
    [TestClass]
    public class MockProvidersUnitTests
    {
        [TestMethod]
        public void Test()
        {
            var contentStr = "<xml></xml>";

            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.LoadXml(contentStr);

            var xadesSignedXml = new XadesSignedXml(xmlDocument);
            xadesSignedXml.XadesDigestProvider = new MockDigestProvider();
            xadesSignedXml.XadesSignatureProvider = new MockSignatureProvider();
            var signatureId = Guid.NewGuid();
            xadesSignedXml.Signature.Id = $"sig-{signatureId}";

            xadesSignedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
            xadesSignedXml.SignedInfo.SignatureMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:custom";
            xadesSignedXml.AddReference(CreateReference(signatureId));
            xadesSignedXml.AddReference(CreateReferenceSignedProps(signatureId));
            xadesSignedXml.AddReference(CreateReferenceKey(signatureId));

            xadesSignedXml.KeyInfo = CreateKeyInfo(signatureId);

            //xadesSignedXml.AddObject(CreateXadesObject(signatureId));

            XadesObject xadesObject = new XadesObject();
            xadesObject.Id = $"obj-{signatureId}";
            xadesObject.QualifyingProperties.Target = $"#sig-{signatureId}";
            xadesObject.QualifyingProperties.SignedProperties.Id = $"signedprops-{signatureId}";
            var signedSignatureProperties = xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties;
            var cert = new Cert();
            var dataSingleCert = new KeyInfoX509Data();
            dataSingleCert.AddIssuerSerial("issuername", "12312");
            cert.IssuerSerial.X509IssuerName = ((X509IssuerSerial)dataSingleCert.IssuerSerials[0]).IssuerName.Replace(", ", ",");
            cert.IssuerSerial.X509SerialNumber = ((X509IssuerSerial)dataSingleCert.IssuerSerials[0]).SerialNumber;
            cert.CertDigest.DigestMethod.Algorithm = SignedXml.XmlDsigSHA1Url;
            cert.CertDigest.DigestValue = new byte[] { 1, 2, 3, 4 };
            signedSignatureProperties.SigningCertificate.CertCollection.Add(cert);
            signedSignatureProperties.SigningTime = DateTime.Now;
            signedSignatureProperties.SignaturePolicyIdentifierSpecified = false;
            xadesSignedXml.AddXadesObject(xadesObject,
                new XmlDsigC14NTransform(),
                null,
                "http://uri.etsi.org/01903#SignedProperties");

            xadesSignedXml.ComputeSignature();

            var xmlDigitalSignature = xadesSignedXml.GetXml();
            var importSignature = xmlDocument.ImportNode(xmlDigitalSignature, true);
            xmlDocument.DocumentElement.AppendChild((XmlNode)importSignature);

            var result = Encoding.UTF8.GetBytes(xmlDocument.OuterXml);
        }

        private Reference CreateReference(Guid signatureId)
        {
            Reference reference = new Reference();
            reference.Uri = "";
            reference.Id = $"ref-{signatureId}";

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform(includeComments: false));
            reference.DigestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:custom";
            return reference;
        }

        private Reference CreateReferenceSignedProps(Guid signatureId)
        {
            Reference reference = new Reference();
            reference.Uri = $"#signedprops-{signatureId}";
            reference.Id = $"ref-signedprops-{signatureId}";
            reference.Type = "http://uri.etsi.org/01903/#SignedProperties";

            reference.AddTransform(new XmlDsigExcC14NTransform(includeComments: false));
            reference.DigestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:custom";
            return reference;
        }

        private Reference CreateReferenceKey(Guid signatureId)
        {
            Reference reference = new Reference();
            reference.Uri = $"#key-{signatureId}";
            reference.Id = $"ref-key-{signatureId}";
            reference.Type = "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd#X509Data";

            reference.AddTransform(new XmlDsigExcC14NTransform(includeComments: false));
            reference.DigestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:custom";
            return reference;
        }

        public DataObject CreateXadesObject(Guid id)
        {
            

            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml($@"<xades:QualifyingProperties xmlns:xades=""http://uri.etsi.org/01903/v1.4.1#"" Target=""sig-{id}""><xades:SignedProperties Id=""signedprops-{id}""><xades:SignedSignatureProperties/></xades:SignedProperties></xades:QualifyingProperties>"); //Cache to XAdES object for later use
            var dataObject = new DataObject();
            dataObject.Id = $"obj-{id}";
            dataObject.Data = xmlDocument.ChildNodes;
            return dataObject;
        }

        private KeyInfo CreateKeyInfo(Guid signatureId)
        {
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.Id = $"key-{signatureId}";

            keyInfo.AddClause(new KeyInfoX509Data(Convert.FromBase64String("MIIDljCCA0OgAwIBAgITSwAAAANS+ZC8/b5bkAAAAAAAAzAKBggqhQMHAQEDAjBKMRMwEQYKCZImiZPyLGQBGRYDZG9tMRQwEgYKCZImiZPyLGQBGRYEcGtpNjEdMBsGA1UEAxMUcGtpNi1QS0ktVy1TRVJWRVItQ0EwHhcNMjMwNTE2MTMzOTQ5WhcNMjQwNTE2MTM0OTQ5WjArMSkwJwYDVQQDDCDQmtGD0LfQvdC10YbQvtCyIGdvc3QgYXV0aCAyNTYtMjBmMB8GCCqFAwcBAQEBMBMGByqFAwICJAAGCCqFAwcBAQICA0MABEDH/V1XiGsRBRPTVzmfcs2Sq/o6ysm1XYA4JPjqOUcA8tGMCq0o7+uU+13OgO76y2CTakfHznb92f6gCmwyU4yko4ICGDCCAhQwJwYDVR0lBCAwHgYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDAjAdBgNVHQ4EFgQUIN8S05BRvksQEv6zzzbp9r1ZyFAwHwYDVR0jBBgwFoAUtj0mP7a97tg8O3SQKMd160x00A8wgdQGA1UdHwSBzDCByTCBxqCBw6CBwIaBvWxkYXA6Ly8vQ049cGtpNi1QS0ktVy1TRVJWRVItQ0EsQ049UEtJLVctU2VydmVyLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXBraTYsREM9ZG9tP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBwwYIKwYBBQUHAQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1wa2k2LVBLSS1XLVNFUlZFUi1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1wa2k2LERDPWRvbT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAMBgNVHRMBAf8EAjAAMAoGCCqFAwcBAQMCA0EAnEGAfIjJlhrErBmDIO2piZM0c1DwPVJbbSrEqwc87inu0g0xhgrRXQn2CPDkIilWSZuWCxv+uuN4zAw0iClWjA==")));
            return keyInfo;
        }
    }
}
