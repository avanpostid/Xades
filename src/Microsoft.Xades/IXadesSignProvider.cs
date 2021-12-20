using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Xades
{
    public interface IXadesSignatureProvider
    {
        byte[] CreateSignature(string signatureMethod, byte[] value);
    }

    public interface IXadesDigestProvider
    {
        byte[] ComputeDigest(string digestMethod, byte[] value);
    }

    public class DotnetXadesSignProvider : IXadesSignatureProvider
    {
        private AsymmetricAlgorithm _privateKey;
        public DotnetXadesSignProvider(AsymmetricAlgorithm privateKey)
        {
            _privateKey = privateKey;
        }

        public byte[] CreateSignature(string signatureMethod, byte[] value)
        {
            SignatureDescription description = CryptoConfig.CreateFromName(signatureMethod) as SignatureDescription;
            if (description == null)
            {
                throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
            }
            HashAlgorithm hashAlgorithm = description.CreateDigest();
            if (hashAlgorithm == null)
            {
                throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
            }
            var hashValue = hashAlgorithm.ComputeHash(value);
            return description.CreateFormatter(_privateKey).CreateSignature(hashValue);
        }
    }
}
