﻿namespace Microsoft.Xades.UnitTest
{
    public class MockSignatureProvider : IXadesSignatureProvider
    {
        public byte[] CreateSignature(string signatureMethod, byte[] value)
        {
            return new byte[] { 1, 2, 3, 4 };
        }
    }
}
