﻿namespace Microsoft.Xades.UnitTestNet6
{
    public class MockDigestProvider : IXadesDigestProvider
    {
        public byte[] ComputeDigest(string digestMethod, byte[] value)
        {
            return new byte[] {1,2,3,4 };
        }
    }
}
