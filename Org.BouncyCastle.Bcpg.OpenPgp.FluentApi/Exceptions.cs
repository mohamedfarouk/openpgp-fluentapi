using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.FluentApi
{
    public class SecretKeyNotFound : Exception
    {
        public SecretKeyNotFound(string message)
            : base(message)
        {

        }
    }
    public class PgpLitralDataNotFound : Exception
    {
        public PgpLitralDataNotFound(string message)
            : base(message)
        {

        }
    }

    public class PgpIntegrityCheckFailed : Exception
    {
        public PgpIntegrityCheckFailed(string message)
            : base(message)
        {

        }
    }
}
