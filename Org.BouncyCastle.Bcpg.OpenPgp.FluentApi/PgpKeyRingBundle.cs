using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.FluentApi
{
    /// <remarks>
	/// Often a PGP key ring file is made up of a succession of master/sub-key key rings.
	/// If you want to read an entire secret key file in one hit this is the class for you.
	/// </remarks>
    internal class PgpKeyRingBundle
    {
        private readonly IDictionary secretRings;
        private readonly IDictionary pubRings;

        private readonly IList order;

        internal PgpKeyRingBundle(byte[] encoding)
            : this(new MemoryStream(encoding, false))
        {
        }

        /// <summary>Build a PgpSecretKeyRingBundle from the passed in input stream.</summary>
        /// <param name="inputStream">Input stream containing data.</param>
        /// <exception cref="IOException">If a problem parsing the stream occurs.</exception>
        /// <exception cref="PgpException">If an object is encountered which isn't a PgpSecretKeyRing.</exception>
        internal PgpKeyRingBundle(Stream inputStream)
            : this(new PgpObjectFactory(inputStream).AllPgpObjects())
        {
        }

        internal PgpKeyRingBundle(IEnumerable e)
        {
            this.secretRings = Platform.CreateHashtable();
            this.pubRings = Platform.CreateHashtable();

            this.order = Platform.CreateArrayList();

            foreach (object obj in e)
            {
                if (obj is PgpSecretKeyRing)
                {
                    PgpSecretKeyRing pgpSecret = obj as PgpSecretKeyRing;
                    long key = pgpSecret.GetPublicKey().KeyId;
                    secretRings.Add(key, pgpSecret);
                    order.Add(key);
                }
                else if(obj is PgpPublicKeyRing)
                {
                    PgpPublicKeyRing pgpPub = obj as PgpPublicKeyRing;
                    long key = pgpPub.GetPublicKey().KeyId;
                    pubRings.Add(key, pgpPub);
                    order.Add(key);
                }
            }
        }

        [Obsolete("Use 'Count' property instead")]
        internal int Size
        {
            get { return order.Count; }
        }

        /// <summary>Return the number of rings in this collection.</summary>
        internal int Count
        {
            get { return order.Count; }
        }

        /// <summary>Allow enumeration of the secret key rings making up this collection.</summary>
        internal IEnumerable GetSecretKeyRings()
        {
            return new EnumerableProxy(secretRings.Values);
        }

        /// <summary>Allow enumeration of the secret key rings making up this collection.</summary>
        internal IEnumerable GetPublicKeyRings()
        {
            return new EnumerableProxy(pubRings.Values);
        }


        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        internal IEnumerable GetSecretKeyRings(string userId)
        {
            return GetSecretKeyRings(userId, false, false);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        internal IEnumerable GetSecretKeyRings(string userId,bool matchPartial)
        {
            return GetSecretKeyRings(userId, matchPartial, false);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <param name="ignoreCase">If true, case is ignored in user ID comparisons.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        internal IEnumerable GetSecretKeyRings(string userId,bool matchPartial,bool ignoreCase)
        {
            IList rings = Platform.CreateArrayList();

            if (ignoreCase)
            {
                userId = Platform.ToUpperInvariant(userId);
            }

            foreach (PgpSecretKeyRing secRing in GetSecretKeyRings())
            {
                foreach (string nextUserID in secRing.GetSecretKey().UserIds)
                {
                    string next = nextUserID;
                    if (ignoreCase)
                    {
                        next = Platform.ToUpperInvariant(next);
                    }

                    if (matchPartial)
                    {
                        if (Platform.IndexOf(next, userId) > -1)
                        {
                            rings.Add(secRing);
                        }
                    }
                    else
                    {
                        if (next.Equals(userId))
                        {
                            rings.Add(secRing);
                        }
                    }
                }
            }

            return new EnumerableProxy(rings);
        }

        /// <summary>Return the PGP secret key associated with the given key id.</summary>
        /// <param name="keyId">The ID of the secret key to return.</param>
        internal PgpSecretKey GetSecretKey(long keyId)
        {
            foreach (PgpSecretKeyRing secRing in GetSecretKeyRings())
            {
                PgpSecretKey sec = secRing.GetSecretKey(keyId);

                if (sec != null)
                {
                    return sec;
                }
            }

            return null;
        }

        /// <summary>Return the secret key ring which contains the key referred to by keyId</summary>
        /// <param name="keyId">The ID of the secret key</param>
        internal PgpSecretKeyRing GetSecretKeyRing(long keyId)
        {
            long id = keyId;

            if (secretRings.Contains(id))
            {
                return (PgpSecretKeyRing)secretRings[id];
            }

            foreach (PgpSecretKeyRing secretRing in GetSecretKeyRings())
            {
                PgpSecretKey secret = secretRing.GetSecretKey(keyId);

                if (secret != null)
                {
                    return secretRing;
                }
            }

            return null;
        }

        /// <summary>
        /// Return true if a key matching the passed in key ID is present, false otherwise.
        /// </summary>
        /// <param name="keyID">key ID to look for.</param>
        internal bool ContainsSecretKey(long keyID)
        {
            return GetSecretKey(keyID) != null;
        }


        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        internal IEnumerable GetPublicKeyRings(string userId)
        {
            return GetPublicKeyRings(userId, false, false);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        internal IEnumerable GetPublicKeyRings(string userId, bool matchPartial)
        {
            return GetPublicKeyRings(userId, matchPartial, false);
        }

        /// <summary>Allow enumeration of the key rings associated with the passed in userId.</summary>
        /// <param name="userId">The user ID to be matched.</param>
        /// <param name="matchPartial">If true, userId need only be a substring of an actual ID string to match.</param>
        /// <param name="ignoreCase">If true, case is ignored in user ID comparisons.</param>
        /// <returns>An <c>IEnumerable</c> of key rings which matched (possibly none).</returns>
        internal IEnumerable GetPublicKeyRings(string userId, bool matchPartial, bool ignoreCase)
        {
            IList rings = Platform.CreateArrayList();

            if (ignoreCase)
            {
                userId = Platform.ToUpperInvariant(userId);
            }

            foreach (PgpPublicKeyRing pubRing in GetPublicKeyRings())
            {
                foreach (string nextUserID in pubRing.GetPublicKey().GetUserIds())
                {
                    string next = nextUserID;
                    if (ignoreCase)
                    {
                        next = Platform.ToUpperInvariant(next);
                    }

                    if (matchPartial)
                    {
                        if (Platform.IndexOf(next, userId) > -1)
                        {
                            rings.Add(pubRing);
                        }
                    }
                    else
                    {
                        if (next.Equals(userId))
                        {
                            rings.Add(pubRing);
                        }
                    }
                }
            }
            return new EnumerableProxy(rings);
        }

        /// <summary>Return the PGP secret key associated with the given key id.</summary>
        /// <param name="keyId">The ID of the secret key to return.</param>
        internal PgpPublicKey GetPublicKey(long keyId)
        {
            foreach (PgpPublicKeyRing pubRing in GetPublicKeyRings())
            {
                PgpPublicKey pub = pubRing.GetPublicKey(keyId);

                if (pub != null)
                {
                    return pub;
                }
            }

            return null;
        }

        /// <summary>Return the secret key ring which contains the key referred to by keyId</summary>
        /// <param name="keyId">The ID of the secret key</param>
        internal PgpPublicKeyRing GetPublicKeyRing(long keyId)
        {
            if (pubRings.Contains(keyId))
            {
                return (PgpPublicKeyRing)pubRings[keyId];
            }

            foreach (PgpPublicKeyRing pubRing in GetPublicKeyRings())
            {
                PgpPublicKey pub = pubRing.GetPublicKey(keyId);

                if (pub != null)
                {
                    return pubRing;
                }
            }

            return null;
        }

        /// <summary>
        /// Return true if a key matching the passed in key ID is present, false otherwise.
        /// </summary>
        /// <param name="keyID">key ID to look for.</param>
        internal bool ContainsPublicKey(long keyID)
        {
            return GetPublicKey(keyID) != null;
        }

    }

    partial class BcpgOutputStreamExt
    {
        internal static BcpgOutputStream Wrap(
            Stream outStr)
        {
            if (outStr is BcpgOutputStream)
            {
                return (BcpgOutputStream)outStr;
            }

            return new BcpgOutputStream(outStr);
        }
    }

    class Platform
    {
        private static readonly CompareInfo InvariantCompareInfo = CultureInfo.InvariantCulture.CompareInfo;

        internal static System.Collections.IList CreateArrayList()
        {
            return new ArrayList();
        }

        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            return new ArrayList(collection);
        }

        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Hashtable();
        }

        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            return new Hashtable(dictionary);
        }

        internal static string GetTypeName(object obj)
        {
            return obj.GetType().FullName;
        }

        internal static int IndexOf(string source, string value)
        {
            return InvariantCompareInfo.IndexOf(source, value, CompareOptions.Ordinal);
        }

        internal static string ToUpperInvariant(string s)
        {
            return s.ToUpper(CultureInfo.InvariantCulture);
        }
    }

    sealed class EnumerableProxy
        : IEnumerable
    {
        private readonly IEnumerable inner;

        internal EnumerableProxy(
            IEnumerable inner)
        {
            if (inner == null)
                throw new ArgumentNullException("inner");

            this.inner = inner;
        }

        public IEnumerator GetEnumerator()
        {
            return inner.GetEnumerator();
        }
    }
}
