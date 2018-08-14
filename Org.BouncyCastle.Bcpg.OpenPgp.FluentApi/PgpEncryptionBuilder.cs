using System;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.FluentApi
{
    public class PgpEncryptionBuilder
    {
        public PgpEncryptionBuilder()
        {
            Armor = false;
            Compress = false;
            IntegrityCheck = false;
            PublicKeys = new List<Stream>();
            PrivateKeys = new List<PrivateKeyInfo>();
        }

        private FileInfo InFile;
        private FileInfo OutFile;

        private List<Stream> PublicKeys;
        private List<PrivateKeyInfo> PrivateKeys;

        private bool Armor;
        private bool Compress;
        private bool IntegrityCheck;
        private bool SignOutput;

        #region Fluent API

        public PgpEncryptionBuilder Encrypt(string inputFilePath)
        {
            if (string.IsNullOrEmpty(inputFilePath))
                throw new ArgumentNullException("inputFilePath");

            if (!File.Exists(inputFilePath))
                throw new ArgumentException("inputFilePath", "file does not exists");

            var fileInfo = new FileInfo(inputFilePath);

            return Encrypt(fileInfo);
        }

        public PgpEncryptionBuilder Encrypt(Stream inputStream)
        {
            if(inputStream == null)
                throw new ArgumentNullException("inputStream");

            if (!inputStream.CanRead)
                throw new ArgumentException("stream is not readable", "inputStream");

            if (inputStream.CanSeek)
                inputStream.Seek(0, SeekOrigin.Begin);


            var tempFile = Utils.CreateTempFile();

            using (FileStream fs = tempFile.OpenWrite())
            {
                inputStream.CopyTo(fs);
            }

            return Encrypt(tempFile);
        }

        public PgpEncryptionBuilder Encrypt(FileInfo inputFile)
        {
            if (InFile != null)
                throw new InvalidOperationException("file to encrypt already specified");

            InFile = inputFile ?? throw new ArgumentNullException("inputFile");

            return this;
        }

        public PgpEncryptionBuilder WriteOutputTo(string outfilePath, bool overwrite = true)
        {
            if (string.IsNullOrEmpty(outfilePath))
                throw new ArgumentNullException("outfilePath");

            if (!Uri.IsWellFormedUriString(outfilePath, UriKind.RelativeOrAbsolute))
                throw new ArgumentException("outfilePath", "malformed file path");

            if (File.Exists(outfilePath) && !overwrite)
                throw new ArgumentException("inputFilePath", "out file already exists");

            var fileInfo = new FileInfo(outfilePath);

            return WriteOutputTo(fileInfo);
        }

        public PgpEncryptionBuilder WriteOutputTo(FileInfo outFile)
        {
            if (OutFile != null)
                throw new InvalidOperationException("stream to encrypt already specified");

            OutFile = outFile ?? throw new ArgumentNullException("outFile");

            return this;
        }

        public PgpEncryptionBuilder WithPublicKey(string publicKeyPath)
        {
            if (string.IsNullOrEmpty(publicKeyPath))
                throw new ArgumentNullException("inputFilePath");

            if (!Uri.IsWellFormedUriString(publicKeyPath, UriKind.RelativeOrAbsolute))
                throw new ArgumentException("inputFilePath", "malformed file path");

            if (!File.Exists(publicKeyPath))
                throw new ArgumentException("inputFilePath", "file does not exists");

            var publicKeyStream = File.OpenRead(publicKeyPath);

            return WithPublicKey(publicKeyStream);
        }

        public PgpEncryptionBuilder WithPublicKey(Stream publicKeyStream)
        {
            if (publicKeyStream == null)
                throw new ArgumentNullException("publicKeyStream");

            if (!publicKeyStream.CanRead)
                throw new ArgumentException("stream is not readable", "publicKeyStream");

            if (publicKeyStream.CanSeek)
                publicKeyStream.Seek(0, SeekOrigin.Begin);

            PublicKeys.Add(publicKeyStream ?? throw new ArgumentNullException("publicKeyStream"));

            return this;
        }

        public PgpEncryptionBuilder WithArmor()
        {
            this.Armor = true;
            return this;
        }

        public PgpEncryptionBuilder WithCompression()
        {
            this.Compress = true;
            return this;
        }

        public PgpEncryptionBuilder WithIntegrityCheck()
        {
            this.IntegrityCheck = true;
            return this;
        }

        public PgpEncryptionBuilder WithSigning(string signKeyFilePath, string password)
        {
            if (string.IsNullOrEmpty(signKeyFilePath))
                throw new ArgumentNullException("signKeyFilePath");

            if (!Uri.IsWellFormedUriString(signKeyFilePath, UriKind.RelativeOrAbsolute))
                throw new ArgumentException("signKeyFilePath", "malformed file path");

            if (!File.Exists(signKeyFilePath))
                throw new ArgumentException("signKeyFilePath", "file does not exists");

            var signKeyStream = File.OpenRead(signKeyFilePath);

            return WithSigning(signKeyStream, password);
        }


        public PgpEncryptionBuilder WithSigning(Stream signKeyStream, string password)
        {
            if (signKeyStream == null)
                throw new ArgumentNullException("signKeyStream");

            if (!signKeyStream.CanRead)
                throw new ArgumentException("stream is not readable", "signKeyStream");

            if (signKeyStream.CanSeek)
                signKeyStream.Seek(0, SeekOrigin.Begin);

            PrivateKeys.Add(new PrivateKeyInfo
            {
                PrivateKeyPassword = password,
                PrivateKeyStream = signKeyStream ?? throw new ArgumentNullException("signKeyStream")
            });

            SignOutput = true;
            return this;
        }

        public PgpEncryptionTask Build()
        {
            if (InFile == null)
                throw new InvalidOperationException("no input file/stream was specified");

            if(PublicKeys.Count == 0)
                throw new InvalidOperationException("no encryption key was specified");

            if (SignOutput && PrivateKeys.Count == 0)
                throw new InvalidOperationException("no signing key was specified");

            if (OutFile == null)
            {
                OutFile = Utils.CreateTempFile();
            }

            return new PgpEncryptionTask
            {
                InFile = InFile,
                OutFile = OutFile,
                PublicKeys = PublicKeys,
                PrivateKeys = PrivateKeys,
                Armor = Armor,
                Compress = Compress,
                WithIntegrityCheck = IntegrityCheck,
                WithSigning = SignOutput
            };
        }
        #endregion

    }
}
