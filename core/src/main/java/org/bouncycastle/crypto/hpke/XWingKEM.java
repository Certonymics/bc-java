package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMExtractor;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;

import java.security.SecureRandom;

class XWingKEM extends KEM
{
    private final AsymmetricCipherKeyPairGenerator kpGen;

    private final EncapsulatedSecretGenerator esGen;

    private final int Nenc;

    protected XWingKEM()
    {
        esGen = new XWingKEMGenerator(getSecureRandom());
        Nenc = 1184;

        this.kpGen = new XWingKeyPairGenerator();
        this.kpGen.init(new XWingKeyGenerationParameters(getSecureRandom()));
    }

    public static AsymmetricCipherKeyPair generateKeyPair(SecureRandom random)
    {
        XWingKeyPairGenerator generator = new XWingKeyPairGenerator();
        XWingKeyGenerationParameters params = new XWingKeyGenerationParameters(random);
        generator.init(params);
        return generator.generateKeyPair();
    }

    // Key Generation
    public AsymmetricCipherKeyPair GeneratePrivateKey()
    {
        return kpGen.generateKeyPair();
    }

    AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    // Encapsulates a shared secret for a given public key and returns the encapsulated key and shared secret.
    protected byte[][] Encap(AsymmetricKeyParameter pkR)
    {
        byte[][] output = new byte[2][];

        SecretWithEncapsulation secretWithEncapsulation = esGen.generateEncapsulated(pkR);

        output[0] = secretWithEncapsulation.getSecret();
        output[1] = secretWithEncapsulation.getEncapsulation();
        return output;
    }

    protected byte[][] Encap(
            AsymmetricKeyParameter pkR,
            AsymmetricCipherKeyPair kpE
    )
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    protected byte[][] AuthEncap(
            AsymmetricKeyParameter pkR,
            AsymmetricCipherKeyPair kpS
    )
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    // Decapsulates the given encapsulated key using the recipient's key pair and returns the shared secret.
    protected byte[] Decap(
            byte[] encapsulatedKey,
            AsymmetricCipherKeyPair recipientKeyPair
    )
    {
        EncapsulatedSecretExtractor extractor = new XWingKEMExtractor((XWingPrivateKeyParameters) (recipientKeyPair.getPrivate()));
        return extractor.extractSecret(encapsulatedKey);
    }

    protected byte[] AuthDecap(
            byte[] enc,
            AsymmetricCipherKeyPair kpR,
            AsymmetricKeyParameter pkS
    )
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    // Serialization
    protected byte[] SerializePublicKey(AsymmetricKeyParameter publicKey)
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    protected byte[] SerializePrivateKey(AsymmetricKeyParameter key)
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    // Deserialization
    protected AsymmetricKeyParameter DeserializePublicKey(byte[] encodedPublicKey)
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    protected AsymmetricCipherKeyPair DeserializePrivateKey(
            byte[] skEncoded,
            byte[] pkEncoded
    )
    {
        throw new UnsupportedOperationException("Not implemented");
    }

    int getEncryptionSize()
    {
        return Nenc;
    }

    private static SecureRandom getSecureRandom()
    {
        return CryptoServicesRegistrar.getSecureRandom();
    }
}