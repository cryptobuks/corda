package net.corda.core.crypto;

/**
 * Created by sangalli on 15/2/17.
 */
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;


public class bc {

    private static final String filePath = System.getProperty("user.dir") + "/files/";
    private static final String pathToPublicKey = filePath + "dummy.pkr";
    private static final String pathToPrivateKey = filePath + "dummy.skr";

    private static PGPKeyPair mCurrentPGPKey;

    public static void main(String args[]) throws Exception
    {
        char pass[] = {'b', 'i', 't', 'c', 'o', 'i', 'n'};
        PGPKeyRingGenerator krgen = generateKeyRingGenerator ("corda@example.com", pass);

        // Generate public key ring, dump to file.
        PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();
        BufferedOutputStream pubout = new BufferedOutputStream(new FileOutputStream(filePath + "dummy.pkr"));
        pkr.encode(pubout);
        pubout.close();

        // Generate private key, dump to file.
        PGPSecretKeyRing skr = krgen.generateSecretKeyRing();
        System.out.println("this is a signing key: " + skr.getSecretKey().isSigningKey());
        BufferedOutputStream secout = new BufferedOutputStream (new FileOutputStream(filePath + "dummy.skr"));
        skr.encode(secout);
        secout.close();
    }


    private static PGPKeyRingGenerator generateKeyRingGenerator(String id, char[] pass) throws Exception
    {
        return generateKeyRingGenerator(id, pass, 0xc0);
    }

    public static String encryptData (String inputData, AsymmetricKeyParameter encryptionKey) throws Exception
    {
        String encryptedData;
        Security.addProvider(new BouncyCastlePQCProvider());
        AsymmetricBlockCipher e = new RSAEngine();
        e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);

        byte[] dataToBeEncrypted = inputData.getBytes();
        e.init(true, encryptionKey);
        byte[] hexEncodedCipher = e.processBlock(dataToBeEncrypted, 0, dataToBeEncrypted.length);

        encryptedData = getHexString(hexEncodedCipher);

        System.out.println("Here is the encrypted data: " + encryptedData);

        return encryptedData;
    }

    public static String Decrypt(String encrypted, AsymmetricKeyParameter privateKey) throws InvalidCipherTextException {
    //	Source: http://www.mysamplecode.com/2011/08/java-rsa-decrypt-string-using-bouncy.html

        Security.addProvider(new BouncyCastleProvider());

        AsymmetricBlockCipher engine = new RSAEngine();
        engine.init(false, privateKey); //false for decryption

        byte[] encryptedBytes = encrypted.getBytes();
        byte[] hexEncodedCipher = engine.processBlock(encryptedBytes, 0, encryptedBytes.length);

        return new String (hexEncodedCipher);
    }

//    private static String decryptData (String encryptedData, AsymmetricKeyParameter decryptionKey) throws Exception
//    {
//        String decryptedData;
//
//        Security.addProvider(new BouncyCastlePQCProvider());
//        AsymmetricBlockCipher e = new RSAEngine();
//        e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
//        e.init(false, decryptionKey);
//
//        byte[] dataToBeDecrypted = encryptedData.getBytes();
//        byte[] hexEncodedCipher = e.processBlock(dataToBeDecrypted, 0, dataToBeDecrypted.length);
//
//        decryptedData = getHexString(hexEncodedCipher);
//
//        System.out.println("Here is the decrypted data: " + decryptedData);
//
//        return decryptedData;
//    }

    private static String getHexString(byte[] b) throws Exception
    {

        String result = "";
        for (int i=0; i < b.length; i++)
        {
            result += Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }

    private static PGPKeyRingGenerator generateKeyRingGenerator(String id, char[] pass, int s2kcount) throws Exception
    {
        // This object generates individual key-pairs.
        RSAKeyPairGenerator  kpg = new RSAKeyPairGenerator();

        // Boilerplate RSA parameters, no need to change anything
        // except for the RSA key-size (2048). You can use whatever
        // key-size makes sense for you -- 4096, etc.
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001),
                                new SecureRandom(), 2048, 12));

        // First create the master (signing) key with the generator.
        PGPKeyPair PGPMasterKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN,
                kpg.generateKeyPair(), new Date());

        // Then an encryption subkey.
        PGPKeyPair encryptionSubKey = new BcPGPKeyPair
                        (PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

        mCurrentPGPKey = encryptionSubKey;

        System.out.println("is this an encryption key? " + encryptionSubKey.getPublicKey().isEncryptionKey());

        // Add a self-signature on the id
        PGPSignatureSubpacketGenerator signhashgen =
                new PGPSignatureSubpacketGenerator();

        // Add signed metadata on the signature.
        // 1) Declare its purpose
        signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA|KeyFlags.CERTIFY_OTHER);
        // 2) Set preferences for secondary crypto algorithms to use
        //    when sending messages to this key.
        signhashgen.setPreferredSymmetricAlgorithms
                (false, new int[] {
                        SymmetricKeyAlgorithmTags.AES_256,
                        SymmetricKeyAlgorithmTags.AES_192,
                        SymmetricKeyAlgorithmTags.AES_128
                });
        signhashgen.setPreferredHashAlgorithms
                (false, new int[] {
                        HashAlgorithmTags.SHA256,
                        HashAlgorithmTags.SHA1,
                        HashAlgorithmTags.SHA384,
                        HashAlgorithmTags.SHA512,
                        HashAlgorithmTags.SHA224,
                });
        // 3) Request senders add additional checksums to the
        //    message (useful when verifying unsigned messages.)
        signhashgen.setFeature
                (false, Features.FEATURE_MODIFICATION_DETECTION);

        // Create a signature on the encryption subkey.
        PGPSignatureSubpacketGenerator enchashgen =
                new PGPSignatureSubpacketGenerator();
        // Add metadata to declare its purpose
        enchashgen.setKeyFlags
                (false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE);

        // Objects used to encrypt the secret key.
        PGPDigestCalculator sha1Calc =
                new BcPGPDigestCalculatorProvider()
                        .get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc =
                new BcPGPDigestCalculatorProvider()
                        .get(HashAlgorithmTags.SHA256);

        // bcpg 1.48 exposes this API that includes s2kcount. Earlier
        // versions use a default of 0x60.
        PBESecretKeyEncryptor pske =
                (new BcPBESecretKeyEncryptorBuilder
                        (PGPEncryptedData.AES_256, sha256Calc, s2kcount))
                        .build(pass);

        // Finally, create the keyring itself. The constructor
        // takes parameters that allow it to generate the self
        // signature.
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator (PGPSignature.POSITIVE_CERTIFICATION,
                PGPMasterKeyPair, id, sha1Calc, signhashgen.generate(), null,
                                new BcPGPContentSignerBuilder
                                        (PGPMasterKeyPair.getPublicKey().getAlgorithm(),
                                                HashAlgorithmTags.SHA1),
                                pske);

        // Add our encryption subkey, together with its signature.
        keyRingGen.addSubKey(encryptionSubKey, enchashgen.generate(), null);

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();

        String encryptedData = encryptData("hello mate!" , pair.getPublic());
        String decrypted = Decrypt(encryptedData, pair.getPrivate());
        System.out.println(decrypted);

        return keyRingGen;
    }

}
