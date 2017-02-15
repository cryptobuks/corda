package net.corda.core.contracts;

import net.corda.core.crypto.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by sangalli on 15/2/17.
 */
public class pgp
{

    public static boolean verifySignature(PublicKey pubKey, String plaintext, String signature) throws Exception
    {
        Signature rsaVerify = null;
        rsaVerify = Signature.getInstance("SHA256withRSA", "BC");
        rsaVerify.initVerify(pubKey);
        rsaVerify.update(plaintext.getBytes("UTF-8"));
        return rsaVerify.verify(Base58.decode(signature));
    }

    public static String signData(KeyPair pair, String plaintext) throws Exception
    {
        Signature rsaSign = Signature.getInstance("SHA256withRSA", "BC");
        rsaSign.initSign(pair.getPrivate());
        rsaSign.update(plaintext.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();
        String base58Sig = Base58.encode(signature);

        return base58Sig;
    }

    public static PublicKey getCertificatePublicKey(String path) throws Exception
    {
        InputStream in = new FileInputStream(path + "cert.cer");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
        return cert.getPublicKey();
    }

    public static KeyPair getCertificateKey(String path) throws Exception
    {
        BufferedReader br = new BufferedReader(new FileReader(path));
        Security.addProvider(new BouncyCastleProvider());
        PEMParser pp = new PEMParser(br);
        PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
        KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
        pp.close();

        return kp;
    }





//    public static void generateKey() throws Exception
//    {
//        // initialize the KeyStore instance
//        KeyStore ks = new KeyStore("mypgp.keystore", "my store pass");
//
//        // EC curve for this key
//        String curve = EcCurve.P384;
//        // User Id for this key
//        String userId = "my name";
//
//        KeyPairInformation newKey = ks.generateEccKeyPair(curve, userId, "my key password");
//
//        // now the public key can be exported and sent to our partners
//    }
//
//    public static void encrypt (String[] args) throws Exception{
//        // create an instance of the library
//        PGPLib pgp = new PGPLib();
//
//        // is output ASCII or binary
//        boolean asciiArmor = false;
//        // should integrity check information be added
//        // set to false for compatibility with older versions of PGP such as 6.5.8.
//        boolean withIntegrityCheck = false;
//
//        pgp.encryptFile("INPUT.txt",
//                "public.key",
//                "OUTPUT.pgp",
//                asciiArmor,
//                withIntegrityCheck);
//    }
}
