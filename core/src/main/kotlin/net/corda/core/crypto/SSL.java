//package net.corda.core.crypto;
//
//import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.openssl.PEMKeyPair;
//import org.bouncycastle.openssl.PEMParser;
//import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
//import java.io.BufferedReader;
//import java.io.FileReader;
//import java.security.KeyPair;
//import java.security.Security;
//
//public class SSL
//{
//    private static final String filePath = System.getProperty("user.dir") + "/files/";
//    private static final String pathToPEM = filePath + "private.pem";
//
//    public static void main(String args[]) throws Exception
//    {
//        encryptData("Bitcoin ftw!");
//    }
//
//    public static KeyPair getCertificateKeyPair(String path) throws Exception
//    {
//        BufferedReader br = new BufferedReader(new FileReader(path));
//        Security.addProvider(new BouncyCastleProvider());
//        PEMParser pp = new PEMParser(br);
//        PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
//        KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
//        pp.close();
//
//        return kp;
//    }
//
//    public static String encryptData(String dataToEncrypt) throws Exception
//    {
//        KeyPair encryptionKeyPair = getCertificateKeyPair(pathToPEM);
//        String encryptedData = rsa.Encrypt(dataToEncrypt.getBytes(),
//                (AsymmetricKeyParameter) encryptionKeyPair.getPublic());
//        return encryptedData;
//    }
//
//}
