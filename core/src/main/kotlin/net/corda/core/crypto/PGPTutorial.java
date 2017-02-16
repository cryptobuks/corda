package net.corda.core.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.*;
import java.security.Security;
import java.util.Iterator;

/**
 * Created by sangalli on 16/2/17.
 */
public class PGPTutorial {

    private static final String filePath = System.getProperty("user.dir") + "/files/";
    private static final String pathToPublicKey = filePath + "dummy.pkr";
    private static final String pathToPrivateKey = filePath + "dummy.skr";

    public static void main(String args[]) throws Exception
    {
        readKeyFromFile();
    }

    private static void readKeyFromFile() throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        File fileToEncrypt = File.createTempFile(filePath + "encryptedFile", null);
        FileWriter fw = new FileWriter(fileToEncrypt);
        fw.write("Bitcoin is not dead, please encrypt and pass on!".toCharArray());
        fw.close();
        System.out.println("path to public key: " + pathToPublicKey);
        FileInputStream keyReader = new FileInputStream(pathToPublicKey);
        PGPPublicKey myPublicKey = readPublicKey(pathToPublicKey);

        for (java.util.Iterator iterator = myPublicKey.getUserIDs(); iterator.hasNext();)
        {
            System.out.println((String)iterator.next());
        }
    }
    //from BC
    private static PGPPublicKey readPublicKey(String path) throws IOException, PGPException
    {
        BufferedInputStream reader = new BufferedInputStream(new FileInputStream(path));
        PGPPublicKey pubKeyFromFile = readPublicKeyWithInput((InputStream)reader);
        reader.close();
        return pubKeyFromFile;
    }

    static PGPPublicKey readPublicKeyWithInput(InputStream var0) throws IOException, PGPException {
        PGPPublicKeyRingCollection var1 = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(var0), new JcaKeyFingerprintCalculator());
        Iterator var2 = var1.getKeyRings();

        while(var2.hasNext()) {
            PGPPublicKeyRing var3 = (PGPPublicKeyRing)var2.next();
            Iterator var4 = var3.getPublicKeys();

            while(var4.hasNext()) {
                PGPPublicKey var5 = (PGPPublicKey)var4.next();
                if(var5.isEncryptionKey()) {
                    return var5;
                }
            }
        }

        throw new IllegalArgumentException("Can\'t find encryption key in key ring.");
    }
}
