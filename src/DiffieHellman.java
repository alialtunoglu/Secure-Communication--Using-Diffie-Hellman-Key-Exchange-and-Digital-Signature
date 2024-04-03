import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {

    public static BigInteger p = BigInteger.probablePrime(128, new SecureRandom());
    public static BigInteger g = new BigInteger("2");

    public static BigInteger generatePrivateKey(int byteLength) {
        SecureRandom random = new SecureRandom();
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(byteLength * 8, random);
        } while (privateKey.compareTo(BigInteger.ONE) <= 0 || privateKey.compareTo(p.subtract(BigInteger.ONE)) >= 0);

        return privateKey;
    }

    public static BigInteger genelAnahtarHesapla(BigInteger privateKey) {
        // Genel anahtarı = generator^privateKey mod prime
        //g^prv mod p
        return g.modPow(privateKey, p);
    }

    public static byte[] ortakAnahtarHesapla(BigInteger publicKey,BigInteger privateKey) {
        // ortakAnahtar = publicKey^privateKey mod p
        BigInteger ortakAnahtar = publicKey.modPow(privateKey, p);

        return ortakAnahtar.toByteArray();
    }

    public static String  toHexString(byte[] array) {
        StringBuilder sb = new StringBuilder();
        for (byte b : array) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

}
