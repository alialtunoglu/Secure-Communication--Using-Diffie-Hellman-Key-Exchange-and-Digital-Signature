import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

public class AnaProgram {

    public static void main(String[] args) {
        String mesaj;
        System.out.println("Gönderilecek mesah nedir ?");
        Scanner mesajGirdisi = new Scanner(System.in);
        mesaj=mesajGirdisi.nextLine();

        byte[] ortak_K_Anahtari = anahtarPaylasimi();
        if(ortak_K_Anahtari!=null){
            byte[][][] sifrelenmisMetinMatrisi =aesIleSifrele(mesaj,ortak_K_Anahtari);
            String desifrelenmisMesaj = aesIleDesifreleme(sifrelenmisMetinMatrisi,ortak_K_Anahtari);
            String hashDegeriAES = metniHashle(desifrelenmisMesaj);
            System.out.println();
            try {
                String hashDegeriImza = Imzalama(mesaj);
                System.out.println();
                if (hashDegeriAES.equals(hashDegeriImza)) {
                    System.out.println("AES sonucu özet değeri ile imzalama sonucu çıkan özet değeri birbirine eşittir");
                } else {
                    System.out.println("İmza değerleri ve hash değeri eşit değil");
                }
                System.out.println();
                System.out.println("--------AES'in SHA ile oluşturulmuş HASH DEĞERİ--------------");
                System.out.println(hashDegeriAES);
                System.out.println("--------İMZALAMA'nın SHA ile oluşturulmuş HASH DEĞERİ--------");
                System.out.println(hashDegeriImza);

            } catch (Exception e) {

            }
        }

    }

    public static String Imzalama(String message) throws Exception {
        //Public ve private key anahtar çifti oluşturulur
        KeyPair keyPair = ImzalamaDSA.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        //Mesajın sha ile özet değeri alınır imzalanmak üzere
        byte[] sha256Hash = ImzalamaDSA.sha256Hash(message);
        System.out.println("Mesajın özet değeri: ");
        System.out.println(ImzalamaDSA.bytesToHex(sha256Hash));

        // Private key ile imza oluşturma işlemi -> özet değer imzalanıyor burada
        byte[] signature = ImzalamaDSA.signData(sha256Hash, privateKey);

        // İmzayı ekrana yazdır
        System.out.println("Özet metnin imzası: ");
        System.out.println(ImzalamaDSA.bytesToHex(signature));
        System.out.println();
        //Bob İmzayı kendinde olan public key ile doğrular
        boolean isVerified = ImzalamaDSA.verifySignature(sha256Hash, signature, publicKey);
        //Eğer imza doğruysa hash değerini ekrana yazdır değilse doğrulanamadı
        if (isVerified) {

            System.out.println("Public key ile imza doğrulandı.");
            // İmzanın doğrulandığı durumda, imzanın üzerindeki özeti tekrar ekrana yazdır
            byte[] recoveredHash = ImzalamaDSA.sha256Hash(message);
            System.out.println("İmza doğrulandı imza üzerindeki özet değeri: " );
            System.out.println(ImzalamaDSA.bytesToHex(recoveredHash));

            return ImzalamaDSA.bytesToHex(recoveredHash);
        } else {
            System.out.println("İmza doğrulanamadı.");
            return null;
        }

    }

    public static byte[] anahtarPaylasimi(){
        //İkisi içinde birer privateKey oluşturulur
        BigInteger alicePrivateKey = DiffieHellman.generatePrivateKey(8);  // 8 byte uzunluğunda bir özel anahtar
        BigInteger bobPrivateKey = DiffieHellman.generatePrivateKey(8);

        //Private keyler ile mod alma işleminde alice ve bobun paylaşacağı public key oluşturulur
        BigInteger alicePublicKey = DiffieHellman.genelAnahtarHesapla(alicePrivateKey);
        BigInteger bobPublicKey = DiffieHellman.genelAnahtarHesapla(bobPrivateKey);

        // Public ve private keyler birlikte kullanılarak mod alma işlemi yapılır ve sonucunda ortak bir anahtar oluşturulur
        byte[] aliceOrtakAnahtari = DiffieHellman.ortakAnahtarHesapla(bobPublicKey, alicePrivateKey);
        byte[] bobOrtakAnahtari = DiffieHellman.ortakAnahtarHesapla(alicePublicKey, bobPrivateKey);
        // Ortak paylaşılan sırları hexadecimal string olarak yazdır
        System.out.println("Alice'ın Ortak Anahtarı: " + DiffieHellman.toHexString(aliceOrtakAnahtari));
        System.out.println("Bob'un Ortak Anahtarı: " + DiffieHellman.toHexString(bobOrtakAnahtari));

        if(Arrays.equals(aliceOrtakAnahtari, bobOrtakAnahtari)) {
            byte[] ortakAnahtar = Arrays.copyOf(aliceOrtakAnahtari, bobOrtakAnahtari.length);
            return ortakAnahtar;
        }
        else {
            System.out.println("Ortak anahtar oluşturulamadı");
            return null;
        }
    }

    public static  byte[][][] aesIleSifrele(String plainText,byte[] aliceninOrtakAnahtari){
        byte[][] anahtarMatrisi = AesSimple.hexTextToMatrix(DiffieHellman.toHexString(aliceninOrtakAnahtari));

        // Metni şifrele
        byte[][][] sifrelenmisMetinMatrisi = AesSimple.metniSifrele(plainText,anahtarMatrisi);
        System.out.println("Mesajınız Şifrelendi");
        System.out.println("İşte şifrelenmiş Metin matrisi bloklar halinde");
        for (byte[][] state : sifrelenmisMetinMatrisi) {
            System.out.println("--------");
            AesSimple.printState(state);
        }
        return  sifrelenmisMetinMatrisi;
    }

    public static String aesIleDesifreleme( byte[][][] sifrelenmisMetinMatrisi,byte[] bobunOrtakAnahtari ){
        byte[][] anahtarMatrisi = AesSimple.hexTextToMatrix(DiffieHellman.toHexString(bobunOrtakAnahtari));
        // Şifreli metni çöz
        byte[] decryptedMessage = AesSimple.metniDesifrele(sifrelenmisMetinMatrisi, anahtarMatrisi);
        String message = new String(decryptedMessage, StandardCharsets.UTF_8);
        System.out.println("Şifrelenen Mesaj deşifre edildi");
        System.out.println("Çözülmüş Metin: " + message);

        return message;
    }

    public static String metniHashle(String message){
        String sha256Hash = HashSHA256.ozetDegerHesapla(message); // Deşifre edilmiş metnin özet değeri
        return sha256Hash;
    }


}
