import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashSHA256 {

    public static String ozetDegerHesapla(String text) {
        try {
            // MessageDigest objesi oluştur
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // Metni byte dizisine çevir ve özet hesapla
            byte[] messageDigest = md.digest(text.getBytes());

            // Byte dizisini hexadecimal formatına çevir
            StringBuilder sb = new StringBuilder();
            for (byte b : messageDigest) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String metin = "Merhaba, dünya!";
        String sha256Hash = ozetDegerHesapla(metin);

        System.out.println("Metin: " + metin);
        System.out.println("SHA-256 Özet Değeri: " + sha256Hash);
    }
}
