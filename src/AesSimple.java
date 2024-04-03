import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class AesSimple {
    private static final byte[][] sBoxInverse = {
            {(byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB},
            {(byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB},
            {(byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E},
            {(byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25},
            {(byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92},
            {(byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84},
            {(byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06},
            {(byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B},
            {(byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73},
            {(byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E},
            {(byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B},
            {(byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4},
            {(byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F},
            {(byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF},
            {(byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61},
            {(byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D}
    };

    private static final byte[][] sBox = {
            {(byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76},
            {(byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0},
            {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15},
            {(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75},
            {(byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84},
            {(byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf},
            {(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8},
            {(byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2},
            {(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73},
            {(byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb},
            {(byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79},
            {(byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08},
            {(byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
            {(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e},
            {(byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf},
            {(byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16}
    };

    // Key expansion constants
    private static final int RCON[] = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };


    //Bayt Değiştirme işlemi
    //sbox kullanılarak bayt değiştirilir
    public static void subBytes(byte[][] durum) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int satir = (durum[i][j] >> 4) & 0x0F;
                int sutun = durum[i][j] & 0x0F;
                durum[i][j] = sBox[satir][sutun];
            }
        }
    }

    //ters bayt değiştirme işlemi
    public static void inverseSubBytes(byte[][] durum) {
        // Ters yerine koyma işlemi uygulanır
        // Yerine koyma için ters S-box kullanılır
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int satir = (durum[i][j] >> 4) & 0x0F;
                int sutun = durum[i][j] & 0x0F;
                durum[i][j] = sBoxInverse[satir][sutun];
            }
        }
    }

    //Satır kaydırma işlemi
    public static void shiftRows(byte[][] durum) {
        byte[][] kaydirilmisSatir = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                kaydirilmisSatir[i][j] = durum[i][(j + i) % 4];
                //Üst sütun kaydırılmıycak şekilde 1 indisde 1.sutun 0.sutuna kaydırılır 0.sutun ise 4. sutun yerine geçer
            }
            System.arraycopy(kaydirilmisSatir[i], 0, durum[i], 0, 4);
        }
    }
    /*
    10 20 30 40
    50 70 80 90 -> 70 80 90 50
    15 25 35 45 -> 35 45 15 25
    12 23 46 92 -> 92 12 23 46
     */


    //Burada da tam dersi işlem yapılır
    public static void inverseShiftRows(byte[][] durum) {
        byte[][] kaydirilmisSatir = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                kaydirilmisSatir[i][j] = durum[i][(j - i + 4) % 4];
            }
            System.arraycopy(kaydirilmisSatir[i], 0, durum[i], 0, 4);
        }
    }


    private static final int[][] mixColumnMatrix = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
    };

    private static final int[][] invMixColumnMatrix = {
            {0x0E, 0x0B, 0x0D, 0x09},
            {0x09, 0x0E, 0x0B, 0x0D},
            {0x0D, 0x09, 0x0E, 0x0B},
            {0x0B, 0x0D, 0x09, 0x0E}
    };

    //sutun Karıştırma işlemi yapılıyor
    public static void mixColumns(byte[][] durum) {
        byte[][] temp = new byte[durum.length][durum[0].length];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[i][j] = (byte) (gmul(mixColumnMatrix[i][0], durum[0][j]) ^
                        gmul(mixColumnMatrix[i][1], durum[1][j]) ^
                        gmul(mixColumnMatrix[i][2], durum[2][j]) ^
                        gmul(mixColumnMatrix[i][3], durum[3][j]));
            }
        }

        for (int i = 0; i < 4; i++) {
            System.arraycopy(temp[i], 0, durum[i], 0, 4);
        }
    }

    public static void invMixColumns(byte[][] durum) {
        byte[][] temp = new byte[durum.length][durum[0].length];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[i][j] = (byte) (gmul(invMixColumnMatrix[i][0], durum[0][j]) ^
                        gmul(invMixColumnMatrix[i][1], durum[1][j]) ^
                        gmul(invMixColumnMatrix[i][2], durum[2][j]) ^
                        gmul(invMixColumnMatrix[i][3], durum[3][j]));
            }
        }

        for (int i = 0; i < 4; i++) {
            System.arraycopy(temp[i], 0, durum[i], 0, 4);
        }
    }
    public static byte gmul(int a, byte b) {
        byte p = 0;
        byte hi_bit_set;
        for (int sayac = 0; sayac < 8; sayac++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            hi_bit_set = (byte) (a & 0x80);
            a <<= 1;
            if (hi_bit_set != 0) {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        return p;
    }
    //Anahtar genişletme işlemleri
    public static byte[][][] generateRoundKeys(byte[][] originalKey) {
        int keySize = 4; // 4*4 matrislik için 128 bit = 16 byte
        int numberOfRounds = 10; // 128 bitlik aes 10 turdur

        byte[][][] roundKeys = new byte[numberOfRounds + 1][4][4];

        for (int i = 0; i < keySize; i++) {
            System.arraycopy(originalKey[i], 0, roundKeys[0][i], 0, keySize);
        }

        for (int round = 1; round <= numberOfRounds; round++) {
            byte[] temp = new byte[keySize];
            System.arraycopy(roundKeys[round - 1][3], 0, temp, 0, keySize);
            byte[] rotatedWord = rotateWord(temp);
            byte[] subWord = subWord(rotatedWord);
            byte[] roundConstant = getRoundConstant(round);
            for (int i = 0; i < keySize; i++) {
                roundKeys[round][i][0] = (byte) (roundKeys[round - 1][i][0] ^ subWord[i] ^ roundConstant[i]);
            }
            for (int j = 1; j < keySize; j++) {
                for (int i = 0; i < keySize; i++) {
                    roundKeys[round][i][j] = (byte) (roundKeys[round][i][j - 1] ^ roundKeys[round - 1][i][j]);
                }
            }
        }
        return roundKeys;
    }


    public static byte[] rotateWord(byte[] word) {
        byte temp = word[0];
        System.arraycopy(word, 1, word, 0, word.length - 1);
        word[word.length - 1] = temp;
        return word;
    }

    public static byte[] subWord(byte[] word) {
        byte[] sonuc = new byte[word.length];
        for (int i = 0; i < word.length; i++) {
            int satir = (word[i] >> 4) & 0x0F;
            int sutun = word[i] & 0x0F;
            sonuc[i] = sBox[satir][sutun];
        }
        return sonuc;
    }

    public static byte[] getRoundConstant(int round) {
        byte[] roundConstant = new byte[]{(byte) (0x01 << (round - 1)), 0x00, 0x00, 0x00};
        return roundConstant;
    }

    //tur anahtarı üretme işlemleri
    public static void addRoundKey(byte[][] durum, byte[][] roundKey) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                durum[j][i] ^= roundKey[i][j];
            }
        }
    }
    //Şifreleme İşlemi
    public static byte[][][] metniSifrele(String plainText, byte[][] key) {
        byte[][][] roundKeys = generateRoundKeys(key); //anahtar 3 matrisli hale dönüştürülür her turda ayrı ayrı anahtar üretmek için
        byte[][][] matrices = textToMatrices(plainText);
        for (byte[][] state : matrices) {
            addRoundKey(state, roundKeys[0]);
            for (int round = 1; round < 10; round++) {
                //aradaki işlemler
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey(state, roundKeys[round]);
            }
            //Son yapılacak işlemler
            subBytes(state);
            shiftRows(state);
            addRoundKey(state, roundKeys[10]);
        }
        return matrices;
    }

    //Deşifreleme
    public static byte[] metniDesifrele(byte[][][] matrices, byte[][] key) {
        byte[][][] roundKeys = AesSimple.generateRoundKeys(key);
        ByteArrayOutputStream tekBoyutluMatris = new ByteArrayOutputStream();
        for (byte[][] state : matrices) {
            addRoundKey(state, roundKeys[10]);
            inverseShiftRows(state);
            inverseSubBytes(state);
            for (int round = 9; round > 0; round--) {
                addRoundKey(state, roundKeys[round]);
                invMixColumns(state);
                inverseShiftRows(state);
                inverseSubBytes(state);
            }
            AesSimple.addRoundKey(state, roundKeys[0]);

            //printState(state);
            byte[] decryptedBytes = AesSimple.matrixToBytes(state);
            tekBoyutluMatris.write(decryptedBytes, 0, decryptedBytes.length);
        }
        return tekBoyutluMatris.toByteArray();
    }
    public static byte[] matrixToBytes(byte[][] matrix) {
        ByteArrayOutputStream byteDonusumu = new ByteArrayOutputStream();
        for (int sutun = 0; sutun < 4; sutun++) {
            for (int satir = 0; satir < 4; satir++) {

                if (matrix[satir][sutun] != 0) {
                    //0 olacak indisler diziye eklenmez
                    byteDonusumu.write(matrix[satir][sutun]);
                }
            }
        }
        return byteDonusumu.toByteArray();
    }

    //Matrisi String bir metne dönüştürmek için
    public static String matrixToPlainText(byte[][] matrix) {
        StringBuilder plainText = new StringBuilder();

        for (int sutun = 0; sutun < 4; sutun++) {
            for (int satir = 0; satir < 4; satir++) {
                // 0 olan indisleri stringe ekleme
                if (matrix[satir][sutun] != 0) {
                    plainText.append((char) matrix[satir][sutun]);
                }
            }
        }

        return plainText.toString();
    }

    //Matrislerin Durumunu Yazdırıyor
    public static void printState(byte[][] durum) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                System.out.printf("%02x ", durum[i][j]);
            }
            System.out.println();
        }
    }

    // Metni 128 bitlik parçalara ayıran ve 4*4lük matrise aktaran method
    public static byte[][][] textToMatrices(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        int numMatrices = (int) Math.ceil((double) bytes.length / 16);
        byte[][][] matrices = new byte[numMatrices][4][4];

        for (int m = 0; m < numMatrices; m++) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    int index = 16 * m + 4 * i + j;
                    if (index < bytes.length) {
                        matrices[m][j][i] = bytes[index];
                    } else {
                        matrices[m][j][i] = 0;
                        //matris tam 128 bit değilse geri kalan parçaları 0 yapıyoruz
                    }
                }
            }
        }
        return matrices;
    }

    public static byte[][] hexTextToMatrix(String anahtar) {
        byte[][] durum = new byte[4][4];
        String hexText = anahtar;
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (k < hexText.length()) {
                    durum[j][i] = (byte) Integer.parseInt(hexText.substring(k, k + 2), 16);
                    k += 2;
                } else {
                    durum[j][i] = 0;
                }
            }
        }
        return durum;
    }

}
