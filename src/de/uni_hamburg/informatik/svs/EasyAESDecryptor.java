package de.uni_hamburg.informatik.svs;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

public class EasyAESDecryptor {

    private static final String CIPHER = "be393d39ca4e18f41fa9d88a9d47a574";
    private static final String PLAIN = "Verschluesselung";

    public static void main(String[] args) {
        /* // Test auf Korrektheit der Lösung...
         * try {
         *     Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
         *     byte[] keyBytes1 = DatatypeConverter.parseHexBinary("000000F5000000000000630000000000");
         *     byte[] keyBytes2 = DatatypeConverter.parseHexBinary("0000000077000000B000000000000000");
         *     Key key1 = new SecretKeySpec(keyBytes1, "AES");
         *     Key key2 = new SecretKeySpec(keyBytes2, "AES");
         *
         *     cipher.init(Cipher.ENCRYPT_MODE, key1);
         *     byte[] first = cipher.doFinal(PLAIN.getBytes("UTF-8"));
         *
         *     cipher.init(Cipher.ENCRYPT_MODE, key2);
         *     byte[] second = cipher.doFinal(first);
         *
         *     System.out.println(DatatypeConverter.printHexBinary(second));
         *     System.out.println("Matches?: " + Arrays.equals(DatatypeConverter.parseHexBinary(CIPHER), second));
         *
         * } catch (Exception e) {
         *     System.err.println(e.getCause().getClass() + ": " + e.getMessage());
         *     e.printStackTrace();
         * }
         */


        int i = 1;
        for (String s : run()) {
            System.out.println("Key " + i++ + ": " + s);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------

    private final Map<String, Key> cipherToKeyMap;

    private EasyAESDecryptor() {
        cipherToKeyMap = new HashMap<>();
    }

    private void fillMap() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        byte[] bytes = new byte[16];

        for (int i = 0; i < 16; ++i) {
            for (int hex1 = 1; hex1 <= 256; ++hex1) {
                for (int j = 0; j < 16; ++j) {
                    for (int hex2 = 1; hex2 <= 256; ++hex2) {
                        bytes[j] = (byte) hex2;
                        bytes[i] = (byte) hex1;
                        Key key = new SecretKeySpec(bytes, "AES");
                        cipher.init(Cipher.ENCRYPT_MODE, key);
                        cipherToKeyMap.put(DatatypeConverter.printBase64Binary(cipher.doFinal(PLAIN.getBytes("UTF-8"))), key);
                    }
                }
            }
        }
    }

    private String[] meetInTheMiddle() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        byte[] bytes = new byte[16];
        byte[] ciphertext = DatatypeConverter.parseHexBinary(CIPHER);

        for (int i = 0; i < 16; ++i) {
            for (int hex1 = 1; hex1 <= 256; ++hex1) {
                for (int j = 0; j < 16; ++j) {
                    for (int hex2 = 1; hex2 <= 256; ++hex2) {
                        bytes[j] = (byte) hex2;
                        bytes[i] = (byte) hex1;
                        Key key = new SecretKeySpec(bytes, "AES");
                        cipher.init(Cipher.DECRYPT_MODE, key);
                        String encode = DatatypeConverter.printBase64Binary(cipher.doFinal(ciphertext));

                        Key match = cipherToKeyMap.get(encode);
                        if (match != null) {
                            String k1 = DatatypeConverter.printHexBinary(match.getEncoded());
                            String k2 = DatatypeConverter.printHexBinary(bytes);
                            return new String[]{k1, k2};
                        }
                    }
                }
            }
        }
        return new String[]{null, null};
    }

    private static String[] run() {
        EasyAESDecryptor dec = new EasyAESDecryptor();
        String[] result = null;

        try {
            dec.fillMap();
            result = dec.meetInTheMiddle();
        } catch (Exception e) {
            System.err.println(e.getCause().getClass() + ": " + e.getMessage());
            e.printStackTrace();
        }

        return result;
    }
}
