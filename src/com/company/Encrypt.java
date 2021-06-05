package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Encrypt  {

    private static final String fileBasePath = "D:\\dev\\java\\sscw2final\\resources";

    public static void main(String[] args) {
         String keysFilename;
         String sourceFileName;
         String destinationFileName;


        try{


            keysFilename = args[0];
            sourceFileName = args[1];
            destinationFileName = args[2];

            String plainText = fileRead(sourceFileName);

            if(plainText.isEmpty()){
               throw new Exception("file is empty");

            }


            KeyPair keyPair = getKeyPairFromKeyStore(keysFilename);
            String cipherText = encrypt(plainText, keyPair.getPublic());


         String signature = sign("foobar", keyPair.getPrivate());

          fileWrite(destinationFileName,cipherText);

        }catch (ArrayIndexOutOfBoundsException boundsException){
            System.out.println(boundsException.getMessage());
            boundsException.fillInStackTrace();

        } catch (Exception ex) {

            System.out.println(ex.getMessage());
        }


    }


    public static KeyPair getKeyPairFromKeyStore(String keyFileName) throws Exception {

        String alias = "buminduskey";
        String keypwd = "bumindu97";

       InputStream ins = new FileInputStream(fileBasePath+"\\"+keyFileName);

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, keypwd.toCharArray());
        KeyStore.PasswordProtection keyPassword =
                new KeyStore.PasswordProtection(keypwd.toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);

    }


    public static String encrypt(String plainText, PublicKey publicKey) {

        byte[] cipherText = new byte[0];
        try{
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

          
        }catch (NoSuchPaddingException | NoSuchAlgorithmException algException){
            System.out.println("something went wrong with the Algorithm");
            
        }catch (InvalidKeyException invalidKeyException){
            System.out.println("something went wrong with given key");
            
        }catch (BadPaddingException | IllegalBlockSizeException exception ){

            System.out.println(exception.getMessage());
        }

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static  void fileWrite(String fileName,String cipherText){

        try{

            String fileDestPath = fileBasePath+"\\"+fileName;

            System.out.println(fileDestPath);

            FileWriter fileWriter = new FileWriter(fileDestPath);

            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);

            bufferedWriter.write(cipherText);

            bufferedWriter.close();
        }catch (IOException ioException){
            System.out.println(ioException.getMessage());
        }catch (Exception exception){
            System.out.println(exception.getMessage());
        }


    }

    public static String fileRead(String fileName) {

        StringBuilder plainText = new StringBuilder();
        String fileSourcePath = fileBasePath+"\\"+fileName;
        try{

            FileReader fileReader = new FileReader(fileSourcePath);

            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String text;


            while((text=bufferedReader.readLine())!=null){
                plainText.append(text);
            }

            bufferedReader.close();

           
        }catch (FileNotFoundException fileNotFoundException){
            System.out.println("file can't find");
        }catch (IOException ioException){
            System.out.println(ioException.getMessage());
        }
        
        return plainText.toString();


    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }





}
