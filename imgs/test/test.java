/*
test/
-test.java
-Imgs/
--Imgs.java

javac Imgs/Imgs.java test.java
java -cp . test
*/

import Imgs.Imgs;
import java.io.FileOutputStream;

public class test {
    public static void main(String[] args) {
        byte[] data;
        FileOutputStream fos;

        try {
            data = Imgs.zip_png();
            fos = new FileOutputStream("zip.png");
            fos.write(data);
            fos.close();

            data = Imgs.zip_webp();
            fos = new FileOutputStream("zip.webp");
            fos.write(data);
            fos.close();

            data = Imgs.aes_png();
            fos = new FileOutputStream("aes.png");
            fos.write(data);
            fos.close();

            data = Imgs.aes_webp();
            fos = new FileOutputStream("aes.webp");
            fos.write(data);
            fos.close();

            data = Imgs.cloud_png();
            fos = new FileOutputStream("cloud.png");
            fos.write(data);
            fos.close();

            data = Imgs.cloud_webp();
            fos = new FileOutputStream("cloud.webp");
            fos.write(data);
            fos.close();
            
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
        }
    }
}
