/*
 * Copyright (c) 2021-Present, Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pages;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import de.taimos.totp.TOTP;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class QrCodePage extends Page {

    private static final Pattern SECRET_PATTERN = Pattern.compile(".*secret=(?<key>[A-Z0-9]+)&issuer=.*");

    public QrCodePage(WebDriver driver) {
        super(driver);
    }

    @FindBy(id = "qr-code")
    public WebElement qrCode;

    @FindBy(id = "secret-key")
    public WebElement secretKey;

    @FindBy(id = "next-btn")
    public WebElement nextButton;

    public static String obtainSecret(String base64Image) throws IOException, NotFoundException {
        String qrCode = decodeQRCode(Base64.decodeBase64(base64Image.split(",")[1]));
        Matcher matcher = SECRET_PATTERN.matcher(qrCode);
        if (matcher.find()) {
            return matcher.group("key");
        }
        throw new RuntimeException("Couldn't parse QR code");
    }

    private static String decodeQRCode(byte[] imageBytes) throws IOException, NotFoundException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageBytes));
        BinaryBitmap binaryBitmap = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(image)));
        Result qrCodeResult = new MultiFormatReader().decode(binaryBitmap);
        return qrCodeResult.getText();
    }

    public static String getOneTimePassword(String secret) {
        String hexKey = Hex.encodeHexString(new Base32().decode(secret));
        return TOTP.getOTP(hexKey);
    }
}
