package com.stupica.restClient.tsa;


import com.stupica.GlobalVar;
import com.stupica.core.UtilString;
import com.stupica.httpClient.ResultHttpStream;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertNotNull;


/**
 * Ref.:
 * https://test-tsa.ca.posta.rs/index.html
 */
public class ClientGetHttps22 {

    int iLimitContent   = 98;

    //TimeStampRequestGenerator m_tsrg = null;
    //TimeStampRequest m_tsReq;


    @Before
    public void setUp() {
        System.out.println("Setup: ..");
        GlobalVar.bIsModeVerbose = true;

        //m_tsrg = new TimeStampRequestGenerator();
    }


    @Test
    public void testTimeStamp01() {
        // Local variables
        String          sReturn;
        //String          sUrl = "http://localhost:11080/mirror/v1";
        String          sUrl = "https://test-tsa.ca.posta.rs:443/timestamp2";
        ResultHttpStream objResult = null;
        InputStream     objIsKeyStore = null;
        ClientTsaTest01 objClient = new ClientTsaTest01();

        // Initialization
        System.out.println("--");
        System.out.println("Test: testTimeStamp01()");

        assertNotNull(objClient);
        //assertNotNull(m_tsrg);

        objClient.setUrl(sUrl);
        objClient.setReferer("https://test-tsa.ca.posta.rs/timestamp");
        //objClient.setTrustAll(true);

        File objFileKeyStore = new File("./TsaSrb_TestKorisnik.p12");
        assertNotNull(objFileKeyStore);
        if (objFileKeyStore.exists()) {
            try {
                objIsKeyStore = new FileInputStream(objFileKeyStore);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        assertNotNull(objIsKeyStore);

        objClient.setKeyStore(objIsKeyStore, "pkcs12", "1234".toCharArray(), "1234".toCharArray());

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assertNotNull(digest);
        byte[] encodedhash = digest.digest("Test_SHA256".getBytes(StandardCharsets.UTF_8));

        //m_tsReq = m_tsrg.generate(TSPAlgorithms.SHA256, encodedhash, BigInteger.valueOf(new Random().nextLong()));

        try {
            objResult = objClient.postRequestForUrlAndGetResp(sUrl, encodedhash);
            //objResult = objClient.postRequestForUrlAndGetResp(sUrl, m_tsReq.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertNotNull(objResult);
        System.out.println("--> Content:");
        if (UtilString.isEmpty(objResult.sText))
            System.out.println("\tN/A");
        else if (objResult.sText.length() > iLimitContent) {
            System.out.println(objResult.sText.trim().substring(0, iLimitContent) + " ..");
        } else {
            System.out.println(objResult.sText);
        }
    }
}
