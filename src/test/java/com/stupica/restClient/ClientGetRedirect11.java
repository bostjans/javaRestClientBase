package com.stupica.restClient;


import com.stupica.GlobalVar;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;


public class ClientGetRedirect11 {

    int iLimitContent   = 98;


    @Before
    public void setUp() {
        System.out.println("Setup: ..");
        GlobalVar.bIsModeVerbose = true;
    }

    @Test
    public void getContentRedirect() {
        // Local variables
        String          sReturn;
        String          sUrl = "http://www.twitter.com";
        ClientRestBase  objClient = new ClientRestBase();

        // Initialization
        System.out.println("--");
        System.out.println("Test: getContentRedirect()");

        assertNotNull(objClient);
        objClient.setUrl(sUrl);
        objClient.setFollowRedirect(true);

        sReturn = objClient.getRequestForUrl(sUrl);
        assertNotNull(sReturn);
        System.out.println("--> Content:");
        if (sReturn.length() > iLimitContent) {
            System.out.println(sReturn.trim().substring(0, iLimitContent) + " ..");
        } else {
            System.out.println(sReturn);
        }
    }
}
