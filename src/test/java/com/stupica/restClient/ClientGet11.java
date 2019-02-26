package com.stupica.restClient;


import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;


public class ClientGet11 {

    int iLimitContent   = 98;


    @Before
    public void setUp() {
        System.out.println("Setup: ..");
        //GlobalVar.bIsModeVerbose = true;
    }


    @Test
    public void getContent() {
        // Local variables
        String          sReturn;
        String          sUrl = "http://www.stupica.com";
        ClientRestBase  objClient = new ClientRestBase();

        // Initialization
        System.out.println("--");
        System.out.println("Test: getContent() - " + this.getClass().getName());

        assertNotNull(objClient);
        objClient.setUrl(sUrl);
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
