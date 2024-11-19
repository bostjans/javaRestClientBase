package com.stupica.restClient;


import com.stupica.GlobalVar;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;


public class ClientGetHttps11 {

    int iLimitContent   = 98;


    @Before
    public void setUp() {
        System.out.println("Setup: ..");
        GlobalVar.bIsModeVerbose = true;
    }


    @Test
    public void getContent() {
        // Local variables
        String          sReturn;
        String          sUrl = "https://www.stupica.com";
        ClientRestBase  objClient = new ClientRestBase();

        // Initialization
        System.out.println("--");
        System.out.println("Test: getContent()");
        //sUrl = "https://lenkotr.stupica.com/lenkoTrRest/monitor/v1/";
        //sUrl = "https://euez-test.ezdrav.si/servis/preveriDostopnost";
        //sUrl = "https://tdc-euez-cas-1.cs.ezdrav.si/euezDoc/";
        //sUrl = "https://euez-test.ezdrav.si/VS.webservices/services/PicketLinkSTS";

        assertNotNull(objClient);
        objClient.setUrl(sUrl);
        objClient.setTrustAll(true);
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
