/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.arslan.vulnarity.controller;

import java.security.cert.Certificate;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author xcryptomind
 */
public class connectionControllerTest {
    
    public connectionControllerTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }

    /**
     * Test of isValidURL method, of class connectionController.
     */
    @org.junit.Test
    public void testIsValidURL() throws Exception {
        System.out.println("isValidURL");
        String url = "arslansoftware.com";
        boolean result = connectionController.isValidURL(url);
        assertFalse( result);
        url = "http://www.arslansoftware.com";
        result = connectionController.isValidURL(url);
        assertTrue(result);
        // TODO review the generated test code and remove the default call to fail.
       // fail("The test case is a prototype.");
    }

    /**
     * Test of isVparam method, of class connectionController.
     */
    @org.junit.Test
    public void testIsVparam() {
        System.out.println("isVparam");
        String url = "http://www.example.com";
        boolean result = connectionController.isVparam(url);
        assertFalse(result);
        url = "http://www.example.com/id=$Vparam";
        result = connectionController.isVparam(url);
        assertTrue(result);
        // TODO review the generated test code and remove the default call to fail.
       // fail("The test case is a prototype.");
    }

    /**
     * Test of isHTTP method, of class connectionController.
     */
    @org.junit.Test
    public void testIsHTTP() {
        System.out.println("isHTTP");
        String url = "http://www.example.com";
        boolean result = connectionController.isHTTP(url);
        assertTrue(result);
        url = "https://www.example.com";
        result = connectionController.isHTTP(url);
        assertFalse(result);
        // TODO review the generated test code and remove the default call to fail.
       // fail("The test case is a prototype.");
    }

    /**
     * Test of isHTTPS method, of class connectionController.
     */
    @org.junit.Test
    public void testIsHTTPS() {
        System.out.println("isHTTPS");
        String url = "http://www.example.com";
        boolean expResult = false;
        boolean result = connectionController.isHTTPS(url);
        assertEquals(expResult, result);
        url = "https://www.example.com";
        expResult = true;
        result = connectionController.isHTTPS(url);
        assertTrue(result);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

}
