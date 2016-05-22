/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.arslan.vulnarity.controller;

/**
 *
 * @author xcryptomind
 */
public class cvssController {
    private boolean scope;
    private double AV,AC,PR,UI,CI,II,AI,CR,IR,AR;
    private final double AV_network,AV_adjacent,AV_local,AV_physical;
    private final double AC_low,AC_high;
    private final double PR_none,PR_low,PR_high;
    private final double UI_required,UI_notRequired;
    private final double CI_none,CI_low,CI_high;
    private final double II_none,II_low,II_high;
    private final double AI_none,AI_low,AI_high;
    private final double CR_none,CR_medium,CR_low,CR_high;
    private final double IR_none,IR_medium,IR_low,IR_high;
    private final double AR_none,AR_medium,AR_low,AR_high;
    
    public cvssController(boolean scope){
        this.scope=scope;
        if(scope){
            PR_low=0.68;
            PR_high=0.50;
        }else{
            PR_low=0.62;
            PR_high=0.27;
        }
        PR_none=0.85;
        AV_network=0.85;
        AV_adjacent=0.62;
        AV_local=0.55;
        AV_physical=0.2;
        AC_low=0.77;
        AC_high=0.44;
        UI_required=0.62;
        UI_notRequired=0.85;
        CI_none=0;
        CI_low=0.22;
        CI_high=0.56;
        II_none=0;
        II_low=0.22;
        II_high=0.56;
        AI_none=0;
        AI_low=0.22;
        AI_high=0.56;
        CR_none=1.0;
        CR_low=0.5;
        CR_medium=1.0;
        CR_high=1.5;
        IR_none=1.0;
        IR_low=0.5;
        IR_medium=1.0;
        IR_high=1.5;
        AR_none=1.0;
        AR_low=0.5;
        AR_medium=1.0;
        AR_high=1.5;
    }
    
    public void init(String av,String ac,String pr,String ui,String ci, String ii,String ai,String cr,String ir, String ar){
        switch(av){
            case "Network":{
                AV=AV_network;
                break;
            }
            case "Adjacent Network":{
                AV=AV_adjacent;
                break;
            }
            case "Local":{
                AV=AV_local;
                break;
            }
            case "Physical":{
                AV=AV_physical;
                break;
            }
        }
        switch(ac){
            case "Low":{
                AC=AC_low;
                break;
            }
            case "High":{
                AC=AC_high;
                break;
            }
        }
        switch(pr){
            case "None":{
                PR=PR_none;
                break;
            }
            case "Low":{
                PR=PR_low;
                break;
            }
            case "High":{
                PR=PR_high;
                break;
            }
        }
        switch(ui){
            case "Not Required":{
                UI=UI_notRequired;
                break;
            }
            case "Required":{
                UI=UI_required;
                break;
            }
        }
        switch(ci){
            case "None":{
                CI=CI_none;
                break;
            }
            case "Low":{
                CI=CI_low;
                break;
            }
            case "High":{
                CI=CI_high;
                break;
            }
        }
        switch(ii){
            case "None":{
                II=II_none;
                break;
            }
            case "Low":{
                II=II_low;
                break;
            }
            case "High":{
                II=II_high;
                break;
            }
        }
        switch(ai){
            case "None":{
                AI=AI_none;
                break;
            }
            case "Low":{
                AI=AI_low;
                break;
            }
            case "High":{
                AI=AI_high;
                break;
            }
        }
        switch(ar){
            case "None":{
                AR=AR_none;
                break;
            }
            case "Low":{
                AR=AR_low;
                break;
            }
            case "Medium":{
                AR=AR_medium;
                break;
            }
            case "High":{
                AR=AR_high;
                break;
            }
        }
        switch(ir){
            case "None":{
                IR=IR_none;
                break;
            }
            case "Low":{
                IR=IR_low;
                break;
            }
            case "Medium":{
                IR=IR_medium;
                break;
            }
            case "High":{
                IR=IR_high;
                break;
            }
        }
        switch(cr){
            case "None":{
                CR=CR_none;
                break;
            }
            case "Low":{
                CR=CR_low;
                break;
            }
            case "Medium":{
                CR=CR_medium;
                break;
            }
            case "High":{
                CR=CR_high;
                break;
            }
        }
    }
    
    public double getBaseScore(){
        double iss = getISS();
        double ess = getESS();
        double result = 0 ;
        if(iss<=0){
            result= 0;
        }
        else if(scope){
            result = Math.round( Math.min(( iss + ess ) , 10));
        }
        else if(!scope){
            result = Math.round( Math.min(( 1.08 *(iss + ess) ) , 10));
        }
        return result;
    }
    
    /**
     * 
     * @return double: Exploitability Sub Score
     */
    private double getESS(){
      return (8.22 * AV * AC * PR * UI );      
    }
    /**
     * 
     * @return double: Impact Sub Score
     */
    private double getISS(){
        double result = 0;
        double base = getISCbase();
        if(scope){
            result = (7.52 * ( base - 0.029)) - (3.25 * Math.pow( (base - 0.02 ), 15) ); 
        }
        else{
            result = 6.42 * base;
        }
        return result;
    }
    /**
     * 
     * @return double: Impact Sub Score Base 
     */
    private double getISCbase(){
        return (1 -  ( (1 - CI) * (1 - II) * (1 - AI) ) );
    }
    
    public double getMBaseScore(){
        double iss = getMISS();
        double ess = getMESS();
        double result = 0 ;
        if(iss<=0){
            result= 0;
        }
        else if(scope){
            result = Math.round( Math.min(( iss + ess ) , 10));
        }
        else if(!scope){
            result = Math.round( Math.min(( 1.08 *(iss + ess) ) , 10));
        }
        return result;
    }
    
    /**
     * 
     * @return double: Exploitability Sub Score
     */
    private double getMESS(){
      return (8.22 * AV * AC * PR * UI );      
    }
    /**
     * 
     * @return double: Impact Sub Score
     */
    private double getMISS(){
        double result = 0;
        double base = getMISCbase();
        if(scope){
            result = (7.52 * ( base - 0.029)) - (3.25 * Math.pow( (base - 0.02 ), 15) ); 
        }
        else{
            result = 6.42 * base;
        }
        return result;
    }
    /**
     * 
     * @return double: Impact Sub Score Base 
     */
    private double getMISCbase(){
        return Math.min((1 -  ( (1 - CI * CR) * (1 - II * IR) * (1 - AI * AR) ) ),0.915);
    }
    
   
}
