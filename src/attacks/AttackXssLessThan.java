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
import attacks.model.AttackResult;
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

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class AttackXssLessThan extends AttackI {

    private static String atkName = "XSSLT";
    
    private static String[] attackStrings = {
            "℀",
            "〈",
            "﹤",
            "＜",
            "≮",
        "<",
        "%3C",
        "%253C",
        "&lt",
        "&lt;",
        "&LT",
        "&LT;",
        "&#60",
        "&#060",
        "&#0060",
        "&#00060",
        //"&#000060",
        //"&#0000060",
        "&#60;",
        "&#060;",
        "&#0060;",
        "&#00060;",
        //"&#000060;",
        //"&#0000060;",
        "&#x3c",
        "&#x03c",
        "&#x003c",
        "&#x0003c",
        //"&#x00003c",
        //"&#x000003c",
        "&#x3c;",
        "&#x03c;",
        "&#x003c;",
        "&#x0003c;",
        //"&#x00003c;",
        //"&#x000003c;",
        "&#X3c",
        "&#X03c",
        "&#X003c",
        "&#X0003c",
        //"&#X00003c",
        //"&#X000003c",
        "&#X3c;",
        "&#X03c;",
        "&#X003c;",
        "&#X0003c;",
        //"&#X00003c;",
        //"&#X000003c;",
        "&#x3C",
        "&#x03C",
        "&#x003C",
        "&#x0003C",
        //"&#x00003C",
        //"&#x000003C",
        "&#x3C;",
        "&#x03C;",
        "&#x003C;",
        "&#x0003C;",
        //"&#x00003C;",
        //"&#x000003C;",
        "&#X3C",
        "&#X03C",
        "&#X003C",
        "&#X0003C",
        //"&#X00003C",
        //"&#X000003C",
        "&#X3C;",
        "&#X03C;",
        "&#X003C;",
        "&#X0003C;",
        //"&#X00003C;",
        //"&#X000003C;",
        "\\x3c",
        "\\x3C",
        "\\u003c",
        "\\u003C",
    };
    
    private LinkedList<AttackData> attackDataXss = new LinkedList<AttackData>();
    private int state = 0;
    private Color failColor = new Color(0xff, 0xcc, 0xcc, 100);
    
    public AttackXssLessThan(AttackWorkEntry work) {
        super(work);
    }
    
    @Override
    protected String getAtkName() {
        return "XSSLT";
    }
    
    @Override
    protected int getState() {
        return state;
    }
    
    @Override
    public boolean init() {
        String indicator = XssIndicator.getInstance().getIndicator();
        attackDataXss.addAll(generateAttackData(indicator));
        return true;
    }

    public static List<AttackData> generateAttackData(String indicator) {
        List<AttackData> attackDataXss = new LinkedList<AttackData>();
        int n = 0;
        for (String s : attackStrings) {
            AttackData atkData = new AttackData(n++,
                    indicator + s,
                    indicator + "<",
                    AttackData.AttackResultType.VULNUNSURE);
            attackDataXss.add(atkData);
        }
        return new LinkedList<>(new LinkedHashSet<>(attackDataXss));
    }

    @Override
    public boolean performNextAttack() {
        AttackData atkData = attackDataXss.get(state);
        SentinelHttpMessageAtk httpMessage;
        try {
            httpMessage = attack(atkData, false);
            if (httpMessage == null) {
                return false;
            }
            analyzeResponse(httpMessage, atkData);
        } catch (ConnectionTimeoutException ex) {
            state++;
            BurpCallbacks.getInstance().print("Connection timeout: " + ex.getLocalizedMessage());
            return false;
        } catch (UnsupportedEncodingException e) {
            state++;
            BurpCallbacks.getInstance().print("Encoding error: " + e.getLocalizedMessage());
        }

        state++;
        
        if (state >= attackDataXss.size()) {
            return false;
        } else {
            return true;
        }
    }
    
    
    private void analyzeResponse(SentinelHttpMessageAtk httpMessage, AttackData atkData) {
        
        String response = httpMessage.getRes().getResponseStr();
        if (response == null || response.length() == 0) {
            BurpCallbacks.getInstance().print("Response error");
            return;
        }

        if (!"".equals(atkData.getOutput()) && response.contains(atkData.getOutput())) {
            atkData.setSuccess(true);

            AttackResult res = new AttackResult(
                    atkData.getAttackType(),
                    "XSSLT" + state,
                    httpMessage.getReq().getChangeParam(),
                    true,
                    "Found: " + atkData.getOutput(),
                    "Found unencoded < character in response.");
            httpMessage.addAttackResult(res);

            ResponseHighlight h = new ResponseHighlight(atkData.getOutput(), failColor);
            httpMessage.getRes().addHighlight(h);
        } else {
            atkData.setSuccess(false);

            AttackResult res = new AttackResult(
                    AttackData.AttackResultType.NONE,
                    "XSSLT" + state,
                    httpMessage.getReq().getChangeParam(),
                    false,
                    null,
                    "");
            httpMessage.addAttackResult(res);
        }

        // Highlight indicator anyway
        String indicator = XssIndicator.getInstance().getBaseIndicator();
        if (!indicator.equals(atkData.getOutput())) {
            ResponseHighlight h = new ResponseHighlight(indicator, Color.green);
            httpMessage.getRes().addHighlight(h);
        }
    }
}
