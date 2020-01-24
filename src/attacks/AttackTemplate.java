/*
 * Copyright (C) 2016 dobin
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

import attacks.model.AttackData;
import attacks.model.AttackI;
import gui.networking.AttackWorkEntry;
import java.awt.Color;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;

import model.ResponseHighlight;
import model.SentinelHttpMessageAtk;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

import static attacks.model.AttackData.AttackResultType.STATUSGOOD;
import static attacks.model.AttackData.AttackResultType.VULNSURE;

/**
 *
 * @author dobin
 */
public class AttackTemplate extends AttackI {
    // Static:
    private final Color failColor = new Color(0xff, 0xcc, 0xcc, 100);
    private LinkedList<AttackData> attackData = new LinkedList<AttackData>();
    
    private int state = 0;
    
    public AttackTemplate(AttackWorkEntry work) {
        super(work);
        
        String indicator = attackWorkEntry.attackHttpParam.getDecodedValue();

        int index = 0;

        attackData.addAll(generateAttackData(indicator));
    }

    public static List<AttackData> generateAttackData(String indicator) {
        int index = 0;
        List<AttackData> attackData = new LinkedList<AttackData>();
        attackData.add(new AttackData(index++, indicator, indicator, STATUSGOOD));
        // injection in template context
        attackData.add(new AttackData(index++, "{{'" + indicator +"'}}",  indicator, VULNSURE));
        attackData.add(new AttackData(index++, "{{777-111}}",  "666", VULNSURE));
        attackData.add(new AttackData(index++, "${777-111}",  "666", VULNSURE));
        attackData.add(new AttackData(index++, "${'"+indicator +"'}",  indicator, VULNSURE));
        attackData.add(new AttackData(index++, "{{3*'6'}}",  "666", VULNSURE));
        attackData.add(new AttackData(index++,  "6{*comment*}66",  "666", VULNSURE));
        attackData.add(new AttackData(index++,  "6{{! comment}}66",  "666", VULNSURE));
        attackData.add(new AttackData(index++,  "${\"6\".join(\"66\")}",  "666", VULNSURE));
        attackData.add(new AttackData(index++, "cos.constructor(\"return \\\"" + indicator + "\\\"\")()", indicator, VULNSURE));
        attackData.add(new AttackData(index++, "concat.constructor(\"return 777-111\")()", "666", VULNSURE));
        attackData.add(new AttackData(index++, "#{777-111}", "666", VULNSURE));
        attackData.add(new AttackData(index++, "= 777-111", "666", VULNSURE));
        attackData.add(new AttackData(index++, "#{'"+indicator+"'}", indicator, VULNSURE));
        attackData.add(new AttackData(index++, "666+0", "666", VULNSURE));
        attackData.add(new AttackData(index++, "666-0", "666", VULNSURE));
        attackData.add(new AttackData(index++, "666/1", "666", VULNSURE));
        attackData.add(new AttackData(index++, "666*1", "666", VULNSURE));
        attackData.add(new AttackData(index++, "#set( $string = \"666\" )\r\n$string.class", "java.lang.String", VULNSURE));
        attackData.add(new AttackData(index++, "*{class}", "java", VULNSURE));
        attackData.add(new AttackData(index++, "~{:: title}", "", VULNSURE));
        attackData.add(new AttackData(index++, "@{/order/{orderId}/details(orderId=${777-111})}", "666", VULNSURE));
        attackData.add(new AttackData(index++, "${{777-111}}", "666", VULNSURE));
        attackData.add(new AttackData(index++, "*{{class}}", "java", VULNSURE));
        attackData.add(new AttackData(index++, "__${777-111}__", "666", VULNSURE));
        attackData.add(new AttackData(index++, "!{777-111}", "666", VULNSURE));
        attackData.add(new AttackData(index++, "$(777-111)", "666", VULNSURE));
        attackData.add(new AttackData(index++, "@{(777-111)}", "666", VULNSURE));
        attackData.add(new AttackData(index++, "T(String).valueOf(\"" + indicator + "\")", indicator, VULNSURE));
        attackData.add(new AttackData(index++, "T(Integer).valueOf(666)", "666", VULNSURE));
        attackData.add(new AttackData(index++, "{{this}}", "Object", VULNSURE));
        attackData.add(new AttackData(index++, "{{self}}", "Object", VULNSURE));
        attackData.add(new AttackData(index++, "{[expr 777-111]}", "666", VULNSURE));
        attackData.add(new AttackData(index++, "{[error PWNED!]}", "PWNED!", VULNSURE));
        attackData.add(new AttackData(index++, "<%= 777-111 %>", "666", VULNSURE));
        // injection in template placeholder context
        attackData.add(new AttackData(index++, "]}{[error PWNED!", "PWNED!", VULNSURE));
        attackData.add(new AttackData(index++, "}!{777-111", "666", VULNSURE));
        attackData.add(new AttackData(index++, ")$(777-111", "666", VULNSURE));
        attackData.add(new AttackData(index++, ")}@{(777-111", "666", VULNSURE));
        attackData.add(new AttackData(index++, "}#{777-111", "666", VULNSURE));
        attackData.add(new AttackData(index++, "}}{{777-111",  "666", VULNSURE));
        attackData.add(new AttackData(index++, "}*{class", "java", VULNSURE));

        // errors
        attackData.add(new AttackData(index++, "${",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "{{",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "#{",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "~{",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "!{",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "@{",  "Error", VULNSURE));

        attackData.add(new AttackData(index++, "\uFF04{",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "\uFF20{",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "\uFF03{",  "Error", VULNSURE));

        attackData.add(new AttackData(index++, "\\uFF04{",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "\\uFF20{",  "Error", VULNSURE));
        attackData.add(new AttackData(index++, "\\uFF03{",  "Error", VULNSURE));



        return new LinkedList<AttackData>(new LinkedHashSet<>(attackData));
    }
    
    @Override
    protected String getAtkName() {
        return "TMPL";
    }
    
    @Override
    protected int getState() {
        return state;
    }
    
    @Override
    public boolean init() {
        return true;
    }
    

    @Override
    public boolean performNextAttack() {
        boolean doContinue = true;

        if(attackData.isEmpty())
            return false;

        BurpCallbacks.getInstance().print("A: " + state);
        
        AttackData data = attackData.get(state);
        SentinelHttpMessageAtk httpMessage;
        try {
            httpMessage = attack(data, false);
            if (httpMessage == null) {
                state++;
                return false;
            }
            analyzeResponse(data, httpMessage);

        } catch (ConnectionTimeoutException ex) {
            state++;
            BurpCallbacks.getInstance().print("Connection timeout: " + ex.getLocalizedMessage());
            return false;
        } catch (UnsupportedEncodingException e) {
            BurpCallbacks.getInstance().print("Encoding error: " + e.getLocalizedMessage());
        }


        if(state >= attackData.size()-1) {
            doContinue = false;
        }
        
        state++;
        return doContinue;
    }
    
    private void analyzeResponse(AttackData data, SentinelHttpMessageAtk httpMessage) {
            String response = httpMessage.getRes().getResponseStr();
            if (response == null || response.length() == 0) {
                BurpCallbacks.getInstance().print("Response error");
                return;
            }

            if (!"".equals(data.getOutput()) && response.contains(data.getOutput())) {
                ResponseHighlight h = new ResponseHighlight(data.getOutput(), Color.green);
                httpMessage.getRes().addHighlight(h);
            }
    }

}
