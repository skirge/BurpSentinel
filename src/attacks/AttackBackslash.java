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
import java.util.LinkedList;
import model.ResponseHighlight;
import model.SentinelHttpMessageAtk;
import model.XssIndicator;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

/**
 *
 * @author dobin
 */
public class AttackBackslash extends AttackI {
    private final Color failColor = new Color(0xff, 0xcc, 0xcc, 100);
    private final char[] specialCharacters = {' ','!','"','#','$','%','&','(',')','*','+',',','-','.','/',':',';','<',
            '=','>','?','@','[','\\',']','^','_','`','{','|','}','~','\'','t','b','r','n','f','0','1','2','u','o','x' };

    private final String[] singleLineComments = {
            "#", "//", "-- ", ";", "%", "'", "\"", "\\", "!", "*"
    };

    private final String[] multilineComments = {
            "/*test*/","(*test*)","%(test)%", "{test}", "{-test-}","#|test|#","#=test=#", "#[test]#","--[[test]]",
            "<!--test-->"
    };

    private final String[] concatenation = {
            "+",".","&","||","//","~","<>","..",":","^","++","$+",","
    };

    private final String[] stringDelimiters = {
            "","\"","'","'''","]]","`"
    };

    private final String[] numericInjections = {
            "+0","-0","/1","*1"," sum 0"," difference 0"," product 1"," add 0"," sub 0"," mul 1"," div 1"," idiv 1",
            "**1","^1","|0"
    };

    private final String[] commandSeparators = {
            ";",",",":","\n","\r","\r\n","\u0008","\u0009"
    };

    private LinkedList<AttackData> attackData;

    private int state = 0;

    public AttackBackslash(AttackWorkEntry work) {
        super(work);

        attackData = new LinkedList<AttackData>();
        String indicator = attackWorkEntry.attackHttpParam.getDecodedValue();
        int attackIndex = 0;

        attackData.add(new AttackData(attackIndex++, indicator, indicator, AttackData.AttackResultType.STATUSGOOD));
        for(int i=0;i<specialCharacters.length;i++) {
            char special = specialCharacters[i];
            attackData.add(new AttackData(attackIndex++, indicator + special, indicator + special,
                    AttackData.AttackResultType.VULNUNSURE));
            attackData.add(new AttackData(attackIndex++, indicator + "\\" + special, indicator + special,
                    AttackData.AttackResultType.VULNSURE));
            attackData.add(new AttackData(attackIndex++, indicator + "\\\\" + special, indicator + "\\" + special,
                    AttackData.AttackResultType.VULNSURE));
        }

        for(int i = 0; i<stringDelimiters.length;i++) {
            for(int j = 0; j<singleLineComments.length;j++) {
                attackData.add(new AttackData(attackIndex++, indicator + stringDelimiters[i] + singleLineComments[j],
                        indicator, AttackData.AttackResultType.VULNSURE));
            }
        }

        for(int i = 0; i<stringDelimiters.length;i++) {
            for(int j = 0; j<multilineComments.length;j++) {
                attackData.add(new AttackData(attackIndex++, indicator + stringDelimiters[i] + multilineComments[j]
                        + stringDelimiters[i], indicator, AttackData.AttackResultType.VULNSURE));
                attackData.add(new AttackData(attackIndex++, indicator + stringDelimiters[i] + multilineComments[j]
                        , indicator, AttackData.AttackResultType.VULNSURE));
            }
        }

        for(int i = 0; i<stringDelimiters.length;i++) {
            for(int j = 0; j<concatenation.length;j++) {
                attackData.add(new AttackData(attackIndex++, indicator + stringDelimiters[i] + concatenation[j]
                      + stringDelimiters[i], indicator, AttackData.AttackResultType.VULNSURE));
            }
        }

        for(int i = 0; i<commandSeparators.length;i++) {
            attackData.add(new AttackData(attackIndex++, indicator + commandSeparators[i] + indicator, indicator, AttackData.AttackResultType.VULNSURE));
        }
        // duplicated value
        attackData.add(new AttackData(attackIndex++, indicator + ";" + indicator, indicator, AttackData.AttackResultType.VULNSURE));

        // TODO: only for numerical fields
        for(int i=0;i<numericInjections.length;i++) {
            attackData.add(new AttackData(attackIndex++, indicator + numericInjections[i], indicator,
                    AttackData.AttackResultType.VULNUNSURE));
        }

    }

    @Override
    protected String getAtkName() {
        return "BACKSLASH";
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

        BurpCallbacks.getInstance().print("A: " + state);

        AttackData data = attackData.get(state);
        SentinelHttpMessageAtk httpMessage;
        try {
            httpMessage = attack(data, false);
            if (httpMessage == null) {
                state++;
                return false;
            }
        } catch (ConnectionTimeoutException ex) {
            state++;
            return false;
        }

        analyzeResponse(data, httpMessage);

        if(state >= attackData.size()-1) {
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
    }

}
