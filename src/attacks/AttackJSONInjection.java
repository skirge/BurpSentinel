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
import model.SentinelHttpMessage;
import model.SentinelHttpMessageAtk;
import model.XssIndicator;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.translate.CharSequenceTranslator;
import org.apache.commons.lang3.text.translate.EntityArrays;
import org.apache.commons.lang3.text.translate.LookupTranslator;
import org.apache.commons.lang3.text.translate.UnicodeEscaper;
import org.w3c.tidy.TidyMessage;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

/**
 * @author dobin
 */
public class AttackJSONInjection extends AttackI {
    // Static:
    private final Color failColor = new Color(0xff, 0xcc, 0xcc, 100);
    private LinkedList<AttackData> attackData;

    public static final CharSequenceTranslator ESCAPE_UNICODE = new UnicodeEscaper();

    private int state = 0;

    public AttackJSONInjection(AttackWorkEntry work) {
        super(work);

        attackData = new LinkedList<AttackData>();

        String indicator = attackWorkEntry.attackHttpParam.getDecodedValue();
        int index = 0;

        attackData.add(new AttackData(index++, indicator,indicator, AttackData.AttackResultType.STATUSGOOD));
        attackData.add(new AttackData(index++, "\"" + ESCAPE_UNICODE.translate(indicator) + "\"",indicator, AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "[]",  "[]", AttackData.AttackResultType.VULNUNSURE));
        attackData.add(new AttackData(index++, "{}",  "{}", AttackData.AttackResultType.VULNUNSURE));
        attackData.add(new AttackData(index++, "1",  "1", AttackData.AttackResultType.VULNUNSURE));
        attackData.add(new AttackData(index++, "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",  "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", AttackData.AttackResultType.VULNUNSURE));
        attackData.add(new AttackData(index++, "\"test\"", "test", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"@class\":\"java.io.IOException\"}","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"java.io.IOException\":\"test\"}","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "[\"java.io.IOException\",\"test\"]","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"@c\":\"java.io.IOException\"}","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"@type\":\"java.io.IOException\"}","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"preferredClass\":\"java.io.IOException\"}","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"$type\":\"java.io.IOException\"}","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"__type\":\"java.io.IOException\"}","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"__record\":\"Map\"}","Exception", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, "{\"__iterable\":\"Map\"}","Exception", AttackData.AttackResultType.VULNSURE));
    }

    @Override
    protected String getAtkName() {
        return "JSON";
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
            // this attack by default removes param value with payload
            httpMessage = attack(data, true);
            if (httpMessage == null) {
                doContinue = false;
            }
            analyzeResponse(data, httpMessage);
        } catch (ConnectionTimeoutException ex) {
            BurpCallbacks.getInstance().print("Connection timeout: " + ex.getLocalizedMessage());
            doContinue = false;
        }

        if (state >= attackData.size()-1) {
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

        if (response.contains(data.getOutput())) {
            ResponseHighlight h = new ResponseHighlight(data.getOutput(), Color.green);
            httpMessage.getRes().addHighlight(h);
        }
    }

}
