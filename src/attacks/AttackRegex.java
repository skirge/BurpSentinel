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
public class AttackRegex extends AttackI {
    // Static:
    private final Color failColor = new Color(0xff, 0xcc, 0xcc, 100);
    private LinkedList<AttackData> attackData;

    private int state = 0;

    public AttackRegex(AttackWorkEntry work) {
        super(work);

        attackData = new LinkedList<AttackData>();
        String indicator;

        indicator = XssIndicator.getInstance().getIndicator();

        attackData.add(new AttackData(0, indicator +"\\0", indicator, AttackData.AttackResultType.STATUSGOOD));
        attackData.add(new AttackData(1, indicator + "\\1", indicator, AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(2, indicator + "\\99", indicator, AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(3, indicator + "\\100", indicator, AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(4, indicator +"$0", indicator, AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(5, indicator + "$1", indicator, AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(6, indicator + "$99", indicator, AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(7, indicator + "$100", indicator, AttackData.AttackResultType.VULNSURE));
    }

    @Override
    protected String getAtkName() {
        return "REGEX";
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
            analyzeResponse(data, httpMessage);
        } catch (ConnectionTimeoutException ex) {
            state++;
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
        // Highlight indicator anyway
        String indicator = XssIndicator.getInstance().getBaseIndicator();
        if (! indicator.equals(data.getOutput())) {
            ResponseHighlight h = new ResponseHighlight(indicator, Color.green);
            httpMessage.getRes().addHighlight(h);
        }
    }

}
