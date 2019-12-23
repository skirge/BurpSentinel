/*
 * Copyright (C) 2019 skirge
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

/**
 *
 * @author skirge
 */
public class AttackUnicode extends AttackI {
    // Static:
    private final Color failColor = new Color(0xff, 0xcc, 0xcc, 100);
    private LinkedList<AttackData> attackData = new LinkedList<AttackData>();

    private int state = 0;

    public AttackUnicode(AttackWorkEntry work) {
        super(work);

        String indicator = attackWorkEntry.attackHttpParam.getDecodedValue();

        int index = 0;

        attackData.addAll(generateAttackData(indicator));
    }

    public static List<AttackData> generateAttackData(String indicator) {
        int index = 0;
        List<AttackData> attackData = new LinkedList<AttackData>();
        attackData.add(new AttackData(index++, indicator, indicator, AttackData.AttackResultType.STATUSGOOD));
        attackData.add(new AttackData(index++, indicator + "\u0000\u0000\u0000\u0000\u0000", indicator + "\u0000", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2080", indicator + "0", AttackData.AttackResultType.VULNSURE));
        //• U+2101, ℁
        //• U+2105, ℅
        //• U+2106, ℆
        //• U+FF0F, ／
        //• U+2047, ⁇
        //• U+2048, ⁈
        //• U+2049, ⁉
        //• U+FE16,︖
        //• U+FE56, ﹖
        //• U+FF1F, ？
        //• U+FE5F, ﹟
        //• U+FF03, ＃
        //• U+FE6B, ﹫
        //• U+FF20, ＠
        attackData.add(new AttackData(index++, indicator + "\u2100", indicator + "a/c", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2101", indicator + "c/0", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2106", indicator + "c/u", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\uff0f", indicator + "/", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\uff0c", indicator + " ,", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2047", indicator + "??", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2048", indicator + "?!", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2049", indicator + "!?", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\ufe16", indicator + "?", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\ufe56", indicator + "?", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\uff1f", indicator + "?", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\ufe5f", indicator + "#", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\uff03", indicator + "#", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\ufe6b", indicator + "@", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\uff20", indicator + "@", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u249b", indicator + "20.", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u00BD", indicator + "1/2", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2082", indicator + "2", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2473", indicator + "20", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2487", indicator + "(20)", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u24EA", indicator + "0", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u1F01", indicator + "0,", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\u2152", indicator + "1/10", AttackData.AttackResultType.VULNSURE));

        // U+FFED ￭
        attackData.add(new AttackData(index++, indicator + "\uFFED", indicator + "￭", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\uFF41", indicator + "a", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\uFF21", indicator + "A", AttackData.AttackResultType.VULNSURE));
        attackData.add(new AttackData(index++, indicator + "\uFF10", indicator + "0", AttackData.AttackResultType.VULNSURE));



        return new LinkedList<AttackData>(new LinkedHashSet<>(attackData));
    }

    @Override
    protected String getAtkName() {
        return "UNICODE";
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
