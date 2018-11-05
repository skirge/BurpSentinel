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
import attacks.model.AttackResult;
import gui.categorizer.model.ResponseCategory;
import gui.networking.AttackWorkEntry;

import java.awt.Color;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

import model.ResponseHighlight;
import model.SentinelHttpMessageAtk;
import model.XssIndicator;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

/**
 * @author dobin
 */
public class AttackBackslash extends AttackI {
    private static final String ATTACK_NAME = "BACKSLASH";
    private final Color failColor = new Color(0xff, 0xcc, 0xcc, 100);

    private static final char[] specialCharacters = {' ', '!', '"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<',
            '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', '\'', 't', 'b', 'r', 'n', 'f', '0', '1', '2', 'u', 'o', 'x', '\r', '\n',
            '\u560a', '\u560d', '\u563e', '\u563c'
    };

    private static final String[] singleLineComments = {
            "#", "//", "-- ", ";", "%", "'", "\"", "\\", "!", "*", "\r", "\n", "\r\n"
    };

    private static final String[] multilineComments = {
            "/*test*/", "(*test*)", "%(test)%", "{test}", "{-test-}", "#|test|#", "#=test=#", "#[test]#", "--[[test]]",
            "<!--test-->"
    };

    private static final String[] concatenation = {
            "", " ", "+", ".", "&", "||", "//", "~", "<>", "..", ":", "^", "++", "$+", ","
    };

    private static final String[] stringDelimiters = {
            "", "\"", "'", "'''", "]]", "`", "\r", "\n"
    };

    private static final String[] numericInjections = {
            "+0", "-0", "/1", "*1", " sum 0", " difference 0", " product 1", " add 0", " sub 0", " mul 1", " div 1", " idiv 1",
            "**1", "^1", "|0", " $ne 0", " $gt 0", " $lt 0", " $eq 0"
    };

    private static final String[] commandSeparators = {
            ";", ",", ":", "\n", "\r", "\r\n", "\u0008", "\u0009", "&&", "||", "&", "|", ">"
    };

    private LinkedList<AttackData> attackData;

    private int state = 0;

    public AttackBackslash(AttackWorkEntry work, boolean allPayloads) {
        super(work);

        attackData = new LinkedList<AttackData>();
        String indicator = attackWorkEntry.attackHttpParam.getDecodedValue();
        attackData.addAll(generateAttackData(indicator, allPayloads));
    }

    private static Collection<? extends AttackData> generateAttackData(String indicator, boolean allPayloads) {
        List attacks = new LinkedList<AttackData>();

        int attackIndex = 0;

        attacks.add(new AttackData(attackIndex++, indicator, indicator, AttackData.AttackResultType.STATUSGOOD));

        if (allPayloads) {
            for (int i = 0; i < specialCharacters.length; i++) {
                for (int j = 0; j < specialCharacters.length; j++) {
                    attacks.add(new AttackData(attackIndex++, indicator + specialCharacters[i] + specialCharacters[j],
                            indicator, AttackData.AttackResultType.VULNUNSURE));
                    attacks.add(new AttackData(attackIndex++, indicator + "\\" + specialCharacters[i] + specialCharacters[j],
                            indicator + specialCharacters[i],
                            AttackData.AttackResultType.VULNSURE));
                    attacks.add(new AttackData(attackIndex++, indicator + "\\\\" + specialCharacters[i] + specialCharacters[j],
                            indicator + "\\" + specialCharacters[i],
                            AttackData.AttackResultType.VULNSURE));
                }
            }
        } else {

            for (int i = 0; i < stringDelimiters.length; i++) {
                for (int j = 0; j < singleLineComments.length; j++) {
                    attacks.add(new AttackData(attackIndex++, indicator + stringDelimiters[i] + singleLineComments[j],
                            indicator, AttackData.AttackResultType.VULNSURE));
                }
            }

            for (int i = 0; i < stringDelimiters.length; i++) {
                for (int j = 0; j < multilineComments.length; j++) {
                    attacks.add(new AttackData(attackIndex++, indicator + stringDelimiters[i] + multilineComments[j]
                            + stringDelimiters[i], indicator, AttackData.AttackResultType.VULNSURE));
                    attacks.add(new AttackData(attackIndex++, indicator + stringDelimiters[i] + multilineComments[j]
                            , indicator, AttackData.AttackResultType.VULNSURE));
                }
            }

            for (int i = 0; i < stringDelimiters.length; i++) {
                for (int j = 0; j < concatenation.length; j++) {
                    attacks.add(new AttackData(attackIndex++, indicator + stringDelimiters[i] + concatenation[j]
                            + stringDelimiters[i], indicator, AttackData.AttackResultType.VULNSURE));
                }
            }

            for (int i = 0; i < numericInjections.length; i++) {
                attacks.add(new AttackData(attackIndex++, indicator + numericInjections[i], indicator,
                        AttackData.AttackResultType.VULNUNSURE));
            }
            attacks.add(new AttackData(attackIndex++, "abs(" + indicator +")", indicator,
                    AttackData.AttackResultType.VULNSURE));
        }
        return new ArrayList<>(new LinkedHashSet<>(attacks));
    }

    @Override
    protected String getAtkName() {
        return ATTACK_NAME;
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

        if (attackData.isEmpty())
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
            return false;
        } catch (UnsupportedEncodingException e) {
            state++;
            BurpCallbacks.getInstance().print("Encoding error: " + e.getLocalizedMessage());
        }


        if (state >= attackData.size() - 1) {
            doContinue = false;
        }

        state++;
        return doContinue;
    }

    private void analyzeResponse(AttackData data, SentinelHttpMessageAtk httpMessage) {
        boolean hasError = false;
        ResponseCategory responseCategory = null;

        String response = httpMessage.getRes().getResponseStr();
        if (response == null || response.length() == 0) {
            BurpCallbacks.getInstance().print("Response error");
            return;
        }

        for(ResponseCategory rc: httpMessage.getRes().getCategories()) {
            hasError = true;
            responseCategory = rc;
            break;
        }

        if (hasError) {
            AttackResult res = new AttackResult(
                    AttackData.AttackResultType.VULNSURE,
                    this.ATTACK_NAME,
                    httpMessage.getReq().getChangeParam(),
                    true,
                    "Error: " + responseCategory.getIndicator(),
                    "Exception message in response");
            httpMessage.addAttackResult(res);
        }

        if (response.contains(data.getOutput())) {
            ResponseHighlight h = new ResponseHighlight(data.getOutput(), Color.green);
            httpMessage.getRes().addHighlight(h);
        }
    }


    public static void main(String[] args) throws UnsupportedEncodingException {
        Collection<? extends AttackData> attacks = generateAttackData("FUZZME", true);

        attacks.stream().map(AttackData::getInput).map(s -> {
            try {
                return URLEncoder.encode(s, "utf-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return null;
        }).forEach(System.out::println);
    }
}
