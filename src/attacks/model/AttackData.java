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

package attacks.model;

import util.BurpCallbacks;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Objects;

/**
 *
 * @author unreal
 */
public class AttackData {


    public enum AttackResultType {
        NONE,
        ABORT,
        ERROR,

        STATUSGOOD,
	STATUSBAD,

        INFO,
        INFOSURE,
        INFOUNSURE,
        
        VULNSURE,
        VULNUNSURE
    };

    private String input;
    private String output;
    private Boolean success = false;
    private int index = -1;
    private AttackResultType attackType;
    
    public AttackData(int index, String input, String output, AttackResultType attackType) {
        this.index = index;
        this.input = input;
        this.output = output;
        this.attackType = attackType;
    }
    
    public AttackResultType getAttackType() {
        return attackType;
    }
    
    public int getIndex() {
        return index;
    }
    
    public String getInput() {
        return input;
    }
    
    public String getOutput() {
        return output;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public Boolean getSuccess() {
        return success;
    }
 
    public void urlEncode() throws UnsupportedEncodingException {
        input = URLEncoder.encode(input,"UTF-8");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttackData that = (AttackData) o;
        return Objects.equals(getInput(), that.getInput()) &&
                Objects.equals(getOutput(), that.getOutput());
    }

    @Override
    public int hashCode() {

        return Objects.hash(getInput(), getOutput());
    }

}
