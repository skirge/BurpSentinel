package intruder;

import attacks.AttackBackslash;
import attacks.model.AttackData;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

import java.util.List;

public class SmartCodeIntruderPayloadFactory implements IIntruderPayloadGeneratorFactory {
    @Override
    public String getGeneratorName() {
        return "Sentinel - Smart Code Injections";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        List<AttackData> data = AttackBackslash.generateAttackData("FUZZME", false);
        return new BackslashIntruder(data);
    }
}
