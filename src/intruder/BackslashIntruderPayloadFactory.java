package intruder;

import attacks.AttackBackslash;
import attacks.model.AttackData;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

import java.util.List;

public class BackslashIntruderPayloadFactory implements IIntruderPayloadGeneratorFactory {

    @Override
    public String getGeneratorName() {
        return "Sentinel - Backslash payloads";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        List<AttackData> data = AttackBackslash.generateAttackData("FUZZME", true);
        return new BackslashIntruder(data);
    }

}
