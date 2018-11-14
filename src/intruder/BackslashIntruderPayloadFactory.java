package intruder;

import attacks.AttackBackslash;
import attacks.model.AttackData;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

import java.util.List;

public class BackslashIntruderPayloadFactory implements IIntruderPayloadGeneratorFactory {
    private String name;
    private List<AttackData> data;

    public BackslashIntruderPayloadFactory(String name, List<AttackData> data) {
        this.name = name;
        this.data = data;
    }

    @Override
    public String getGeneratorName() {
        return "Sentinel - " + name;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new BackslashIntruder(data);
    }

}
