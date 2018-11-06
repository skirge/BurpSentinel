package intruder;

import attacks.model.AttackData;
import burp.IIntruderPayloadGenerator;

import java.util.List;

public class BackslashIntruder implements IIntruderPayloadGenerator
{
    int payloadIndex;
    List<AttackData> data;

    public BackslashIntruder(List<AttackData> data) {
        this.data = data;
    }

    @Override
    public boolean hasMorePayloads()
    {
        return payloadIndex < data.size();
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue)
    {
        byte[] payload = data.get(payloadIndex).getInput().getBytes();
        payloadIndex++;
        return payload;
    }

    @Override
    public void reset()
    {
        payloadIndex = 0;
    }
}