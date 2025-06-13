package pro.javacard.jcardsim.tool;

// Essentially simple tagged byte array.
public class RemoteMessage {
    public enum Type {
        POWERUP,
        POWERDOWN,
        RESET,
        ATR,
        APDU,
        ERROR
    }

    byte[] payload;
    Type type;

    public RemoteMessage(Type type, byte[] payload) {
        this.payload = payload.clone();
        this.type = type;
    }

    public RemoteMessage(Type type) {
        this.type = type;
        this.payload = null;
    }

    public Type getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload;
    }
}
