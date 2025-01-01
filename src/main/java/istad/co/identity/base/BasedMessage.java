// BasedMessage.java
package istad.co.identity.base;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BasedMessage {
    private String message;
    private Object data;

    // Constructor for message-only responses
    public BasedMessage(String message) {
        this.message = message;
        this.data = null;
    }
}