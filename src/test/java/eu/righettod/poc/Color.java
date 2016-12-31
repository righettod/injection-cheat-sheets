package eu.righettod.poc;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.io.Serializable;

/**
 * Color entity
 */
@Entity
@Table(name = "color")
public class Color implements Serializable {

    @Id
    @Column(name = "friendly_name")
    private String friendlyName;

    @Column(name = "red")
    private int red;

    @Column(name = "green")
    private int green;

    @Column(name = "blue")
    private int blue;

    public Color() {
    }

    public Color(String friendlyName, int red, int green, int blue) {
        this.friendlyName = friendlyName;
        this.red = red;
        this.green = green;
        this.blue = blue;
    }

    public String getFriendlyName() {
        return friendlyName;
    }

    public void setFriendlyName(String friendlyName) {
        this.friendlyName = friendlyName;
    }

    public int getRed() {
        return red;
    }

    public void setRed(int red) {
        this.red = red;
    }

    public int getGreen() {
        return green;
    }

    public void setGreen(int green) {
        this.green = green;
    }

    public int getBlue() {
        return blue;
    }

    public void setBlue(int blue) {
        this.blue = blue;
    }


    @Override
    public String toString() {
        return "Color{" +
                       "friendlyName='" + friendlyName + '\'' +
                       ", red=" + red +
                       ", green=" + green +
                       ", blue=" + blue +
                       '}';
    }
}
