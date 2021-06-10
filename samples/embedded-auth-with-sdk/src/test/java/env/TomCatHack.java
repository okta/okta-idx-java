package env;

import org.apache.catalina.webresources.TomcatURLStreamHandlerFactory;
import org.junit.Test;

public class TomCatHack {

    @Test
    public void test() {
        System.out.println("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        System.out.println(TomcatURLStreamHandlerFactory.disable());
    }
}
