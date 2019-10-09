import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;

public class Test {


    @org.junit.Test
    public void getkey() throws Exception {
        KeyPair keyPair = TestRSA.getKeyPair();
        String privateKey = new String(Base64.encodeBase64(keyPair.getPrivate().getEncoded()));
        String publicKey = new String(Base64.encodeBase64(keyPair.getPublic().getEncoded()));
        System.out.println("私钥:" + privateKey);
        System.out.println("公钥:" + publicKey);
    }

    //私钥
    public String privateKey = "MIICcwIBADANBgkqhkiG9w0BAQEFAASCAl0wggJZAgEAAoGBAI4ey1fLJxfC/DjE/YeoxN4gHmMJtDCk8QVr49EuyFtoopTYNkHMYF0Sev15i5y5cAio8vQkq/IhWsW/0yCa8hOvLC7BOH9qcvoHvngbx7xVQzhlyzcq5yFGixxbm3vgZisNg7PhR3wTBzfkSJQGh88O+FSkB/P9AsQNQspOzxopAgMBAAECfxY0uZD+LR2JWd+E6BhKRnhujFDtMzpmi0JNmUsWBDhEISMgpVmilWv1d0Iju6zBTMANpeh/0l4C2CwNzO9LRoePsPvLo7Aq1QDGvur4nKSeyNOifk/WefHKSoigGBvjxsC67YRIY11JVsZxEwZhYaAbZ5er3XDTlMaXFLo+USECQQDvWzeoYhJvhFe7pYgCx0rBpepZxx3FbbxtAYnOKF/Fq3a5/QthB94ttYIfRprEnaw9AT1+0jzZBvkt8QzddnhvAkEAmACtlNm7BGckzbR+tZyDSnpxw5E9rTrJizqzFjs1zqnKryt6WnUTLZ4dksVjJbbmGCw2qK6ZHXGJxqLoKqly5wJAb8xoc9LTD5l+LRyFKd8SUN8BVkvF4Rh/gV7NkiiTi02qV/cUoI6/PRRhoeAlnB6Ve60fnyPt3eT+8HF989dJKwJAC/ohs1Tks5gdAkhyo4TNo5S6WhqbrYawUtQxQFMyDjK60cqvPWl0NWf8FJCRG2up/cWeGPSJBBTqMkir2pC3iQJAH3ag/xZgQFrYfFHHQEvMYDk4BJOBGd97H5WzTRxEZctjvZE9JjBWn2Ktg8/DOI0NyhhLyfeiAqlM55MarPF+cQ==";
    //公钥
    public String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOHstXyycXwvw4xP2HqMTeIB5jCbQwpPEFa+PRLshbaKKU2DZBzGBdEnr9eYucuXAIqPL0JKvyIVrFv9MgmvITrywuwTh/anL6B754G8e8VUM4Zcs3KuchRoscW5t74GYrDYOz4Ud8Ewc35EiUBofPDvhUpAfz/QLEDULKTs8aKQIDAQAB";



}
