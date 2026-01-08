package co.uk.theconfigteam.tctm.capacitor.https;

import android.net.Uri;
import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;

import com.getcapacitor.BridgeWebViewClient;
import com.getcapacitor.Logger;
import com.getcapacitor.Plugin;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Objects;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

@CapacitorPlugin(name = "TCTMHttps")
public class TCTMHttpsPlugin extends Plugin {

    TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[]{};
                }

                @Override
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                }
            }
    };

    @Override
    public void load() {
        
        if (this.getBridge().getConfig().getHostname().equalsIgnoreCase("localhost"))
            //no specific server set - ignore!
            return;

        boolean ignoreSSLErrors = this.getConfig().getBoolean("ignoreSSLErrors", false);
        if (ignoreSSLErrors) {
            try {
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

                String allowedHostname = this.getBridge().getConfig().getHostname();
                HostnameVerifier originalVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
                HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> {
                    if (allowedHostname.equalsIgnoreCase(hostname))
                        return true;

                    return originalVerifier.verify(hostname, session);
                });
                HttpsURLConnection.setFollowRedirects(true);
            } catch (KeyManagementException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        String[] backendPaths = this.getConfig().getArray("backendPaths", new String[]{});

        this.bridge.setWebViewClient(new BridgeWebViewClient(this.bridge) {
            @Override
            public void onReceivedSslError(WebView view, final SslErrorHandler handler, SslError error) {
                if (ignoreSSLErrors)
                    handler.proceed();
                else
                    handler.cancel();
            }

            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                for (String backendPath : backendPaths)
                    if (Objects.requireNonNull(request.getUrl().getPath()).startsWith(backendPath))
                        return null;

                return super.shouldInterceptRequest(view, request);
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                if(request.getUrl().getHost().equalsIgnoreCase(Uri.parse(bridge.getScheme() + "://" + bridge.getHost()).getHost())
                   && request.getUrl().getBooleanQueryParameter("ssoLoginDone", false)
                ){
                    //when we bounce back from SSO login, we need to load the URL again so the shouldInterceptRequest is called again
                    //and the data is loaded from the local server
                    view.loadUrl(request.getUrl().toString());
                    return false;
                }
                return super.shouldOverrideUrlLoading(view, request);
            }
        });
    }
}
