package com.michealyonan.teammh;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.view.WindowManager;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class MainActivity extends Activity {

    private static final String HOME_URL = "https://team-mh.michealuonanayad.workers.dev/";
    private static final String ALLOWED_HOST = "team-mh.michealuonanayad.workers.dev";

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Block screenshots and screen recording of the dashboard.
        getWindow().setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);

        webView = new WebView(this);
        setContentView(webView);

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        // No access to local files or content providers from web content.
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setAllowFileAccessFromFileURLs(false);
        s.setAllowUniversalAccessFromFileURLs(false);
        s.setMediaPlaybackRequiresUserGesture(true);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setBuiltInZoomControls(false);
        s.setSupportZoom(false);
        s.setTextZoom(100);
        // No native bridge: web pages get zero access to app code.

        webView.setWebChromeClient(new WebChromeClient());

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String host = uri.getHost();
                if (host != null && (host.equals(ALLOWED_HOST) || host.endsWith("." + ALLOWED_HOST))) {
                    return false; // stay inside the app for the dashboard's own domain
                }
                // Any other site opens in the system browser, outside the app.
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
                return true;
            }

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler,
                    android.net.http.SslError error) {
                // Never bypass certificate errors.
                handler.cancel();
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request,
                    WebResourceError error) {
                if (request.isForMainFrame()) {
                    String html = "<html dir=\"rtl\" lang=\"ar\"><head>"
                            + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                            + "</head><body style=\"font-family:sans-serif;display:flex;"
                            + "flex-direction:column;align-items:center;justify-content:center;"
                            + "height:100vh;margin:0;background:#0f172a;color:#e2e8f0;\">"
                            + "<h2>لا يوجد اتصال بالإنترنت</h2>"
                            + "<p>تأكد من اتصالك بالشبكة ثم حاول مرة أخرى</p>"
                            + "<button onclick=\"window.location.href='" + HOME_URL + "'\""
                            + " style=\"padding:12px 32px;font-size:18px;border:none;"
                            + "border-radius:8px;background:#3b82f6;color:white;\">إعادة المحاولة</button>"
                            + "</body></html>";
                    view.loadDataWithBaseURL(null, html, "text/html", "utf-8", null);
                }
            }
        });

        webView.loadUrl(HOME_URL);
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
