package com.michealyonan.teammh;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    private static final String HOME_URL = "https://team-mh.michealuonanayad.workers.dev/";
    private static final String ALLOWED_HOST = "team-mh.michealuonanayad.workers.dev";
    private static final long POLL_MS = 20000;
    private static final long JOB_WATCHDOG_MS = 150000;
    private static final long AUTH_HOLD_MS = 5 * 60 * 1000;

    private WebView webView;

    // ---- phone form agent (admin only; the worker gates every endpoint on role) ----
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService net = Executors.newSingleThreadExecutor();
    private WebView agentView;
    private String agentJs;
    private volatile boolean jobRunning = false;
    private volatile long authHoldUntil = 0;
    private JSONObject currentJob;
    private String currentCookie;
    private boolean injected;

    private final Runnable pollRunnable = new Runnable() {
        @Override public void run() {
            pollOnce();
            handler.postDelayed(this, POLL_MS);
        }
    };

    private final Runnable watchdog = new Runnable() {
        @Override public void run() {
            if (jobRunning) finishJob("{\"error\":\"watchdog_timeout\"}");
        }
    };

    private static String chromeUa(String ua) {
        // Google sign-in refuses embedded-WebView agents ("; wv"); present as plain Chrome.
        return ua == null ? null : ua.replace("; wv", "");
    }

    private static boolean inAppHost(String host) {
        if (host == null) return false;
        return host.equals(ALLOWED_HOST) || host.endsWith("." + ALLOWED_HOST)
                || host.equals("docs.google.com")
                || host.equals("accounts.google.com")
                || host.equals("myaccount.google.com")
                || host.equals("accounts.youtube.com");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Block screenshots and screen recording of the dashboard.
        getWindow().setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);

        try {
            InputStream in = getAssets().open("phone_form_agent.js");
            agentJs = readStream(in);
        } catch (Exception e) {
            agentJs = null;
        }

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
        s.setUserAgentString(chromeUa(s.getUserAgentString()));
        // No native bridge on the dashboard WebView: web pages get zero access to app code.

        webView.setWebChromeClient(new WebChromeClient());

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String host = uri.getHost();
                if (inAppHost(host)) {
                    return false; // dashboard and Google sign-in/forms stay inside the app
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

        // Phone agent loop: only does anything when this device is logged in as admin
        // (the worker enforces that) and Google is signed in inside the app.
        handler.postDelayed(pollRunnable, 15000);
    }

    // ---------------- phone agent internals ----------------

    private void pollOnce() {
        if (jobRunning || agentJs == null) return;
        if (System.currentTimeMillis() < authHoldUntil) return;
        final String cookie = CookieManager.getInstance().getCookie(HOME_URL);
        if (cookie == null || cookie.indexOf("session") < 0) return;
        net.execute(new Runnable() {
            @Override public void run() {
                try {
                    HttpURLConnection c = (HttpURLConnection) new URL(HOME_URL + "api/forms/phone-poll").openConnection();
                    c.setRequestProperty("Cookie", cookie);
                    c.setConnectTimeout(15000);
                    c.setReadTimeout(15000);
                    String body = readStream(c.getInputStream());
                    c.disconnect();
                    JSONObject resp = new JSONObject(body);
                    final JSONObject job = resp.optJSONObject("job");
                    if (job != null) {
                        jobRunning = true;
                        handler.post(new Runnable() {
                            @Override public void run() { runJob(job, cookie); }
                        });
                    }
                } catch (Exception ignored) {
                }
            }
        });
    }

    private void runJob(JSONObject job, String cookie) {
        currentJob = job;
        currentCookie = cookie;
        injected = false;
        if (agentView == null) {
            agentView = new WebView(this);
            WebSettings as = agentView.getSettings();
            as.setJavaScriptEnabled(true);
            as.setDomStorageEnabled(true);
            as.setUserAgentString(chromeUa(as.getUserAgentString()));
            agentView.addJavascriptInterface(new ReportBridge(), "AndroidReport");
            agentView.setAlpha(0f);
            FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(1, 1);
            lp.leftMargin = -50;
            lp.topMargin = -50;
            addContentView(agentView, lp);
            agentView.setWebViewClient(new WebViewClient() {
                @Override
                public void onPageFinished(WebView v, String url) {
                    if (!jobRunning || injected || currentJob == null) return;
                    injected = true;
                    String js = "window.__TMH_JOB=" + currentJob.toString() + ";\n" + agentJs;
                    v.evaluateJavascript(js, null);
                }

                @Override
                public void onReceivedSslError(WebView view, SslErrorHandler h,
                        android.net.http.SslError error) {
                    h.cancel();
                }
            });
        }
        String formUrl = job.optString("url");
        if (formUrl.length() == 0) {
            finishJob("{\"error\":\"no_url\"}");
            return;
        }
        handler.postDelayed(watchdog, JOB_WATCHDOG_MS);
        agentView.loadUrl(formUrl);
    }

    private class ReportBridge {
        @JavascriptInterface
        public void report(final String json) {
            handler.post(new Runnable() {
                @Override public void run() { finishJob(json); }
            });
        }
    }

    private void finishJob(String resultJson) {
        if (!jobRunning) return;
        jobRunning = false;
        handler.removeCallbacks(watchdog);
        if (agentView != null) agentView.stopLoading();
        String payload;
        try {
            JSONObject r = new JSONObject(resultJson);
            JSONObject out = new JSONObject();
            out.put("id", currentJob != null ? currentJob.optLong("id") : 0);
            out.put("ok", r.optBoolean("ok"));
            if (r.has("error")) out.put("error", r.optString("error"));
            if (r.has("detail")) out.put("detail", r.optString("detail"));
            if (r.has("status")) out.put("status", r.optInt("status"));
            if (r.has("submitted")) out.put("submitted", r.optBoolean("submitted"));
            if ("auth_expired".equals(r.optString("error"))) {
                authHoldUntil = System.currentTimeMillis() + AUTH_HOLD_MS;
                out.put("retry", true); // worker re-queues; the phone retries after sign-in
            }
            payload = out.toString();
        } catch (Exception e) {
            payload = "{\"id\":0,\"ok\":false,\"error\":\"report_parse\"}";
        }
        final String body = payload;
        final String cookie = currentCookie;
        net.execute(new Runnable() {
            @Override public void run() {
                try {
                    HttpURLConnection c = (HttpURLConnection) new URL(HOME_URL + "api/forms/phone-report").openConnection();
                    c.setRequestMethod("POST");
                    c.setRequestProperty("Cookie", cookie);
                    c.setRequestProperty("Content-Type", "application/json");
                    c.setDoOutput(true);
                    c.setConnectTimeout(15000);
                    c.setReadTimeout(15000);
                    OutputStream os = c.getOutputStream();
                    os.write(body.getBytes(StandardCharsets.UTF_8));
                    os.close();
                    c.getInputStream().close();
                    c.disconnect();
                } catch (Exception ignored) {
                }
            }
        });
    }

    private static String readStream(InputStream in) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) sb.append(line);
        br.close();
        return sb.toString();
    }

    // ---------------- lifecycle ----------------

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
        handler.removeCallbacks(pollRunnable);
        handler.removeCallbacks(watchdog);
        if (agentView != null) {
            agentView.destroy();
            agentView = null;
        }
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
