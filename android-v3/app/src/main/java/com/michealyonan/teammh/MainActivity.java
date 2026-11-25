package com.michealyonan.teammh;

import android.Manifest;
import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.GeolocationPermissions;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.SslErrorHandler;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.TextView;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.content.FileProvider;
import androidx.fragment.app.FragmentActivity;

import com.google.firebase.messaging.FirebaseMessaging;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends FragmentActivity {

    private static final String HOME_URL = "https://team-mh.michealuonanayad.workers.dev/";
    private static final String ALLOWED_HOST = "team-mh.michealuonanayad.workers.dev";
    private static final long POLL_MS = 20000;
    private static final long JOB_WATCHDOG_MS = 90000;
    private static final long AUTH_HOLD_MS = 5 * 60 * 1000;
    private static final int RC_FILE_CHOOSER = 41;
    private static final int RC_MIC_PERM = 42;
    private static final int RC_STORAGE_PERM = 43;
    private static final int RC_NOTIF_PERM = 44;

    private WebView webView;

    // ---- v3 additions (Micheal 26 Nov: اعتماد الكل) ----
    private boolean unlocked = false;
    private ValueCallback<Uri[]> fileCallback;
    private Uri cameraUri;
    private PermissionRequest pendingMicRequest;
    private String pendingGeoOrigin;
    private GeolocationPermissions.Callback pendingGeoCallback;
    private static final int RC_STARTUP_PERMS = 45;
    private static final int RC_GEO_PERM = 46;

    // ---- phone form agent (admin only; the worker gates every endpoint on role) ----
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService net = Executors.newSingleThreadExecutor();
    private WebView agentView;
    private String agentJs;
    private volatile boolean jobRunning = false;
    private volatile long authHoldUntil = 0;
    private JSONObject currentJob;
    private String currentToken;
    private boolean injected;

    private final Runnable pollRunnable = new Runnable() {
        @Override public void run() {
            pollOnce();
            handler.postDelayed(this, POLL_MS);
        }
    };

    private final Runnable watchdog = new Runnable() {
        @Override public void run() {
            if (!jobRunning) return;
            if (agentView == null) { finishJob("{\"error\":\"watchdog_timeout\",\"detail\":\"no_agent_view\"}"); return; }
            agentView.evaluateJavascript(
                    "(function(){try{return location.href.slice(0,110)+' | t:'+document.title.slice(0,50)+' | rs:'+document.readyState+' | alive:'+(window.__TMH_ALIVE?1:0)}catch(e){return 'eval_err:'+e}})()",
                    value -> {
                        String d = value == null ? "null" : value;
                        if (d.length() > 172) d = d.substring(0, 172);
                        try {
                            JSONObject diag = new JSONObject();
                            diag.put("error", "watchdog_timeout");
                            diag.put("detail", d);
                            finishJob(diag.toString());
                        } catch (Exception e) {
                            finishJob("{\"error\":\"watchdog_timeout\"}");
                        }
                    });
        }
    };

    private final Runnable injectProbe = new Runnable() {
        @Override public void run() {
            if (!jobRunning || agentView == null || currentJob == null) return;
            agentView.evaluateJavascript("window.__TMH_ALIVE?1:0", value -> {
                if (!jobRunning) return;
                if (value != null && value.trim().equals("1")) {
                    injected = true;
                    return;
                }
                agentView.evaluateJavascript("window.__TMH_JOB=" + currentJob.toString() + ";\n" + agentJs, null);
                handler.postDelayed(injectProbe, 4000);
            });
        }
    };

    private static String chromeUa(String ua) {
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
        // v3: minimal bridge - the dashboard calls window.TeamMH.getFcmToken()
        // to register this device for push. Read-only, exposes nothing else.
        webView.addJavascriptInterface(new TeamMHBridge(), "TeamMH");

        webView.setWebChromeClient(new WebChromeClient() {
            // v3: chat image upload from gallery OR camera straight into the WebView.
            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;
                cameraUri = null;
                if (Build.VERSION.SDK_INT < 29
                        && ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                    ActivityCompat.requestPermissions(MainActivity.this, new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, RC_STORAGE_PERM);
                    return true;
                }
                launchFileChooser();
                return true;
            }

            // v3: voice notes - MediaRecorder inside the WebView needs RECORD_AUDIO.
            @Override
            public void onPermissionRequest(PermissionRequest request) {
                boolean ours = request.getOrigin() != null && ALLOWED_HOST.equals(request.getOrigin().getHost());
                boolean wantsMic = false;
                for (String r : request.getResources()) {
                    if (PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(r)) wantsMic = true;
                }
                if (!ours || !wantsMic) { request.deny(); return; }
                if (ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                    request.grant(new String[]{PermissionRequest.RESOURCE_AUDIO_CAPTURE});
                } else {
                    pendingMicRequest = request;
                    ActivityCompat.requestPermissions(MainActivity.this, new String[]{Manifest.permission.RECORD_AUDIO}, RC_MIC_PERM);
                }
            }

            // v3.1: site geolocation (rider live map / geo capture) needs the app-side grant too.
            @Override
            public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
                boolean ours = origin != null && origin.contains(ALLOWED_HOST);
                if (!ours) { callback.invoke(origin, false, false); return; }
                if (ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                        || ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                    callback.invoke(origin, true, false);
                } else {
                    pendingGeoOrigin = origin;
                    pendingGeoCallback = callback;
                    ActivityCompat.requestPermissions(MainActivity.this,
                            new String[]{Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION}, RC_GEO_PERM);
                }
            }

            @Override
            public void onGeolocationPermissionsHidePrompt() {
                pendingGeoOrigin = null;
                pendingGeoCallback = null;
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String host = uri.getHost();
                if (inAppHost(host)) {
                    return false;
                }
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
                return true;
            }

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler,
                    android.net.http.SslError error) {
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

        // v3: push plumbing - channel + token cache + Android 13 notification permission.
        FcmService.ensureChannel(this);
        FirebaseMessaging.getInstance().getToken().addOnSuccessListener(token ->
                getSharedPreferences(FcmService.PREFS, MODE_PRIVATE).edit().putString("token", token).apply());
        gateEntry();

        // v3: biometric gate before the dashboard loads (skipped when the device
        // has no enrolled biometric/credential - never locks anyone out).
        unlock();

        // Phone agent loop: only does anything when this device is logged in as admin
        // (the worker enforces that) and Google is signed in inside the app.
        handler.postDelayed(pollRunnable, 15000);

        // v3: in-app update check (restored from v1.4; v2 lost it).
        checkUpdate();
    }

    // v3.1 (Micheal, 26 Nov): permissions are mandatory. The app does not open until
    // notifications + mic + camera + location are all granted; if he permanently denied
    // one, the gate sends him to the app's system settings page instead of looping.
    private FrameLayout permView;

    private java.util.ArrayList<String> missingRequiredPerms() {
        java.util.ArrayList<String> want = new java.util.ArrayList<>();
        if (Build.VERSION.SDK_INT >= 33
                && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            want.add(Manifest.permission.POST_NOTIFICATIONS);
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED)
            want.add(Manifest.permission.RECORD_AUDIO);
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED)
            want.add(Manifest.permission.CAMERA);
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED)
            want.add(Manifest.permission.ACCESS_FINE_LOCATION);
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED)
            want.add(Manifest.permission.ACCESS_COARSE_LOCATION);
        return want;
    }

    private void gateEntry() {
        if (!missingRequiredPerms().isEmpty()) { showPermGate(); return; }
        if (permView != null) { permView.setVisibility(View.GONE); permView = null; }
        unlock();
    }

    private void showPermGate() {
        final java.util.ArrayList<String> missing = missingRequiredPerms();
        if (missing.isEmpty()) { gateEntry(); return; }
        // permanently denied = already asked and no rationale left -> only settings can fix it
        boolean permanentlyDenied = false;
        for (String perm : missing) {
            if (!ActivityCompat.shouldShowRequestPermissionRationale(this, perm)
                    && getSharedPreferences(FcmService.PREFS, MODE_PRIVATE).getBoolean("asked_perms_v1", false)) {
                permanentlyDenied = true;
                break;
            }
        }
        if (permView != null && permView.getParent() instanceof android.view.ViewGroup) {
            ((android.view.ViewGroup) permView.getParent()).removeView(permView);
        }
        permView = new FrameLayout(this);
        permView.setBackgroundColor(Color.parseColor("#0f172a"));
        TextView t = new TextView(this);
        t.setText("🔐 الأذونات مطلوبة");
        t.setTextColor(Color.WHITE);
        t.setTextSize(24);
        t.setGravity(Gravity.CENTER);
        FrameLayout.LayoutParams tp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT);
        tp.gravity = Gravity.CENTER;
        tp.bottomMargin = 300;
        TextView d = new TextView(this);
        d.setText("التطبيق محتاج الأذونات دي عشان يشتغل صح:\nالإشعارات والمايكروفون والكاميرا والموقع.\nمش هيشتغل من غيرها.");
        d.setTextColor(Color.parseColor("#cbd5e1"));
        d.setTextSize(16);
        d.setGravity(Gravity.CENTER);
        FrameLayout.LayoutParams dp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT);
        dp.gravity = Gravity.CENTER;
        dp.bottomMargin = 120;
        dp.leftMargin = 48; dp.rightMargin = 48;
        Button b = new Button(this);
        b.setText(permanentlyDenied ? "فتح إعدادات التطبيق" : "تفعيل الأذونات");
        b.setTextSize(18);
        FrameLayout.LayoutParams bp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT);
        bp.gravity = Gravity.CENTER;
        bp.topMargin = 120;
        permView.addView(t, tp);
        permView.addView(d, dp);
        permView.addView(b, bp);
        final boolean toSettings = permanentlyDenied;
        b.setOnClickListener(v -> {
            if (toSettings) {
                try {
                    startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                            Uri.parse("package:" + getPackageName())));
                } catch (Exception e) {
                    startActivity(new Intent(android.provider.Settings.ACTION_SETTINGS));
                }
            } else {
                getSharedPreferences(FcmService.PREFS, MODE_PRIVATE).edit().putBoolean("asked_perms_v1", true).apply();
                ActivityCompat.requestPermissions(this, missing.toArray(new String[0]), RC_STARTUP_PERMS);
            }
        });
        if (permView.getParent() == null) {
            addContentView(permView, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        }
        permView.setVisibility(View.VISIBLE);
        permView.bringToFront();
        // ask immediately on first launch, no need to wait for the button
        if (!permanentlyDenied
                && !getSharedPreferences(FcmService.PREFS, MODE_PRIVATE).getBoolean("asked_perms_v1", false)) {
            getSharedPreferences(FcmService.PREFS, MODE_PRIVATE).edit().putBoolean("asked_perms_v1", true).apply();
            ActivityCompat.requestPermissions(this, missing.toArray(new String[0]), RC_STARTUP_PERMS);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        // back from the system permission dialog or app settings: re-evaluate the gate
        if (permView != null && !unlocked) gateEntry();
    }

    // ---------------- biometric lock ----------------

    private void unlock() {
        if (unlocked) return;
        unlocked = true;
        webView.loadUrl(HOME_URL);
    }

    // ---------------- file chooser (gallery + camera) ----------------

    private void launchFileChooser() {
        try {
            Intent content = new Intent(Intent.ACTION_GET_CONTENT);
            content.addCategory(Intent.CATEGORY_OPENABLE);
            content.setType("image/*");
            Intent chooser = Intent.createChooser(content, "اختار صورة");
            try {
                ContentValues v = new ContentValues();
                v.put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg");
                v.put(MediaStore.Images.Media.DISPLAY_NAME, "tmh_" + System.currentTimeMillis() + ".jpg");
                cameraUri = getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, v);
                if (cameraUri != null) {
                    Intent cam = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
                    cam.putExtra(MediaStore.EXTRA_OUTPUT, cameraUri);
                    cam.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    chooser.putExtra(Intent.EXTRA_INITIAL_INTENTS, new Intent[]{cam});
                }
            } catch (Exception ignored) { cameraUri = null; }
            startActivityForResult(chooser, RC_FILE_CHOOSER);
        } catch (Exception e) {
            if (fileCallback != null) { fileCallback.onReceiveValue(null); fileCallback = null; }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == RC_FILE_CHOOSER) {
            Uri[] result = null;
            if (resultCode == RESULT_OK) {
                if (data != null && data.getData() != null) result = new Uri[]{data.getData()};
                else if (cameraUri != null) result = new Uri[]{cameraUri};
            }
            if (result == null && cameraUri != null) {
                try { getContentResolver().delete(cameraUri, null, null); } catch (Exception ignored) {}
            }
            if (fileCallback != null) { fileCallback.onReceiveValue(result); fileCallback = null; }
            cameraUri = null;
            return;
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        boolean granted = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
        if (requestCode == RC_MIC_PERM && pendingMicRequest != null) {
            if (granted) pendingMicRequest.grant(new String[]{PermissionRequest.RESOURCE_AUDIO_CAPTURE});
            else pendingMicRequest.deny();
            pendingMicRequest = null;
        } else if (requestCode == RC_STARTUP_PERMS) {
            gateEntry();
        } else if (requestCode == RC_GEO_PERM && pendingGeoCallback != null) {
            boolean anyLoc = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                    || ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
            pendingGeoCallback.invoke(pendingGeoOrigin, anyLoc, false);
            pendingGeoOrigin = null;
            pendingGeoCallback = null;
        } else if (requestCode == RC_STORAGE_PERM) {
            if (granted) launchFileChooser();
            else if (fileCallback != null) { fileCallback.onReceiveValue(null); fileCallback = null; }
        }
    }

    // ---------------- FCM bridge ----------------

    private class TeamMHBridge {
        @JavascriptInterface
        public String getFcmToken() {
            SharedPreferences p = getSharedPreferences(FcmService.PREFS, MODE_PRIVATE);
            String t = p.getString("token", "");
            return t == null ? "" : t;
        }

        @JavascriptInterface
        public int getAppVersion() {
            return BuildConfig.VERSION_CODE;
        }
    }

    // ---------------- in-app update ----------------

    private void checkUpdate() {
        net.execute(() -> {
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(HOME_URL + "app.version").openConnection();
                c.setConnectTimeout(10000);
                c.setReadTimeout(10000);
                String body = readStream(c.getInputStream()).trim();
                c.disconnect();
                int code = Integer.parseInt(body.split("\\s+")[0]);
                if (code > BuildConfig.VERSION_CODE) downloadUpdate();
            } catch (Exception ignored) {
            }
        });
    }

    private void downloadUpdate() {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(HOME_URL + "app.apk").openConnection();
            c.setConnectTimeout(15000);
            c.setReadTimeout(30000);
            File out = new File(getCacheDir(), "tmh-update.apk");
            InputStream in = c.getInputStream();
            FileOutputStream fos = new FileOutputStream(out);
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
            fos.close();
            in.close();
            c.disconnect();
            handler.post(() -> {
                try {
                    Uri uri = FileProvider.getUriForFile(MainActivity.this,
                            "com.michealyonan.teammh.fileprovider", out);
                    Intent i = new Intent(Intent.ACTION_VIEW);
                    i.setDataAndType(uri, "application/vnd.android.package-archive");
                    i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(i);
                } catch (Exception ignored) {
                }
            });
        } catch (Exception ignored) {
        }
    }

    // ---------------- phone agent internals (ported from v2, unchanged) ----------------

    private void pollOnce() {
        if (jobRunning || agentJs == null) return;
        if (System.currentTimeMillis() < authHoldUntil) return;
        if (!unlocked) return; // no token reads before the biometric gate opens
        webView.evaluateJavascript(
                "(function(){try{var t=sessionStorage.getItem('pd_token');if(t)return t;"
                        + "var s=JSON.parse(localStorage.getItem('pd_remember_login')||'null');"
                        + "if(s&&s.expires>Date.now())return s.t||'';return ''}catch(e){return ''}})()",
                value -> {
                    String token = null;
                    try {
                        if (value != null && value.length() >= 2) {
                            token = new org.json.JSONTokener(value).nextValue().toString();
                        }
                    } catch (Exception ignored) {
                    }
                    if (token == null || token.length() != 64 || "null".equals(token)) return;
                    pollWithToken(token);
                });
    }

    private void pollWithToken(final String token) {
        net.execute(new Runnable() {
            @Override public void run() {
                try {
                    HttpURLConnection c = (HttpURLConnection) new URL(HOME_URL + "api/forms/phone-poll").openConnection();
                    c.setRequestProperty("Authorization", "Bearer " + token);
                    c.setConnectTimeout(15000);
                    c.setReadTimeout(15000);
                    String body = readStream(c.getInputStream());
                    c.disconnect();
                    JSONObject resp = new JSONObject(body);
                    final JSONObject job = resp.optJSONObject("job");
                    if (job != null) {
                        jobRunning = true;
                        handler.post(new Runnable() {
                            @Override public void run() { runJob(job, token); }
                        });
                    }
                } catch (Exception ignored) {
                }
            }
        });
    }

    private void runJob(JSONObject job, String token) {
        currentJob = job;
        currentToken = token;
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
                    if (!jobRunning || currentJob == null) return;
                    v.evaluateJavascript("window.__TMH_JOB=" + currentJob.toString() + ";\n" + agentJs, null);
                }

                @Override
                public void onReceivedError(WebView view, WebResourceRequest request,
                        WebResourceError error) {
                    if (request.isForMainFrame() && jobRunning) {
                        finishJob("{\"error\":\"page_load_failed\",\"detail\":\"" + error.getErrorCode() + "\"}");
                    }
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
        handler.postDelayed(injectProbe, 5000);
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
        injected = false;
        handler.removeCallbacks(watchdog);
        handler.removeCallbacks(injectProbe);
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
                out.put("retry", true);
            }
            payload = out.toString();
        } catch (Exception e) {
            payload = "{\"id\":0,\"ok\":false,\"error\":\"report_parse\"}";
        }
        final String body = payload;
        final String token = currentToken;
        net.execute(new Runnable() {
            @Override public void run() {
                try {
                    HttpURLConnection c = (HttpURLConnection) new URL(HOME_URL + "api/forms/phone-report").openConnection();
                    c.setRequestMethod("POST");
                    c.setRequestProperty("Authorization", "Bearer " + token);
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
