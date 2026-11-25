package com.michealyonan.teammh;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

/**
 * Receives FCM pushes from the worker (chat messages, legal reminders, rider
 * status changes). The worker always sends notification+data on channel
 * teammh_alerts; when the app is in the foreground the system does NOT display
 * them, so we do. New tokens are cached for the WebView bridge to register.
 */
public class FcmService extends FirebaseMessagingService {

    static final String CHANNEL_ID = "teammh_alerts";
    static final String PREFS = "tmh_fcm";

    static void ensureChannel(Context ctx) {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null && nm.getNotificationChannel(CHANNEL_ID) == null) {
                NotificationChannel ch = new NotificationChannel(CHANNEL_ID, "تنبيهات Team MH", NotificationManager.IMPORTANCE_HIGH);
                ch.setDescription("رسايل الشات وتنبيهات المناديب والقانوني");
                nm.createNotificationChannel(ch);
            }
        }
    }

    @Override
    public void onNewToken(String token) {
        super.onNewToken(token);
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString("token", token).apply();
        // The dashboard WebView picks it up through window.TeamMH.getFcmToken()
        // and registers it at /api/push/register (site-side, already live).
    }

    @Override
    public void onMessageReceived(RemoteMessage msg) {
        // Foreground delivery: the tray won't show these, so post them ourselves.
        String title = null, body = null;
        if (msg.getNotification() != null) {
            title = msg.getNotification().getTitle();
            body = msg.getNotification().getBody();
        }
        if (title == null || title.isEmpty()) title = msg.getData().get("title");
        if (body == null || body.isEmpty()) body = msg.getData().get("body");
        if ((title == null || title.isEmpty()) && (body == null || body.isEmpty())) return;

        ensureChannel(this);
        Intent intent = new Intent(this, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pi = PendingIntent.getActivity(this, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        NotificationCompat.Builder b = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(title == null ? "Team MH" : title)
                .setContentText(body == null ? "" : body)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(pi);
        try {
            NotificationManagerCompat.from(this).notify((int) (System.currentTimeMillis() % 100000), b.build());
        } catch (SecurityException se) {
            // POST_NOTIFICATIONS not granted yet (Android 13+): nothing else we can do here.
        }
    }
}
