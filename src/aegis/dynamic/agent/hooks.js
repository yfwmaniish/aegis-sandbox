/*
 * Aegis Sandbox — Frida instrumentation for Android dynamic analysis.
 *
 * Injected into the target app on the detonation device. Each intercepted API emits a
 * single JSON object via send(); the Frida host writes them as newline-delimited JSON
 * (frida.jsonl), which aegis.dynamic.normalize.parse_frida_events() turns into the
 * canonical event stream. Every hook is wrapped so a missing class/method on a given
 * Android version disables only that hook, never the whole script.
 *
 * Usage (host side):
 *   frida -U -f <package> -l hooks.js --runtime=v8 -o /dev/stdout
 */
"use strict";

function emit(obj) {
  try {
    obj.ts = Date.now();
    send(obj);
  } catch (e) {}
}

function safe(name, fn) {
  try { fn(); } catch (e) { /* class/method absent on this API level */ }
}

Java.perform(function () {

  // --- SMS / OTP ---
  safe("SmsManager", function () {
    var Sms = Java.use("android.telephony.SmsManager");
    Sms.sendTextMessage.overload(
      "java.lang.String", "java.lang.String", "java.lang.String",
      "android.app.PendingIntent", "android.app.PendingIntent"
    ).implementation = function (dest, sc, body, a, b) {
      emit({ t: "sms", api: "SmsManager.sendTextMessage", dest: dest, body: body });
      return this.sendTextMessage(dest, sc, body, a, b);
    };
  });

  // --- Network: raw sockets ---
  safe("Socket", function () {
    var Socket = Java.use("java.net.Socket");
    Socket.connect.overload("java.net.SocketAddress", "int").implementation = function (addr, t) {
      emit({ t: "network", api: "Socket.connect", host: addr ? addr.toString() : null, protocol: "tcp" });
      return this.connect(addr, t);
    };
  });

  // --- Network: HTTP(S) via URL ---
  safe("URL", function () {
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {
      emit({ t: "http", api: "URL.openConnection", url: this.toString(), protocol: "http" });
      return this.openConnection();
    };
  });

  // --- Native command execution ---
  safe("Runtime.exec", function () {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
      emit({ t: "exec", api: "Runtime.exec", cmd: cmd });
      return this.exec(cmd);
    };
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (arr) {
      emit({ t: "exec", api: "Runtime.exec", cmd: arr ? arr.join(" ") : null });
      return this.exec(arr);
    };
  });

  // --- File writes (dropper artifacts) ---
  safe("FileOutputStream", function () {
    var FOS = Java.use("java.io.FileOutputStream");
    FOS.$init.overload("java.io.File").implementation = function (f) {
      emit({ t: "file", api: "FileOutputStream", path: f ? f.getAbsolutePath() : null, mode: "write" });
      return this.$init(f);
    };
  });

  // --- Dynamic code loading (stagers) ---
  ["dalvik.system.DexClassLoader", "dalvik.system.PathClassLoader", "dalvik.system.InMemoryDexClassLoader"].forEach(function (cls) {
    safe(cls, function () {
      var CL = Java.use(cls);
      CL.$init.overload("java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function (a, b, c) {
        emit({ t: "dex", api: cls.split(".").pop(), path: a });
        return this.$init(a, b, c);
      };
    });
  });

  // --- Telephony identifiers (IMEI / IMSI / SIM) ---
  safe("TelephonyManager", function () {
    var TM = Java.use("android.telephony.TelephonyManager");
    ["getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber", "getLine1Number"].forEach(function (m) {
      if (TM[m]) {
        try {
          TM[m].overload().implementation = function () {
            var v = this[m]();
            emit({ t: "telephony", api: "TelephonyManager." + m, value: v });
            return v;
          };
        } catch (e) {}
      }
    });
  });

  // --- Location ---
  safe("LocationManager", function () {
    var LM = Java.use("android.location.LocationManager");
    LM.getLastKnownLocation.implementation = function (provider) {
      emit({ t: "location", api: "getLastKnownLocation", provider: provider });
      return this.getLastKnownLocation(provider);
    };
  });

  // --- Microphone / recording ---
  safe("MediaRecorder", function () {
    var MR = Java.use("android.media.MediaRecorder");
    MR.start.implementation = function () {
      emit({ t: "media", api: "MediaRecorder.start", target: "microphone/camera" });
      return this.start();
    };
  });

  // --- Crypto (payload (de)cryption) ---
  safe("Cipher", function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (algo) {
      emit({ t: "crypto", api: "Cipher.getInstance", algo: algo });
      return this.getInstance(algo);
    };
  });

  emit({ t: "ipc", api: "aegis.hooks.installed", target: "instrumentation-ready" });
});
