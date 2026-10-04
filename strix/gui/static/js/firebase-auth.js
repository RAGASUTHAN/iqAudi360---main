/**
 * iqAudi360 - Centralized Firebase Client Authentication Module
 * 
 * Provides unified, safe singleton initialization and error-safe wrappers
 * for Firebase Authentication across all pages.
 */

(function(window) {
  "use strict";

  let _firebaseApp = null;
  let _firebaseAuthInstance = null;
  let _isInitialized = false;

  const IqAuth = {
    /**
     * Initialize Firebase App and Auth instances.
     * Guaranteed to run in correct order without duplicate initialization or TDZ errors.
     * 
     * @param {Object} config - Public Firebase Web SDK configuration
     * @returns {Object|null} The initialized auth instance
     */
    init: function(config) {
      if (_isInitialized && _firebaseAuthInstance) {
        return _firebaseAuthInstance;
      }

      if (typeof firebase === "undefined") {
        console.error("[iqAudi360 Auth] Firebase SDK scripts not loaded.");
        return null;
      }

      try {
        if (!firebase.apps || firebase.apps.length === 0) {
          _firebaseApp = firebase.initializeApp(config);
        } else {
          _firebaseApp = firebase.app();
        }

        _firebaseAuthInstance = firebase.auth();
        _isInitialized = true;
        return _firebaseAuthInstance;
      } catch (err) {
        console.error("[iqAudi360 Auth] Initialization failed:", err);
        return null;
      }
    },

    /**
     * Get the active Firebase Auth instance safely.
     * 
     * @returns {Object} The Firebase Auth instance
     */
    getAuth: function() {
      if (!_firebaseAuthInstance) {
        if (typeof firebase !== "undefined" && firebase.apps && firebase.apps.length > 0) {
          _firebaseAuthInstance = firebase.auth();
          _isInitialized = true;
        } else if (window.__FIREBASE_CONFIG__) {
          this.init(window.__FIREBASE_CONFIG__);
        }
      }
      return _firebaseAuthInstance;
    },

    /**
     * Register a new user with Email and Password.
     * 
     * @param {string} email
     * @param {string} password
     * @param {string} displayName
     * @returns {Promise<{user: Object, idToken: string}>}
     */
    register: async function(email, password, displayName) {
      const auth = this.getAuth();
      if (!auth) {
        throw new Error("Authentication service is not initialized. Please refresh the page.");
      }

      // 1. Create account with Firebase Auth
      const userCredential = await auth.createUserWithEmailAndPassword(email, password);
      const user = userCredential.user;

      // 2. Update display name if provided
      if (displayName && user.updateProfile) {
        try {
          await user.updateProfile({ displayName: displayName });
        } catch (profileErr) {
          console.warn("[iqAudi360 Auth] Could not set display name:", profileErr);
        }
      }

      // 3. Obtain ID token
      const idToken = await user.getIdToken(true);

      // 4. Exchange token with iqAudi360 backend session
      const res = await fetch("/api/auth/session-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          idToken: idToken,
          displayName: displayName || user.displayName || email.split("@")[0]
        })
      });

      const data = await res.json();
      if (!res.ok || data.status !== "ok") {
        throw new Error(data.message || "Failed to establish platform session.");
      }

      return { user: user, session: data };
    },

    /**
     * Sign in with Email and Password.
     * 
     * @param {string} email
     * @param {string} password
     * @returns {Promise<{user: Object, session: Object}>}
     */
    login: async function(email, password) {
      const auth = this.getAuth();
      if (!auth) {
        throw new Error("Authentication service is not initialized. Please refresh the page.");
      }

      const userCredential = await auth.signInWithEmailAndPassword(email, password);
      const user = userCredential.user;
      const idToken = await user.getIdToken();

      const res = await fetch("/api/auth/session-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          idToken: idToken,
          displayName: user.displayName
        })
      });

      const data = await res.json();
      if (!res.ok || data.status !== "ok") {
        throw new Error(data.message || "Failed to establish platform session.");
      }

      return { user: user, session: data };
    },

    /**
     * Sign in with Google Popup.
     * 
     * @returns {Promise<{user: Object, session: Object}>}
     */
    loginWithGoogle: async function() {
      const auth = this.getAuth();
      if (!auth) {
        throw new Error("Authentication service is not initialized. Please refresh the page.");
      }

      const provider = new firebase.auth.GoogleAuthProvider();
      provider.addScope("email");
      provider.addScope("profile");

      const userCredential = await auth.signInWithPopup(provider);
      const user = userCredential.user;
      const idToken = await user.getIdToken();

      const res = await fetch("/api/auth/session-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          idToken: idToken,
          displayName: user.displayName
        })
      });

      const data = await res.json();
      if (!res.ok || data.status !== "ok") {
        throw new Error(data.message || "Failed to establish platform session.");
      }

      return { user: user, session: data };
    },

    /**
     * Send password reset email.
     * 
     * @param {string} email
     * @returns {Promise<void>}
     */
    resetPassword: async function(email) {
      const auth = this.getAuth();
      if (!auth) {
        throw new Error("Authentication service is not initialized. Please refresh the page.");
      }
      return await auth.sendPasswordResetEmail(email);
    },

    /**
     * Sign out user from both Firebase Auth and backend session.
     * 
     * @returns {Promise<void>}
     */
    logout: async function() {
      const auth = this.getAuth();
      if (auth) {
        try {
          await auth.signOut();
        } catch (e) {
          console.warn("[iqAudi360 Auth] Firebase signOut warning:", e);
        }
      }

      try {
        await fetch("/api/auth/session-logout", { method: "POST" });
      } catch (e) {
        console.warn("[iqAudi360 Auth] Session logout error:", e);
      }

      window.location.href = "/login";
    },

    /**
     * Map Firebase error codes to friendly human-readable messages.
     * 
     * @param {Error|Object} err
     * @returns {string}
     */
    formatErrorMessage: function(err) {
      if (!err) return "An unexpected error occurred.";
      const code = err.code || "";
      const msg = err.message || "";

      switch (code) {
        case "auth/email-already-in-use":
          return "An account with this email address already exists. Please log in instead.";
        case "auth/invalid-email":
          return "Please enter a valid email address.";
        case "auth/operation-not-allowed":
          return "Email/password authentication is not enabled in the Firebase project console.";
        case "auth/weak-password":
          return "Password is too weak. Please use at least 6 characters.";
        case "auth/user-disabled":
          return "This user account has been disabled by an administrator.";
        case "auth/user-not-found":
        case "auth/wrong-password":
        case "auth/invalid-credential":
          return "Invalid email or password. Please verify your credentials.";
        case "auth/popup-closed-by-user":
          return "Sign-in popup was closed before completing authentication.";
        case "auth/cancelled-popup-request":
          return "Popup authentication was cancelled.";
        case "auth/network-request-failed":
          return "Network connection failed. Please check your internet connection.";
        case "auth/too-many-requests":
          return "Access temporarily blocked due to many failed attempts. Try again later.";
        default:
          return msg || "Authentication request failed.";
      }
    }
  };

  // Expose IqAuth to window
  window.IqAuth = IqAuth;
})(window);
