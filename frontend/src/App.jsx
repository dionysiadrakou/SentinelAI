import { useEffect, useRef, useState } from "react";
import "./App.css";
import "./Login.css";

const API_BASE_URL = (
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [token, setToken] = useState(sessionStorage.getItem("sentinelai_token"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [threatFilter, setThreatFilter] = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedIncident, setExpandedIncident] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [visibleSections, setVisibleSections] = useState({});
  const [showRegister, setShowRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const inactivityTimer = useRef(null);
  const INACTIVITY_TIMEOUT = 30 * 60 * 1000;
  const [isUploading, setIsUploading] = useState(false);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
  const [uploadMessage, setUploadMessage] = useState(null);

  //-------- Λειτουργία LOGIN ---------
  const handleLogin = async () => {
    if (isLoggingIn) return;

    setIsLoggingIn(true);

    try {
      // Στέλνουμε το username και το password
      // στο endpoint /login του FastAPI backend.
      const response = await fetch(
        `${API_BASE_URL}/login`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          },

          body: new URLSearchParams({
            username: username,
            password: password
          })
        }
      );

      // Παίρνουμε την απάντηση του backend σε JSON.
      const result = await response.json();

      // Αν το login απέτυχε,
      // εμφανίζουμε το μήνυμα του backend.
      if (!response.ok) {
        throw new Error(
          result.detail || "Login failed"
        );
      }

      // Αποθηκεύουμε το JWT token που μας επέστρεψε το backend.
      setToken(result.access_token);

      sessionStorage.setItem(
        "sentinelai_token",
        result.access_token
      );

      // Καθαρίζουμε το password.
      setPassword("");

    } catch (error) {

      // Εμφανίζουμε μήνυμα σε περίπτωση αποτυχίας του login.
      alert("Login failed: " + error.message);
    } finally {
      setIsLoggingIn(false);
    }
  };

  //-------- Λειτουργία REGISTER ---------
  const handleRegister = async () => {
    if (isRegistering) {
      return;
    }

    if (password !== confirmPassword) {
      alert("Passwords do not match.");
      return;
    }

    setIsRegistering(true);

    try {
      const response = await fetch(
        `${API_BASE_URL}/register`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            username: username,
            email: email,
            password: password
          })
        }
      );

      const result = await response.json();

      if (!response.ok) {
        throw new Error(
          result.detail || "Registration failed"
        );
      }

      alert("Registration successful. You can now login.");

      setShowRegister(false);
      setPassword("");
      setConfirmPassword("");

    } catch (error) {
      alert("Registration failed: " + error.message);
    } finally {
      setIsRegistering(false);
    }
  };

  //-------- Λειτουργία LOGOUT ---------

  const handleLogout = () => {
    // Σταματάμε το timer αδράνειας.
    clearTimeout(inactivityTimer.current);

    // Διαγράφουμε τα αποθηκευμένα στοιχεία της συνεδρίας.
    sessionStorage.removeItem("sentinelai_token");
    sessionStorage.removeItem("sentinelai_uploaded_data");

    // Κλείνουμε το παράθυρο επιβεβαίωσης.
    setShowLogoutConfirm(false);

    // Καθαρίζουμε την κατάσταση της εφαρμογής.
    setToken(null);
    setData(null);
    setError(null);
    setSelectedFile(null);
    setExpandedIncident(null);
    setUploadMessage(null);
  };

  //-------- AUTO LOGOUT AFTER INACTIVITY ---------

  useEffect(() => {
    if (!token) {
      return;
    }

    const resetInactivityTimer = () => {
      clearTimeout(inactivityTimer.current);

      inactivityTimer.current = setTimeout(() => {
        handleLogout();
      }, INACTIVITY_TIMEOUT);
    };

    const activityEvents = [
      "mousemove",
      "mousedown",
      "keydown",
      "scroll",
      "touchstart",
      "click"
    ];

    activityEvents.forEach((event) => {
      window.addEventListener(event, resetInactivityTimer);
    });

    resetInactivityTimer();

    return () => {
      clearTimeout(inactivityTimer.current);

      activityEvents.forEach((event) => {
        window.removeEventListener(event, resetInactivityTimer);
      });
    };
  }, [token]);


  //-------- Λειτουργία UPLOAD ---------
  const handleUpload = async () => {
    if (isUploading) {
      return;
    }

    if (!selectedFile) {
      setUploadMessage({
        type: "error",
        text: "Please select a CSV file first."
      });
      return;
    }

    setIsUploading(true);
    setUploadMessage({
      type: "loading",
      text: "Uploading your CSV and analyzing security events..."
    });

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch(`${API_BASE_URL}/upload`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`
        },
        body: formData
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(
          result.detail || "Unable to upload and analyze the file."
        );
      }

      const uploadedData = {
        total_events: result.total_events,
        total_incidents: result.total_incidents,
        suspicious_ips: result.suspicious_ips,
        events_over_time: result.events_over_time,
        incidents: result.incidents
      };

      setData(uploadedData);

      sessionStorage.setItem(
        "sentinelai_uploaded_data",
        JSON.stringify(uploadedData)
      );

      setUploadMessage({
        type: "success",
        text: result.message || "CSV uploaded and analyzed successfully."
      });

    } catch (error) {
      const message =
        error.message === "Failed to fetch"
          ? "Unable to connect to the SentinelAI server. Please try again."
          : error.message;

      setUploadMessage({
        type: "error",
        text: `Upload failed: ${message}`
      });

    } finally {
      setIsUploading(false);
    }
  };



  // Φορτώνουμε τα δεδομένα του dashboard από το backend.
  useEffect(() => {
    // Αν δεν υπάρχει JWT token,
    // δεν προσπαθούμε να καλέσουμε protected endpoint.
    if (!token) {
      return;
    }

    // Ελέγχουμε αν υπάρχει uploaded dashboard state
    // από την τρέχουσα session.
    const savedUploadedData = sessionStorage.getItem(
      "sentinelai_uploaded_data"
    );

    if (savedUploadedData) {
      try {
        const parsedData = JSON.parse(savedUploadedData);

        // Επαναφέρουμε το τελευταίο uploaded αποτέλεσμα
        // αντί να φορτώσουμε ξανά τα default logs.
        setData(parsedData);

        return;
      } catch {
        // Αν το stored data είναι corrupted,
        // το διαγράφουμε και συνεχίζουμε με το default dataset.
        sessionStorage.removeItem("sentinelai_uploaded_data");
      }
    }

    // Αν δεν υπάρχει uploaded state,
    // φορτώνουμε τα default security logs από το backend.
    fetch(
      `${API_BASE_URL}/analyze`,
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    )
      .then((response) => {

        if (response.status === 401) {
          handleLogout();
          return null;
        }

        if (!response.ok) {
          throw new Error("Failed to load dashboard data");
        }

        return response.json();
      })

      .then((result) => {
        if (result) {
          setData(result);
        }
      })

      .catch(() => {
        setError(
          "Unable to connect to the SentinelAI server. Please make sure the backend is running."
        );
      });

  }, [token]);

  useEffect(() => {
    const elements = document.querySelectorAll(".reveal");

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
          } else {
            entry.target.classList.remove("visible");
          }
        });
      },
      {
        threshold: 0.15
      }
    );

    elements.forEach((element) => {
      observer.observe(element);
    });

    return () => {
      elements.forEach((element) => {
        observer.unobserve(element);
      });
    };
  }, [data]);

  if (error) {
    return (
      <div className="error-page">
   i     <h2>Unable to connect to SentinelAI backend</h2>
        <p>{error}</p>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="login-section">

        <div
          key={showRegister ? "register" : "login"}
          className="auth-form"
        >

          {showRegister ? (
            <>
              <h2>SentinelAI Register</h2>

              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
              />

              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />

              
              <div className="password-input-wrapper">
                <input
                  type={showPassword ? "text" : "password"}
                  placeholder="Password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />

                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M3 3l18 18" />
                      <path d="M10.6 10.6a2 2 0 0 0 2.8 2.8" />
                      <path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c5 0 8.5 4.5 9.5 7a11.8 11.8 0 0 1-2.1 3.2" />
                      <path d="M6.2 6.2C3.9 7.7 2.7 10 2.5 12c.5 1.3 1.5 3 3.5 4.7A9.8 9.8 0 0 0 12 19c1.1 0 2.1-.2 3-.5" />
                    </svg>
                  ) : (
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7Z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>

              <div className="password-input-wrapper">
                <input
                  type={showConfirmPassword ? "text" : "password"}
                  placeholder="Confirm Password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                />

                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  aria-label={
                    showConfirmPassword
                      ? "Hide password confirmation"
                      : "Show password confirmation"
                  }
                >
                  {showConfirmPassword ? (
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M3 3l18 18" />
                      <path d="M10.6 10.6a2 2 0 0 0 2.8 2.8" />
                      <path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c5 0 8.5 4.5 9.5 7a11.8 11.8 0 0 1-2.1 3.2" />
                      <path d="M6.2 6.2C3.9 7.7 2.7 10 2.5 12c.5 1.3 1.5 3 3.5 4.7A9.8 9.8 0 0 0 12 19c1.1 0 2.1-.2 3-.5" />
                    </svg>
                  ) : (
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7Z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>


              <button
                onClick={handleRegister}
                disabled={isRegistering}
              >
                {isRegistering ? "Creating account..." : "Register"}
              </button>

              {isRegistering && (
                <p className="auth-loading-message" role="status">
                  Creating your account. Please wait...
                </p>
              )}

              <p className="login-security-note auth-switch">
                Already have an account?{" "}
                <button
                  type="button"
                  className="auth-link"
                  onClick={() => setShowRegister(false)}
                >
                  Login
                </button>
              </p>

              <p className="login-security-note">
                Secure access to your SentinelAI dashboard
              </p>
            </>
          ) : (
            <>
              <h2>SentinelAI Login</h2>

              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
              />
              
              <div className="password-input-wrapper">
                <input
                  type={showPassword ? "text" : "password"}
                  placeholder="Password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />

                
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M3 3l18 18" />
                      <path d="M10.6 10.6a2 2 0 0 0 2.8 2.8" />
                      <path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c5 0 8.5 4.5 9.5 7a11.8 11.8 0 0 1-2.1 3.2" />
                      <path d="M6.2 6.2C3.9 7.7 2.7 10 2.5 12c.5 1.3 1.5 3 3.5 4.7A9.8 9.8 0 0 0 12 19c1.1 0 2.1-.2 3-.5" />
                    </svg>
                  ) : (
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7Z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>

              <button
                onClick={handleLogin}
                disabled={isLoggingIn}
              >
                {isLoggingIn ? "Logging in..." : "Login"}
              </button>

              {isLoggingIn && (
                <p className="auth-loading-message" role="status">
                  Connecting to SentinelAI. Please wait...
                </p>
              )}

              <p className="login-security-note auth-switch">
                Don't have an account?{" "}
                <button
                  type="button"
                  className="auth-link"
                  onClick={() => setShowRegister(true)}
                >
                  Register
                </button>
              </p>

              <p className="login-security-note">
                Secure access to your SentinelAI dashboard
              </p>
            </>
          )}

        </div>

      </div>
    );
  }

  if (!data) {
    return <div className="loading-screen">Loading...</div>;
  }

  const incidents = data.incidents;

  // Φιλτράρουμε τα incidents σύμφωνα με τα κριτήρια του χρήστη.
  const filteredIncidents = incidents.filter((incident) => {
    // Φιλτράρισμα βάσει severity.
    if (
      severityFilter !== "ALL" &&
      incident.severity !== severityFilter
    ) {
      return false;
    }

    // Φιλτράρισμα βάσει τύπου απειλής.
    if (
      threatFilter !== "ALL" &&
      !incident.threats.includes(threatFilter)
    ) {
      return false;
    }

    const search = searchTerm.toLowerCase();

    // Αναζήτηση βάσει username ή IP.
    if (
      search &&
      !incident.user.toLowerCase().includes(search) &&
      !incident.ip.toLowerCase().includes(search)
    ) {
      return false;
    }

    return true;
  });

  // Υπολογίζουμε τα incidents ανά severity.
  const criticalCount = incidents.filter(
    (incident) => incident.severity === "CRITICAL"
  ).length;

  const highCount = incidents.filter(
    (incident) => incident.severity === "HIGH"
  ).length;

  const mediumCount = incidents.filter(
    (incident) => incident.severity === "MEDIUM"
  ).length;


  // Παίρνουμε τα δεδομένα για το γράφημα.
  const chartData = data.events_over_time || [];

  // Διαστάσεις και περιθώρια του γραφήματος.
  const chartWidth = 900;
  const chartHeight = 280;

  const paddingLeft = 70;
  const paddingRight = 50;
  const paddingTop = 30;
  const paddingBottom = 55;

  // Υπολογίζουμε τον διαθέσιμο χώρο του γραφήματος.
  const usableWidth =
    chartWidth - paddingLeft - paddingRight;

  const usableHeight =
    chartHeight - paddingTop - paddingBottom;

  // Βρίσκουμε τη μέγιστη τιμή του γραφήματος.
  // Χρησιμοποιούμε τουλάχιστον 1 ώστε να μην υπάρχει
  // division by zero όταν όλες οι τιμές είναι 0.
  const maxCount = Math.max(
    ...chartData.map((item) => item.count),
    0
  );

  const chartScaleMax = Math.max(maxCount, 1);

  // Μετατρέπουμε τα δεδομένα σε σημεία του γραφήματος.
  const points = chartData.map((item, index) => {
    const x =
      chartData.length === 1
        ? paddingLeft + usableWidth / 2
        : paddingLeft +
          (index / (chartData.length - 1)) * usableWidth;

    const y =
      paddingTop +
      usableHeight -
      (item.count / chartScaleMax) * usableHeight;

    return {
      ...item,
      x,
      y,
    };
  });

  // Δημιουργούμε τα σημεία της γραμμής του γραφήματος.
  const linePoints = points
    .map((point) => `${point.x},${point.y}`)
    .join(" ");

  console.log("expandedIncident:", expandedIncident);

  return (
    <div className="app">

      <header className="top-header">
        <div className="brand">
          <div className="brand-text">
            <h1>SentinelAI</h1>
            <p>AI-Powered Security Log Analyzer</p>
          </div>
        </div>
        <button
          className="logout-button"
          onClick={() => setShowLogoutConfirm(true)}
        >
          Logout
        </button>
      </header>

      <div className="upload-section">
        <div className="upload-header">
          <div>
            <h2>Upload Security Logs</h2>
            <p>
              Upload a CSV file containing security logs to analyze potential threats
              and security incidents.
            </p>
          </div>
        </div>

        <div className="upload-content">
          <label className="file-upload">
            <input
              type="file"
              accept=".csv"
              onChange={(event) => {
                setSelectedFile(event.target.files[0] || null);
                setUploadMessage(null);
              }}
            />

            <div className="upload-icon">
              ↑
            </div>

            <div className="upload-text">
              <strong>
                {selectedFile ? selectedFile.name : "Choose a security log file"}
              </strong>
              <span>
                {selectedFile ? "File selected successfully" : "CSV files only"}
              </span>
              <span className="browse-button">Browse</span>
            </div>
          </label>

          <button
            className="analyze-button"
            onClick={handleUpload}
            disabled={isUploading}
          >
            {isUploading ? "Uploading & Analyzing..." : "Upload & Analyze"}
          </button>
        </div>

         {uploadMessage && (
            <p
              className={`upload-message ${uploadMessage.type}`}
              role="status"
              aria-live="polite"
            >
              {uploadMessage.text}
            </p>
          )}
      </div>

      <main className="main">

        <section className="stats-grid">

          <div className="stat-card stat-events">
            <div className="stat-top">
              <span className="stat-label">Total Events</span>
            </div>

            <div className="stat-value">
              {data.total_events}
            </div>

            <div className="stat-description">
              Security events analyzed
            </div>
          </div>


          <div className="stat-card stat-incidents">
            <div className="stat-top">
              <span className="stat-label">Total Incidents</span>
            </div>

            <div className="stat-value">
              {data.total_incidents}
            </div>

            <div className="stat-description">
              Detected security incidents
            </div>
          </div>


          <div className="stat-card stat-critical">
            <div className="stat-top">
              <span className="stat-label">Critical Alerts</span>
            </div>

            <div className="stat-value">
              {criticalCount}
            </div>

            <div className="stat-description">
              Critical severity incidents
            </div>
          </div>


          <div className="stat-card stat-high">
            <div className="stat-top">
              <span className="stat-label">High Alerts</span>
            </div>

            <div className="stat-value">
              {highCount}
            </div>

            <div className="stat-description">
              High severity incidents
            </div>
          </div>


          <div className="stat-card stat-ips">
            <div className="stat-top">
              <span className="stat-label">Suspicious IPs</span>
            </div>

            <div className="stat-value">
              {data.suspicious_ips}
            </div>

            <div className="stat-description">
              Potentially malicious sources
            </div>
          </div>

        </section>

        <section className="section reveal">

          <h2>Risk Overview</h2>

          <div className="risk-list">

            <div className="risk-item critical">
              <p>Critical</p>
              <strong>{criticalCount}</strong>
            </div>

            <div className="risk-item high">
              <p>High</p>
              <strong>{highCount}</strong>
            </div>

            <div className="risk-item medium">
              <p>Medium</p>
              <strong>{mediumCount}</strong>
            </div>

          </div>

        </section>


        <section className="section reveal">

          <h2>Events Over Time</h2>

          <div className="chart-container">

            {/* Δημιουργούμε το γράφημα με SVG. */}
            <svg
              viewBox={`0 0 ${chartWidth} ${chartHeight}`}
              className="events-chart"
              preserveAspectRatio="xMidYMid meet"
            >

              {/* Οριζόντιες γραμμές του grid. */}
              <line
                x1={paddingLeft}
                y1={paddingTop}
                x2={chartWidth - paddingRight}
                y2={paddingTop}
                className="chart-grid"
              />

              <line
                x1={paddingLeft}
                y1={paddingTop + usableHeight / 2}
                x2={chartWidth - paddingRight}
                y2={paddingTop + usableHeight / 2}
                className="chart-grid"
              />

              <line
                x1={paddingLeft}
                y1={paddingTop + usableHeight}
                x2={chartWidth - paddingRight}
                y2={paddingTop + usableHeight}
                className="chart-grid"
              />


              {/* Τιμές του άξονα Y. */}
              <text
                x={paddingLeft - 12}
                y={paddingTop + 5}
                textAnchor="end"
                className="chart-label"
              >
                {maxCount}
              </text>

              <text
                x={paddingLeft - 12}
                y={paddingTop + usableHeight / 2 + 5}
                textAnchor="end"
                className="chart-label"
              >
                {Math.round(maxCount / 2)}
              </text>

              <text
                x={paddingLeft - 12}
                y={paddingTop + usableHeight + 5}
                textAnchor="end"
                className="chart-label"
              >
                0
              </text>


              {/* Σχεδιάζουμε τη γραμμή του γραφήματος. */}
              <polyline
                points={linePoints}
                fill="none"
                className="chart-line"
              />


              {/* Σχεδιάζουμε τα σημεία των δεδομένων. */}
              {points.map((point) => (
                <circle
                  key={point.time}
                  cx={point.x}
                  cy={point.y}
                  r="4"
                  className="chart-point"
                />
              ))}

              {points.map((point, index) => {
                // Εμφανίζουμε μόνο κάθε δεύτερη ώρα στον άξονα X.
                if (index % 2 !== 0) {
                  return null;
                }

                return (
                  <text
                    key={`${point.time}-label`}
                    x={point.x}
                    y={chartHeight - 10}
                    textAnchor="middle"
                    className="chart-label"
                  >
                    {point.time}
                  </text>
                );
              })}

            </svg>

          </div>

        </section>


        <section className="section reveal">

          <h2>Recent Security Incidents</h2>

          <div className="filters">
            {/* Φιλτράρισμα βάσει severity. */}
            <select
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Φιλτράρισμα βάσει τύπου απειλής. */}
            <select
              value={threatFilter}
              onChange={(event) => setThreatFilter(event.target.value)}
            >
              <option value="ALL">All Threat Types</option>
              <option value="Brute Force">Brute Force</option>
              <option value="Suspicious IP Activity">
                Suspicious IP Activity
              </option>
              <option value="Unusual Login">Unusual Login</option>
              <option value="Privilege Escalation">
                Privilege Escalation
              </option>
              <option value="ML Anomaly">ML Anomaly</option>
            </select>

            {/* Αναζήτηση βάσει username ή IP. */}
            <input
              type="text"
              placeholder="Search user or IP..."
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
            />

          </div>

          <div className="incident-count">
            Showing {filteredIncidents.length} of {incidents.length} incidents
          </div>

          <div className="incidents">
            {filteredIncidents.length === 0 ? (
              <p className="no-incidents">
                No incidents match the selected filters.
              </p>
            ) : (
              filteredIncidents.map((incident, index) => {

                // Επιλέγουμε CSS class ανάλογα με το severity.
                const severityClass =
                  incident.severity === "CRITICAL"
                    ? "severity-critical"
                    : incident.severity === "HIGH"
                    ? "severity-high"
                    : incident.severity === "MEDIUM"
                    ? "severity-medium"
                    : "severity-low";

                return (
                    <div
                      className={`incident ${severityClass}`}
                      key={index}
                      onClick={() =>
                        setExpandedIncident(
                          expandedIncident === incident.user ? null : incident.user
                        )
                      }
                    >

                    <div className="incident-header">

                      <strong>{incident.user}</strong>

                      <span className={`severity ${severityClass}`}>
                        {incident.severity}
                      </span>

                    </div>

                    {/* Εμφανίζουμε επιπλέον πληροφορίες όταν ανοίγει το incident. */}
                    <div className="incident-info">
                      <div>
                        <div className="info-label">
                          IP Address
                        </div>

                        <div className="info-value">
                          {incident.ip}
                        </div>
                      </div>

                      <div>
                        <div className="info-label">
                          Risk Score
                        </div>

                        <div className="info-value">
                          {incident.risk_score}/100
                        </div>
                      </div>

                      <div>
                        <div className="info-label">
                          Threat Count</div>

                        <div className="info-value">
                          {incident.threats.length}
                        </div>
                      </div>

                    </div>


                    {/* Εμφανίζουμε τις απειλές του incident. */}
                    <div className="threats">
                      <div className="threats-title">
                        Detected Threats
                      </div>
                      <div className="threat-list">

                        {incident.threats.map(
                          (threat, threatIndex) => (
                            <span
                              className="threat"
                               key={threatIndex}
                             >
                               {threat}
                             </span>
                          )
                         )}

                      </div>

                    </div>
                  </div>
                );
              })

            )}
          </div>
        </section>
      </main>


      {expandedIncident && (() => {
        const selectedIncident = incidents.find(
          (incident) => incident.user === expandedIncident
        );

        if (!selectedIncident) {
          return null;
        }

        console.log("selectedIncident:", selectedIncident);

        return (
          <div className="modal-overlay">
            <div className="incident-modal">

              <button
                className="modal-close"
                onClick={() => setExpandedIncident(null)}
                aria-label="Close"
              >
                ×
              </button>

              <div className="modal-header">
                <div>
                  <h2>{selectedIncident.user}</h2>
                  <span
                    className={`severity severity-${selectedIncident.severity.toLowerCase()}`}
                  >
                    {selectedIncident.severity}
                  </span>
                </div>
              </div>

              <div className="modal-info">
                <div>
                  <div className="info-label">IP Address</div>
                  <div className="info-value">
                    {selectedIncident.ip}
                  </div>
                </div>

                <div>
                  <div className="info-label">Risk Score</div>
                  <div className="info-value">
                    {selectedIncident.risk_score}/100
                  </div>
                </div>

                <div>
                  <div className="info-label">Threat Count</div>
                  <div className="info-value">
                    {selectedIncident.threats.length}
                  </div>
                </div>
              </div>

              <div className="modal-section">
                <div className="modal-section-title">
                  Detected Threats
                </div>

                <div className="threat-list">
                  {selectedIncident.threats.map(
                    (threat, threatIndex) => (
                      <span
                        className="threat"
                        key={threatIndex}
                      >
                        {threat}
                      </span>
                    )
                  )}
                </div>
              </div>

              <div className="details">
                <div className="details-title">
                  Incident Details
                </div>

                <div className="details-list">
                  {selectedIncident.details.map(
                    (detail, detailIndex) => (
                      <div
                        className="detail-item"
                        key={detailIndex}
                      >
                        <strong>{detail.type}</strong>

                        {detail.attempts !== undefined && (
                          <p>
                            Failed attempts: {detail.attempts}
                          </p>
                        )}

                        {detail.failed_attempts !== undefined && (
                          <p>
                            Failed attempts: {detail.failed_attempts}
                          </p>
                        )}

                        {detail.users_targeted !== undefined && (
                          <p>
                            Users targeted: {detail.users_targeted}
                          </p>
                        )}

                        {detail.timestamp !== undefined && (
                          <p>
                            Timestamp: {detail.timestamp}
                          </p>
                        )}

                        {detail.events !== undefined && (
                          <p>
                            Total events: {detail.events}
                          </p>
                        )}

                        {detail.failed_logins !== undefined && (
                          <p>
                            Failed logins: {detail.failed_logins}
                          </p>
                        )}

                        {detail.successful_logins !== undefined && (
                          <p>
                            Successful logins: {detail.successful_logins}
                          </p>
                        )}

                        {detail.privilege_changes !== undefined && (
                          <p>
                            Privilege changes: {detail.privilege_changes}
                          </p>
                        )}

                        {detail.password_changes !== undefined && (
                          <p>
                            Password changes: {detail.password_changes}
                          </p>
                        )}

                        {detail.explanation !== undefined && (
                          <div className="detail-explanation">
                            <div className="explanation-label">
                              AI Explanation
                            </div>

                            <p>
                              {detail.explanation}
                            </p>
                          </div>
                        )}
                      </div>
                    )
                  )}
                </div>
              </div>

              <div className="recommended-actions">
                <div className="recommended-actions-title">
                  Recommended Actions
                </div>

                <ul>
                  {selectedIncident.recommended_actions.map(
                    (action, actionIndex) => (
                      <li key={actionIndex}>
                        {action}
                      </li>
                    )
                  )}
                </ul>
              </div>

            </div>
          </div>
        );
      })()}

      {showLogoutConfirm && (
        <div
          className="logout-confirm-overlay"
          onClick={(event) => {
            if (event.target === event.currentTarget) {
              setShowLogoutConfirm(false);
            }
          }}
        >
          <div
            className="logout-confirm-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="logout-confirm-title"
            aria-describedby="logout-confirm-description"
          >
            <div className="logout-confirm-heading">
              <div className="logout-confirm-text">
                <h2 id="logout-confirm-title">
                  Log out of SentinelAI?
                </h2>

                <p id="logout-confirm-description">
                  Are you sure you want to log out?
                  Your current dashboard view will be cleared
                  from this browser session.
                </p>
              </div>
            </div>

            <div className="logout-confirm-actions">
              <button
                type="button"
                className="logout-cancel-button"
                onClick={() => setShowLogoutConfirm(false)}
              >
                Cancel
              </button>

              <button
                type="button"
                className="logout-confirm-button"
                onClick={handleLogout}
              >
                Log out
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;

