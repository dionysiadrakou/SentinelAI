import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [token, setToken] = useState(sessionStorage.getItem("sentinelai_token"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [threatFilter, setThreatFilter] = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedIncident, setExpandedIncident] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [visibleSections, setVisibleSections] = useState({});

  //-------- Λειτουργία LOGIN ---------
  const handleLogin = async () => {
    try {
      // Στέλνουμε το username και το password
      // στο endpoint /login του FastAPI backend.
      const response = await fetch(
        "http://127.0.0.1:8000/login",
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
    }
  };


  //-------- Λειτουργία LOGOUT ---------
  const handleLogout = () => {
    // Διαγράφουμε το JWT token από το Local Storage.
      sessionStorage.removeItem("sentinelai_token");

    // Αφαιρούμε το token και από το React state.
    setToken(null);

    // Καθαρίζουμε τα δεδομένα του dashboard.
    setData(null);
  };


    //-------- Λειτουργία UPLOAD ---------
  const handleUpload = async () => {

    // Έλεγχος αν έχει επιλεχθέι αρχείο CSV πριν το upload 
    if (!selectedFile) {
      alert("Please select a CSV file first.");
      return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/upload",
        {
          method: "POST",

          headers: {
            // Στέλνουμε το JWT token μαζί με το upload request.
            Authorization: `Bearer ${token}`
          },

          body: formData
        }
      );

      // Παίρνουμε την απάντηση του backend σε JSON μορφή 
      const result = await response.json();

      // Ελέγχουμε αν το upload ηταν επιτυχές
      if (!response.ok) {
        throw new Error(
          result.detail || "Unable to upload and analyze the file."
        );
      }

      // Ενημερώνουμε τα δεδομένα του dashboard.
      setData((previousData) => ({
        ...previousData,
        total_events: result.total_events,
        total_incidents: result.total_incidents,
        suspicious_ips: result.suspicious_ips,
        events_over_time: result.events_over_time,
        incidents: result.incidents
      }));

      alert(result.message);

    } catch (error) {
        // Ελέγχουμε αν το backend είναι διαθέσιμο.
        if (error.message === "Failed to fetch") {
          alert(
            "Upload failed: Unable to connect to the SentinelAI server. Please make sure the backend is running."
          );
        } else {
          // Γενικό error message 
          alert("Upload failed: " + error.message);
        }
      }
  };


  // Φορτώνουμε τα δεδομένα του dashboard από το backend.
  useEffect(() => {
    // Αν δεν υπάρχει JWT token, δεν προσπαθούμε να καλέσουμε το protected endpoint.
    if (!token) {
      return;
    }

    fetch(
      "http://127.0.0.1:8000/analyze",
      {
        headers: {
          // Στέλνουμε το JWT token στο Authorization header.
          Authorization: `Bearer ${token}`
        }
      }
    )
      .then((response) => {

        // Αν το token είναι άκυρο ή έχει λήξει,
        // το backend επιστρέφει 401.
        if (!response.ok) {
          throw new Error("Failed to load dashboard data");
        }

        return response.json();
      })

      .then((result) => {
        // Αποθηκεύουμε τα δεδομένα του dashboard.
        setData(result);
      })

      .catch(() => {

        // Αν το frontend δεν μπορεί να επικοινωνήσει με το backend,
        // εμφανίζουμε μήνυμα σφάλματος.
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
        <h2>Unable to connect to SentinelAI backend</h2>
        <p>{error}</p>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="login-section">

        <h2>SentinelAI Login</h2>

        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />

        <button onClick={handleLogin}>
          Login
        </button>

      </div>
    );
  }

  if (!data) {
    return <div>Loading...</div>;
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
  const chartData = data.events_over_time;

  // Βρίσκουμε τη μέγιστη τιμή του γραφήματος.
  const maxCount = Math.max(
    ...chartData.map((item) => item.count)
  );

  // Διαστάσεις και περιθώρια του γραφήματος.
  const chartWidth = 900;
  const chartHeight = 280;
  const paddingLeft = 50;
  const paddingRight = 20;
  const paddingTop = 20;
  const paddingBottom = 40;

  // Υπολογίζουμε τον διαθέσιμο χώρο του γραφήματος.
  const usableWidth =
    chartWidth - paddingLeft - paddingRight;

  const usableHeight =
    chartHeight - paddingTop - paddingBottom;

  // Μετατρέπουμε τα δεδομένα σε σημεία του γραφήματος.
  const points = chartData.map((item, index) => {
    const x =
      paddingLeft +
      (index / (chartData.length - 1)) * usableWidth;

    const y =
      paddingTop +
      usableHeight -
      (item.count / maxCount) * usableHeight;

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
          onClick={handleLogout}
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
              onChange={(event) => setSelectedFile(event.target.files[0])}
            />

            <div className="upload-icon">
              ↑
            </div>

            <div className="upload-text">
              <strong>
                {selectedFile
                  ? selectedFile.name
                  : "Choose a security log file"}
              </strong>

              <span>
                {selectedFile
                  ? "File selected successfully"
                  : "CSV files only"}
              </span>
            </div>

            <span className="browse-button">
              Browse
            </span>
          </label>

          <button
            className="analyze-button"
            onClick={handleUpload}
          >
            Upload & Analyze
          </button>
        </div>
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
              preserveAspectRatio="none"
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
                x="5"
                y={paddingTop + 5}
                className="chart-label"
              >
                {maxCount}
              </text>

              <text
                x="5"
                y={paddingTop + usableHeight / 2 + 5}
                className="chart-label"
              >
                {Math.round(maxCount / 2)}
              </text>

              <text
                x="15"
                y={paddingTop + usableHeight + 5}
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
                    

                    {expandedIncident === incident.user && (
                      <div className="details">

                        <div className="details-title">
                          Incident Details
                        </div>

                        <div className="details-list">

                          {incident.details.map((detail, detailIndex) => (

                            <div className="detail-item" key={detailIndex}>

                              <strong>{detail.type}</strong>

                              {detail.attempts !== undefined && (
                                <p>Failed attempts: {detail.attempts}</p>
                              )}

                              {detail.failed_attempts !== undefined && (
                                <p>Failed attempts: {detail.failed_attempts}</p>
                              )}

                              {detail.users_targeted !== undefined && (
                                <p>Users targeted: {detail.users_targeted}</p>
                              )}

                              {detail.timestamp !== undefined && (
                                <p>Timestamp: {detail.timestamp}</p>
                              )}

                              {detail.events !== undefined && (
                                <p>Total events: {detail.events}</p>
                              )}

                              {detail.failed_logins !== undefined && (
                                <p>Failed logins: {detail.failed_logins}</p>
                              )}

                              {detail.successful_logins !== undefined && (
                                <p>Successful logins: {detail.successful_logins}</p>
                              )}

                              {detail.privilege_changes !== undefined && (
                                <p>Privilege changes: {detail.privilege_changes}</p>
                              )}

                              {detail.password_changes !== undefined && (
                                <p>Password changes: {detail.password_changes}</p>
                              )}

                              {detail.explanation !== undefined && (
                                <div className="detail-explanation">
                                  <div className="explanation-label">
                                    AI Explanation
                                  </div>

                                  <p>{detail.explanation}</p>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {/* Εμφανίζουμε προτεινόμενες ενέργειες αντιμετώπισης. */}
                    {expandedIncident === incident.user && (
                      <div className="recommended-actions">
                        <div className="recommended-actions-title">
                          Recommended Actions
                        </div>
                        <ul>
                          {incident.recommended_actions.map(
                            (action, actionIndex) => (
                              <li key={actionIndex}>
                                {action}
                              </li>
                            )
                          )}
                        </ul>
                      </div>
                    )}  
                  </div>
                );
              })
              
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;

