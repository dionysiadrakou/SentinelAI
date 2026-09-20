import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/analyze")
      .then((response) => response.json())
      .then((result) => setData(result))
      .catch((error) => console.error("Error:", error));
  }, []);

  if (!data) {
    return <p>Loading...</p>;
  }

  const incidents = data.incidents;

  const criticalCount = incidents.filter(
    (incident) => incident.severity === "CRITICAL"
  ).length;

  const highCount = incidents.filter(
    (incident) => incident.severity === "HIGH"
  ).length;

  const mediumCount = incidents.filter(
    (incident) => incident.severity === "MEDIUM"
  ).length;

  const suspiciousIPs = new Set(
    incidents.map((incident) => incident.ip)
  ).size;

  return (
    <div className="app">

      <header className="header">
        <h1>SentinelAI</h1>
        <p>AI-Powered Security Log Analyzer</p>
      </header>

      <main className="main">

        <section className="stats-grid">

          <div className="stat-card">
            <h3>Total Incidents</h3>
            <p>{data.total_incidents}</p>
          </div>

          <div className="stat-card">
            <h3>Critical Alerts</h3>
            <p>{criticalCount}</p>
          </div>

          <div className="stat-card">
            <h3>High Alerts</h3>
            <p>{highCount}</p>
          </div>

          <div className="stat-card">
            <h3>Suspicious IPs</h3>
            <p>{suspiciousIPs}</p>
          </div>

        </section>

        <section className="section">

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

        <section className="section">

          <h2>Recent Security Incidents</h2>

          <div className="incidents">

            {incidents.map((incident, index) => {

              const severityClass =
                incident.severity === "CRITICAL"
                  ? "severity-critical"
                  : incident.severity === "HIGH"
                  ? "severity-high"
                  : "severity-medium";

              return (
                <div className="incident" key={index}>

                  <div className="incident-header">

                    <strong>{incident.user}</strong>

                    <span className={`severity ${severityClass}`}>
                      {incident.severity}
                    </span>

                  </div>

                  <div className="incident-info">

                    <div>
                      <div className="info-label">IP Address</div>
                      <div className="info-value">
                        {incident.ip}
                      </div>
                    </div>

                    <div>
                      <div className="info-label">Risk Score</div>
                      <div className="info-value">
                        {incident.risk_score}/100
                      </div>
                    </div>

                    <div>
                      <div className="info-label">Threat Count</div>
                      <div className="info-value">
                        {incident.threats.length}
                      </div>
                    </div>

                  </div>

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
            })}

          </div>

        </section>

      </main>

    </div>
  );
}

export default App;
