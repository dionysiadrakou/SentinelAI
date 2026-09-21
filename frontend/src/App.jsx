import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [data, setData] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [threatFilter, setThreatFilter] = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedIncident, setExpandedIncident] = useState(null);

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

  const filteredIncidents = incidents.filter((incident) => {

    if (
      severityFilter !== "ALL" &&
      incident.severity !== severityFilter
    ) {
      return false;
    }

    if (
      threatFilter !== "ALL" &&
      !incident.threats.includes(threatFilter)
    ) {
      return false;
    }

    const search = searchTerm.toLowerCase();

    if (
      search &&
      !incident.user.toLowerCase().includes(search) &&
      !incident.ip.toLowerCase().includes(search)
    ) {
      return false;
    }

    return true;
  });

  const criticalCount = incidents.filter(
    (incident) => incident.severity === "CRITICAL"
  ).length;

  const highCount = incidents.filter(
    (incident) => incident.severity === "HIGH"
  ).length;

  const mediumCount = incidents.filter(
    (incident) => incident.severity === "MEDIUM"
  ).length;

  const chartData = data.events_over_time;

  const maxCount = Math.max(
    ...chartData.map((item) => item.count)
  );

  const chartWidth = 900;
  const chartHeight = 280;
  const paddingLeft = 50;
  const paddingRight = 20;
  const paddingTop = 20;
  const paddingBottom = 40;

  const usableWidth =
    chartWidth - paddingLeft - paddingRight;

  const usableHeight =
    chartHeight - paddingTop - paddingBottom;

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

  const linePoints = points
    .map((point) => `${point.x},${point.y}`)
    .join(" ");

  return (
    <div className="app">

      <header className="header">
        <h1>SentinelAI</h1>
        <p>AI-Powered Security Log Analyzer</p>
      </header>

      <main className="main">

        <section className="stats-grid">

          <div className="stat-card">
            <h3>Total Events</h3>
            <p>{data.total_events}</p>
          </div>

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
            <p>{data.suspicious_ips}</p>
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

          <h2>Events Over Time</h2>

          <div className="chart-container">

            <svg
              viewBox={`0 0 ${chartWidth} ${chartHeight}`}
              className="events-chart"
              preserveAspectRatio="none"
            >

              {/* Horizontal grid lines */}
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


              {/* Y-axis labels */}
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


              {/* Line */}
              <polyline
                points={linePoints}
                fill="none"
                className="chart-line"
              />


              {/* Data points */}
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
                // Εμφανίζουμε μόνο κάθε δεύτερη ώρα
                // ώστε ο άξονας να μην είναι φορτωμένος.
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


        <section className="section">

          <h2>Recent Security Incidents</h2>

          <div className="filters">
            {/* DropDown για Severity */}
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

            {/* DropDown για Threats*/}
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

            <input
              type="text"
              placeholder="Search user or IP..."
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
            />

          </div>

          <div className="incidents">

            {filteredIncidents.map((incident, index) => {

              const severityClass =
                incident.severity === "CRITICAL"
                  ? "severity-critical"
                  : incident.severity === "HIGH"
                  ? "severity-high"
                  : "severity-medium";

              return (  
                  <div
                    className="incident"
                    key={index}
                    onClick={() =>
                      setExpandedIncident(
                        expandedIncident === index ? null : index
                      )
                    }
                  >

                  <div className="incident-header">

                    <strong>{incident.user}</strong>

                    <span className={`severity ${severityClass}`}>
                      {incident.severity}
                    </span>

                  </div>

                  {expandedIncident === index && (
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
                          Threat Count
                        </div>

                        <div className="info-value">
                          {incident.threats.length}
                        </div>
                      </div>

                    </div>
                  )}

                  {expandedIncident === index && (
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
                  )}

                  {expandedIncident === index && (
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
                  
                  {/* Recommended Actions */}

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

