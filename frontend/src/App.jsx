import { useEffect, useState } from "react";

function App() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/analyze")
      .then((response) => response.json())
      .then((result) => setData(result))
      .catch((error) => console.error("Error:", error));
  }, []);

  return (
    <div>
      <h1>SentinelAI</h1>

      {!data ? (
        <p>Loading...</p>
      ) : (
        <div>
          <h2>Total Incidents: {data.total_incidents}</h2>

          {data.incidents.map((incident, index) => (
            <div key={index}>
              <h3>{incident.severity}</h3>

              <p>User: {incident.user}</p>
              <p>IP: {incident.ip}</p>
              <p>Risk Score: {incident.risk_score}/100</p>

              <p>Threats:</p>

              <ul>
                {incident.threats.map((threat, threatIndex) => (
                  <li key={threatIndex}>{threat}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default App;

