function HeaderHUD({ redScore, blueScore, round, totalRounds }) {
  const progress = Math.round((round / totalRounds) * 100);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "10px 18px",
        background: "#060b18",
        borderBottom: "1px solid #1e293b",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: "#EF4444",
              boxShadow: "0 0 6px #EF4444",
            }}
          />
          <span style={{ color: "#EF4444", fontSize: 11, letterSpacing: 1 }}>RED TEAM</span>
          <span
            style={{
              background: "#3d0a0a",
              color: "#EF4444",
              borderRadius: 4,
              padding: "2px 8px",
              fontSize: 12,
              fontWeight: 700,
              border: "1px solid #EF4444",
            }}
          >
            {redScore} pts
          </span>
        </div>

        <div
          style={{
            background: "#1e293b",
            border: "1px solid #334155",
            borderRadius: 6,
            padding: "3px 14px",
            color: "#94a3b8",
            fontSize: 11,
            letterSpacing: 2,
          }}
        >
          ROUND {round} / {totalRounds}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span
            style={{
              background: "#0a1f3d",
              color: "#3B82F6",
              borderRadius: 4,
              padding: "2px 8px",
              fontSize: 12,
              fontWeight: 700,
              border: "1px solid #3B82F6",
            }}
          >
            {blueScore} pts
          </span>
          <span style={{ color: "#3B82F6", fontSize: 11, letterSpacing: 1 }}>BLUE TEAM</span>
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: "#3B82F6",
              boxShadow: "0 0 6px #3B82F6",
            }}
          />
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div
          style={{
            width: 140,
            height: 4,
            background: "#1e293b",
            borderRadius: 2,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${progress}%`,
              height: "100%",
              background: "linear-gradient(90deg, #EF4444 0%, #7c3aed 50%, #3B82F6 100%)",
              borderRadius: 2,
            }}
          />
        </div>
        <span style={{ color: "#475569", fontSize: 10 }}>{progress}%</span>
      </div>
    </div>
  );
}

export default HeaderHUD;
