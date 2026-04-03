export default function ThreatBadge({ category, verdict }) {
  const verdictClass = verdict === 'BLOCK' ? 'badge-block' : 'badge-pass';

  return (
    <span className="threat-badge-group">
      <span className={`badge ${verdictClass}`}>
        {verdict === 'BLOCK' ? '✕' : '✓'} {verdict}
      </span>
      {category && category !== 'safe' && (
        <span className="badge badge-category">{category.replace(/_/g, ' ')}</span>
      )}
    </span>
  );
}
