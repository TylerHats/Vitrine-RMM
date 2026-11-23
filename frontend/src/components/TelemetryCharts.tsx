import React, { useState, useId } from 'react';
import { Activity } from 'lucide-react';

export interface TelemetryChartPoint {
  timestamp: string;
  primary: number;
  secondary?: number;
}

interface TelemetryChartCardProps {
  title: string;
  subtitle?: string;
  unit: string;
  range?: '1h' | '6h' | '24h' | '7d' | '30d' | string;
  points: TelemetryChartPoint[];
  primaryLabel: string;
  primaryColor: string;
  secondaryLabel?: string;
  secondaryColor?: string;
  minY?: number;
  maxY?: number;
  currentText?: string;
  avgText?: string;
  peakText?: string;
  height?: number;
  emptyMessage?: string;
  formatValue?: (val: number) => string;
}

function parseTelemetryDate(iso: string): Date | null {
  if (!iso) return null;
  const d = new Date(iso.includes('T') ? iso : iso.replace(' ', 'T') + 'Z');
  return Number.isNaN(d.getTime()) ? null : d;
}

function formatAxisTime(iso: string, range?: string, spanMs = 0, crossDay = false): string {
  if (!iso) return '';
  const d = parseTelemetryDate(iso);
  if (!d) return iso.slice(11, 16);
  if (range === '30d' || spanMs > 10 * 86400_000) {
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }
  if (range === '7d' || spanMs > 28 * 3600_000 || crossDay) {
    return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export const TelemetryChartCard: React.FC<TelemetryChartCardProps> = ({
  title,
  subtitle,
  unit,
  range,
  points,
  primaryLabel,
  primaryColor,
  secondaryLabel,
  secondaryColor,
  minY = 0,
  maxY,
  currentText,
  avgText,
  peakText,
  height = 200,
  emptyMessage = 'No recorded telemetry samples yet for this timeframe.',
  formatValue
}) => {
  const gradId = useId().replace(/:/g, '_');
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const svgWidth = 640;
  const svgHeight = height;
  const padLeft = unit.trim().length > 1 ? 54 : 46;
  const padRight = 14;
  const padTop = 14;
  const padBottom = 26;
  const plotW = svgWidth - padLeft - padRight;
  const plotH = svgHeight - padTop - padBottom;

  const firstDate = points.length > 0 ? parseTelemetryDate(points[0].timestamp) : null;
  const lastDate = points.length > 1 ? parseTelemetryDate(points[points.length - 1].timestamp) : null;
  const spanMs = firstDate && lastDate ? Math.max(0, lastDate.getTime() - firstDate.getTime()) : 0;
  const crossDay =
    Boolean(firstDate && lastDate) && firstDate!.toLocaleDateString() !== lastDate!.toLocaleDateString();

  const hasSecondary = Boolean(secondaryLabel && secondaryColor);
  const allVals: number[] = [];
  for (const p of points) {
    if (Number.isFinite(p.primary)) allVals.push(p.primary);
    if (hasSecondary && p.secondary != null && Number.isFinite(p.secondary)) {
      allVals.push(p.secondary);
    }
  }

  const rawMax = allVals.length > 0 ? Math.max(...allVals) : 100;
  const computedMaxY =
    maxY !== undefined
      ? maxY
      : rawMax <= 1
        ? 2
        : rawMax <= 10
          ? Math.ceil(rawMax * 1.25)
          : rawMax <= 100
            ? Math.min(100, Math.ceil(rawMax * 1.15))
            : Math.ceil(rawMax * 1.15);
  const yFloor = minY;
  const ySpan = Math.max(0.01, computedMaxY - yFloor);

  const fmtVal = (v: number) => (formatValue ? formatValue(v) : `${v.toFixed(v >= 10 ? 1 : 2)}${unit}`);

  const toX = (idx: number) => {
    if (points.length <= 1) return padLeft + plotW / 2;
    return padLeft + (idx / (points.length - 1)) * plotW;
  };
  const toY = (val: number) => {
    const clamped = Math.min(computedMaxY, Math.max(yFloor, val));
    return padTop + plotH - ((clamped - yFloor) / ySpan) * plotH;
  };

  const primaryCoords = points.map((p, i) => ({ x: toX(i), y: toY(p.primary) }));
  const primaryLinePath =
    primaryCoords.length === 0
      ? ''
      : primaryCoords.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`).join(' ');
  const primaryAreaPath =
    primaryCoords.length >= 2
      ? `${primaryLinePath} L ${primaryCoords[primaryCoords.length - 1].x.toFixed(1)} ${(padTop + plotH).toFixed(1)} L ${primaryCoords[0].x.toFixed(1)} ${(padTop + plotH).toFixed(1)} Z`
      : '';

  const secondaryCoords = hasSecondary
    ? points.map((p, i) => ({ x: toX(i), y: toY(p.secondary ?? 0) }))
    : [];
  const secondaryLinePath =
    secondaryCoords.length === 0
      ? ''
      : secondaryCoords.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`).join(' ');

  const hoveredPoint = hoverIdx != null && hoverIdx >= 0 && hoverIdx < points.length ? points[hoverIdx] : null;
  const gridTicks = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem', padding: '1.15rem 1.25rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <div style={{ fontSize: '0.96rem', fontWeight: 700, color: 'var(--text-main)' }}>{title}</div>
          {subtitle && <div style={{ fontSize: '0.73rem', color: 'var(--text-dim)', marginTop: '0.1rem' }}>{subtitle}</div>}
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center', fontSize: '0.72rem' }}>
          {currentText && (
            <span className="status-pill status-online" style={{ fontSize: '0.7rem' }}>
              Now: {currentText}
            </span>
          )}
          {avgText && (
            <span style={{ color: 'var(--text-muted)', padding: '0.15rem 0.45rem', borderRadius: '6px', background: 'rgba(148,163,184,0.08)' }}>
              Avg: <strong>{avgText}</strong>
            </span>
          )}
          {peakText && (
            <span style={{ color: 'var(--text-muted)', padding: '0.15rem 0.45rem', borderRadius: '6px', background: 'rgba(148,163,184,0.08)' }}>
              Peak: <strong>{peakText}</strong>
            </span>
          )}
        </div>
      </div>

      {points.length === 0 ? (
        <div
          style={{
            height: `${height}px`,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.4rem',
            borderRadius: '10px',
            background: 'var(--surface-panel)',
            border: '1px dashed var(--border-glass)',
            color: 'var(--text-dim)',
            fontSize: '0.8rem',
            padding: '1rem',
            textAlign: 'center'
          }}
        >
          <Activity size={20} style={{ opacity: 0.55 }} />
          <span>{emptyMessage}</span>
        </div>
      ) : (
        <div style={{ position: 'relative' }}>
          <svg
            viewBox={`0 0 ${svgWidth} ${svgHeight}`}
            style={{ width: '100%', height: `${height}px`, display: 'block', overflow: 'visible' }}
            onMouseLeave={() => setHoverIdx(null)}
            onMouseMove={(e) => {
              const rect = e.currentTarget.getBoundingClientRect();
              const relX = ((e.clientX - rect.left) / Math.max(1, rect.width)) * svgWidth;
              if (points.length === 1) {
                setHoverIdx(0);
                return;
              }
              const clamped = Math.min(padLeft + plotW, Math.max(padLeft, relX));
              const ratio = (clamped - padLeft) / Math.max(1, plotW);
              const idx = Math.round(ratio * (points.length - 1));
              setHoverIdx(Math.min(points.length - 1, Math.max(0, idx)));
            }}
          >
            <defs>
              <linearGradient id={`area-${gradId}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={primaryColor} stopOpacity="0.34" />
                <stop offset="100%" stopColor={primaryColor} stopOpacity="0.02" />
              </linearGradient>
            </defs>

            {gridTicks.map((t) => {
              const y = padTop + plotH - t * plotH;
              const val = yFloor + t * ySpan;
              return (
                <g key={t}>
                  <line
                    x1={padLeft}
                    y1={y}
                    x2={padLeft + plotW}
                    y2={y}
                    stroke="var(--border-glass)"
                    strokeDasharray={t === 0 ? undefined : '3 3'}
                    strokeWidth="1"
                  />
                  <text
                    x={padLeft - 6}
                    y={y + 3.5}
                    textAnchor="end"
                    fill="var(--text-muted)"
                    fontSize="10"
                  >
                    {val >= 10 || Number.isInteger(val) ? Math.round(val) : val.toFixed(1)}
                    {unit}
                  </text>
                </g>
              );
            })}

            {primaryAreaPath && <path d={primaryAreaPath} fill={`url(#area-${gradId})`} />}
            {primaryLinePath && (
              <path
                d={primaryLinePath}
                fill="none"
                stroke={primaryColor}
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            )}
            {secondaryLinePath && (
              <path
                d={secondaryLinePath}
                fill="none"
                stroke={secondaryColor}
                strokeWidth="2"
                strokeDasharray="4 2"
                strokeLinecap="round"
              />
            )}

            {points.length === 1 && primaryCoords[0] && (
              <circle cx={primaryCoords[0].x} cy={primaryCoords[0].y} r="4.5" fill={primaryColor} />
            )}

            {/* X-axis timestamp labels */}
            {points.length > 0 && (
              <>
                <text x={padLeft} y={svgHeight - 6} textAnchor="start" fill="var(--text-muted)" fontSize="10">
                  {formatAxisTime(points[0].timestamp, range, spanMs, crossDay)}
                </text>
                {points.length > 2 && (
                  <text
                    x={padLeft + plotW / 2}
                    y={svgHeight - 6}
                    textAnchor="middle"
                    fill="var(--text-muted)"
                    fontSize="10"
                  >
                    {formatAxisTime(points[Math.floor(points.length / 2)].timestamp, range, spanMs, crossDay)}
                  </text>
                )}
                {points.length > 1 && (
                  <text
                    x={padLeft + plotW}
                    y={svgHeight - 6}
                    textAnchor="end"
                    fill="var(--text-muted)"
                    fontSize="10"
                  >
                    {formatAxisTime(points[points.length - 1].timestamp, range, spanMs, crossDay)}
                  </text>
                )}
              </>
            )}

            {/* Interactive Hover Crosshair */}
            {hoverIdx !== null && primaryCoords[hoverIdx] && (
              <g>
                <line
                  x1={primaryCoords[hoverIdx].x}
                  y1={padTop}
                  x2={primaryCoords[hoverIdx].x}
                  y2={padTop + plotH}
                  stroke="var(--text-dim)"
                  strokeOpacity="0.6"
                  strokeWidth="1"
                />
                <circle
                  cx={primaryCoords[hoverIdx].x}
                  cy={primaryCoords[hoverIdx].y}
                  r="4.5"
                  fill={primaryColor}
                  stroke="var(--surface-base)"
                  strokeWidth="1.5"
                />
                {hasSecondary && secondaryCoords[hoverIdx] && (
                  <circle
                    cx={secondaryCoords[hoverIdx].x}
                    cy={secondaryCoords[hoverIdx].y}
                    r="4"
                    fill={secondaryColor}
                    stroke="var(--surface-base)"
                    strokeWidth="1.5"
                  />
                )}
              </g>
            )}
          </svg>

          {hoveredPoint && hoverIdx !== null && primaryCoords[hoverIdx] && (
            <div
              style={{
                position: 'absolute',
                top: '6px',
                right: '10px',
                background: 'var(--surface-elevated)',
                color: 'var(--text-main)',
                border: '1px solid var(--border-glass)',
                borderRadius: '8px',
                padding: '0.4rem 0.65rem',
                fontSize: '0.73rem',
                pointerEvents: 'none',
                boxShadow: '0 8px 20px rgba(0,0,0,0.4)'
              }}
            >
              <div style={{ color: 'var(--text-dim)', marginBottom: '0.15rem' }}>
                {new Date(
                  hoveredPoint.timestamp.includes('T')
                    ? hoveredPoint.timestamp
                    : hoveredPoint.timestamp.replace(' ', 'T') + 'Z'
                ).toLocaleString()}
              </div>
              <div style={{ color: primaryColor, fontWeight: 700 }}>
                {primaryLabel}: {fmtVal(hoveredPoint.primary)}
              </div>
              {hasSecondary && hoveredPoint.secondary != null && (
                <div style={{ color: secondaryColor, fontWeight: 700 }}>
                  {secondaryLabel}: {fmtVal(hoveredPoint.secondary)}
                </div>
              )}
            </div>
          )}

          {hasSecondary && (
            <div style={{ display: 'flex', gap: '1rem', fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ width: '10px', height: '3px', background: primaryColor, display: 'inline-block' }} />
                {primaryLabel}
              </span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ width: '10px', height: '3px', background: secondaryColor, display: 'inline-block' }} />
                {secondaryLabel}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

