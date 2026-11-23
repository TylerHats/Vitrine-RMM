import React, { useEffect, useRef, useState } from 'react';
import { Crop, RotateCcw, Check, X } from 'lucide-react';

export interface IconCropModalProps {
  isOpen: boolean;
  file: File | null;
  title?: string;
  onCancel: () => void;
  onConfirm: (result: { filename: string; base64Data: string; previewDataUrl: string }) => void;
}

type FitMode = 'contain' | 'cover';
type BgMode = 'transparent' | 'dark' | 'white' | 'custom';

function drawRoundedRectPath(ctx: CanvasRenderingContext2D, size: number, radiusPx: number): void {
  const r = Math.max(0, Math.min(size / 2, radiusPx));
  ctx.beginPath();
  if (r === 0) {
    ctx.rect(0, 0, size, size);
    return;
  }
  ctx.moveTo(r, 0);
  ctx.lineTo(size - r, 0);
  ctx.quadraticCurveTo(size, 0, size, r);
  ctx.lineTo(size, size - r);
  ctx.quadraticCurveTo(size, size, size - r, size);
  ctx.lineTo(r, size);
  ctx.quadraticCurveTo(0, size, 0, size - r);
  ctx.lineTo(0, r);
  ctx.quadraticCurveTo(0, 0, r, 0);
  ctx.closePath();
}

function renderCroppedSquare(
  ctx: CanvasRenderingContext2D,
  size: number,
  img: HTMLImageElement,
  opts: {
    fit: FitMode;
    zoom: number;
    panX: number;
    panY: number;
    paddingPct: number;
    bgMode: BgMode;
    bgColor: string;
    radiusPct: number;
  }
): void {
  ctx.clearRect(0, 0, size, size);
  ctx.save();

  const radiusPx = (opts.radiusPct / 100) * (size / 2);
  drawRoundedRectPath(ctx, size, radiusPx);
  ctx.clip();

  if (opts.bgMode === 'dark') {
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(0, 0, size, size);
  } else if (opts.bgMode === 'white') {
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
  } else if (opts.bgMode === 'custom') {
    ctx.fillStyle = /^#[0-9a-fA-F]{6}$/.test(opts.bgColor) ? opts.bgColor : '#0f172a';
    ctx.fillRect(0, 0, size, size);
  }

  const nw = img.naturalWidth || 1;
  const nh = img.naturalHeight || 1;
  const pad = (opts.paddingPct / 100) * (size / 2);
  const inner = Math.max(4, size - pad * 2);
  const baseScale = opts.fit === 'cover' ? Math.max(inner / nw, inner / nh) : Math.min(inner / nw, inner / nh);
  const scale = baseScale * opts.zoom;
  const dw = nw * scale;
  const dh = nh * scale;
  const ratio = size / 240;
  const dx = (size - dw) / 2 + opts.panX * ratio;
  const dy = (size - dh) / 2 + opts.panY * ratio;

  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(img, dx, dy, dw, dh);
  ctx.restore();
}

export const IconCropModal: React.FC<IconCropModalProps> = ({
  isOpen,
  file,
  title = 'Crop & Prepare Square Icon (256x256 PNG)',
  onCancel,
  onConfirm
}) => {
  const editorCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const dragStateRef = useRef<{ dragging: boolean; startX: number; startY: number; origPanX: number; origPanY: number }>({
    dragging: false,
    startX: 0,
    startY: 0,
    origPanX: 0,
    origPanY: 0
  });

  const [loadedImg, setLoadedImg] = useState<HTMLImageElement | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [fit, setFit] = useState<FitMode>('contain');
  const [zoom, setZoom] = useState<number>(1);
  const [panX, setPanX] = useState<number>(0);
  const [panY, setPanY] = useState<number>(0);
  const [paddingPct, setPaddingPct] = useState<number>(4);
  const [bgMode, setBgMode] = useState<BgMode>('transparent');
  const [bgColor, setBgColor] = useState<string>('#0f172a');
  const [radiusPct, setRadiusPct] = useState<number>(0);
  const [previewUrl, setPreviewUrl] = useState<string>('');

  useEffect(() => {
    if (!isOpen || !file) {
      setLoadedImg(null);
      setLoadError(null);
      setPreviewUrl('');
      return;
    }

    setLoadError(null);
    setFit('contain');
    setZoom(1);
    setPanX(0);
    setPanY(0);
    setPaddingPct(4);
    setBgMode('transparent');
    setRadiusPct(0);

    const objUrl = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      setLoadedImg(img);
    };
    img.onerror = () => {
      setLoadError('Unable to decode selected image file. Please choose a valid PNG, JPEG, WebP, or ICO image.');
    };
    img.src = objUrl;

    return () => {
      URL.revokeObjectURL(objUrl);
    };
  }, [isOpen, file]);

  useEffect(() => {
    if (!isOpen || !loadedImg || !editorCanvasRef.current) return;
    const opts = { fit, zoom, panX, panY, paddingPct, bgMode, bgColor, radiusPct };

    const edCtx = editorCanvasRef.current.getContext('2d');
    if (edCtx) {
      renderCroppedSquare(edCtx, 240, loadedImg, opts);
    }

    const outCanvas = document.createElement('canvas');
    outCanvas.width = 256;
    outCanvas.height = 256;
    const outCtx = outCanvas.getContext('2d');
    if (outCtx) {
      renderCroppedSquare(outCtx, 256, loadedImg, opts);
      setPreviewUrl(outCanvas.toDataURL('image/png'));
    }
  }, [isOpen, loadedImg, fit, zoom, panX, panY, paddingPct, bgMode, bgColor, radiusPct]);

  if (!isOpen || !file) return null;

  const handleReset = () => {
    setFit('contain');
    setZoom(1);
    setPanX(0);
    setPanY(0);
    setPaddingPct(4);
    setBgMode('transparent');
    setRadiusPct(0);
  };

  const handleConfirm = () => {
    if (!loadedImg) return;
    const outCanvas = document.createElement('canvas');
    outCanvas.width = 256;
    outCanvas.height = 256;
    const outCtx = outCanvas.getContext('2d');
    if (!outCtx) return;
    renderCroppedSquare(outCtx, 256, loadedImg, {
      fit,
      zoom,
      panX,
      panY,
      paddingPct,
      bgMode,
      bgColor,
      radiusPct
    });
    const dataUrl = outCanvas.toDataURL('image/png');
    const base64Data = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
    const baseName = file.name.replace(/\.[^.]+$/, '') || 'icon';
    onConfirm({
      filename: `${baseName}.png`,
      base64Data,
      previewDataUrl: dataUrl
    });
  };

  const handlePointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    dragStateRef.current = {
      dragging: true,
      startX: e.clientX,
      startY: e.clientY,
      origPanX: panX,
      origPanY: panY
    };
  };

  const handlePointerMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!dragStateRef.current.dragging) return;
    const dx = e.clientX - dragStateRef.current.startX;
    const dy = e.clientY - dragStateRef.current.startY;
    setPanX(Math.max(-160, Math.min(160, dragStateRef.current.origPanX + dx)));
    setPanY(Math.max(-160, Math.min(160, dragStateRef.current.origPanY + dy)));
  };

  const handlePointerUp = () => {
    dragStateRef.current.dragging = false;
  };

  return (
    <div className="modal-backdrop" id="icon-crop-modal" style={{ zIndex: 1200 }} onClick={onCancel}>
      <div
        className="glass-modal"
        style={{ maxWidth: '680px', width: '95vw' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div className="modal-title">
            <Crop size={18} style={{ color: 'var(--primary)' }} />
            <span>{title}</span>
          </div>
          <button type="button" className="btn-glass btn-icon" onClick={onCancel} title="Cancel">
            <X size={18} />
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {loadError ? (
            <div
              style={{
                padding: '0.85rem 1rem',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.14)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                color: '#f87171',
                fontSize: '0.82rem'
              }}
            >
              {loadError}
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: '250px 1fr', gap: '1.25rem', alignItems: 'start' }}>
              {/* Left: Interactive 240x240 Square Crop Canvas */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', alignItems: 'center' }}>
                <div
                  style={{
                    position: 'relative',
                    width: '240px',
                    height: '240px',
                    borderRadius: '8px',
                    overflow: 'hidden',
                    border: '1px solid var(--glass-border)',
                    backgroundImage:
                      'linear-gradient(45deg, rgba(148,163,184,0.18) 25%, transparent 25%), linear-gradient(-45deg, rgba(148,163,184,0.18) 25%, transparent 25%), linear-gradient(45deg, transparent 75%, rgba(148,163,184,0.18) 75%), linear-gradient(-45deg, transparent 75%, rgba(148,163,184,0.18) 75%)',
                    backgroundSize: '16px 16px',
                    backgroundPosition: '0 0, 0 8px, 8px -8px, -8px 0'
                  }}
                >
                  <canvas
                    ref={editorCanvasRef}
                    width={240}
                    height={240}
                    onPointerDown={handlePointerDown}
                    onPointerMove={handlePointerMove}
                    onPointerUp={handlePointerUp}
                    onPointerCancel={handlePointerUp}
                    style={{ width: '240px', height: '240px', cursor: 'grab', display: 'block', touchAction: 'none' }}
                    title="Drag to reposition icon inside square frame"
                  />
                  {/* Rule-of-thirds overlay */}
                  <div
                    style={{
                      position: 'absolute',
                      inset: 0,
                      pointerEvents: 'none',
                      border: '1px dashed rgba(0, 242, 254, 0.35)'
                    }}
                  />
                </div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textAlign: 'center' }}>
                  Drag inside frame to pan • Source:{' '}
                  {loadedImg ? `${loadedImg.naturalWidth}×${loadedImg.naturalHeight}px` : '...'}
                </span>

                {/* Multi-size Windows Icon Preview Strip */}
                {previewUrl && (
                  <div
                    style={{
                      width: '100%',
                      padding: '0.55rem 0.65rem',
                      borderRadius: '8px',
                      background: 'rgba(15, 23, 42, 0.55)',
                      border: '1px solid var(--glass-border)'
                    }}
                  >
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginBottom: '0.4rem', fontWeight: 600 }}>
                      Windows Icon Preview (Tray / EXE / Web)
                    </div>
                    <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: '0.5rem' }}>
                      {[
                        { px: 16, label: '16px Tray' },
                        { px: 32, label: '32px Bar' },
                        { px: 48, label: '48px EXE' },
                        { px: 64, label: '64px UI' }
                      ].map((sz) => (
                        <div key={sz.px} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.2rem' }}>
                          <img
                            src={previewUrl}
                            alt={sz.label}
                            style={{ width: `${sz.px}px`, height: `${sz.px}px`, objectFit: 'contain' }}
                          />
                          <span style={{ fontSize: '0.62rem', color: 'var(--text-muted)' }}>{sz.label}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Right: Controls */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
                <div>
                  <label style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Framing Mode
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                    <button
                      type="button"
                      className={`btn-glass ${fit === 'contain' ? 'btn-primary' : ''}`}
                      style={{ justifyContent: 'center', fontSize: '0.78rem' }}
                      onClick={() => setFit('contain')}
                    >
                      Fit Inside Square
                    </button>
                    <button
                      type="button"
                      className={`btn-glass ${fit === 'cover' ? 'btn-primary' : ''}`}
                      style={{ justifyContent: 'center', fontSize: '0.78rem' }}
                      onClick={() => setFit('cover')}
                    >
                      Fill Square (Cover)
                    </button>
                  </div>
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.76rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-dim)' }}>Zoom</span>
                    <span style={{ color: 'var(--primary)' }}>{zoom.toFixed(2)}×</span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={3}
                    step={0.05}
                    value={zoom}
                    onChange={(e) => setZoom(Number(e.target.value))}
                    style={{ width: '100%' }}
                  />
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.76rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-dim)' }}>Inset Padding</span>
                    <span style={{ color: 'var(--primary)' }}>{paddingPct}%</span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={24}
                    step={1}
                    value={paddingPct}
                    onChange={(e) => setPaddingPct(Number(e.target.value))}
                    style={{ width: '100%' }}
                  />
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.76rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-dim)' }}>Corner Rounding</span>
                    <span style={{ color: 'var(--primary)' }}>{radiusPct}%</span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    step={5}
                    value={radiusPct}
                    onChange={(e) => setRadiusPct(Number(e.target.value))}
                    style={{ width: '100%' }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
                    Square Backdrop Fill
                  </label>
                  <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap', alignItems: 'center' }}>
                    {(
                      [
                        { id: 'transparent', label: 'Transparent' },
                        { id: 'dark', label: 'Dark Slate' },
                        { id: 'white', label: 'White' },
                        { id: 'custom', label: 'Custom' }
                      ] as const
                    ).map((opt) => (
                      <button
                        key={opt.id}
                        type="button"
                        className={`btn-glass ${bgMode === opt.id ? 'btn-primary' : ''}`}
                        style={{ fontSize: '0.74rem', padding: '0.28rem 0.55rem' }}
                        onClick={() => setBgMode(opt.id)}
                      >
                        {opt.label}
                      </button>
                    ))}
                    {bgMode === 'custom' && (
                      <input
                        type="color"
                        value={bgColor}
                        onChange={(e) => setBgColor(e.target.value)}
                        style={{ width: '32px', height: '28px', border: 'none', background: 'transparent', cursor: 'pointer' }}
                      />
                    )}
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                  <button type="button" className="btn-glass" style={{ fontSize: '0.74rem' }} onClick={handleReset}>
                    <RotateCcw size={13} /> Reset Framing
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn-glass" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="button"
            className="btn-glass btn-primary"
            disabled={!loadedImg || Boolean(loadError)}
            onClick={handleConfirm}
          >
            <Check size={15} /> Apply Square Icon
          </button>
        </div>
      </div>
    </div>
  );
};

