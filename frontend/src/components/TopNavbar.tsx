import React, { useState, useEffect, useRef } from 'react';
import { Search, Download, Bell, User, Menu, AlertTriangle, CheckCircle, Info, RefreshCw, X, UserCheck, Monitor } from 'lucide-react';
import { Tenant, AppNotification, Device } from '../types/index.js';
import { fetchNotifications, markNotificationRead, executeNotificationAction } from '../services/api.js';

interface TopNavbarProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  tenants: Tenant[];
  selectedTenantId: string;
  onTenantChange: (id: string) => void;
  onDownloadInstaller: () => void;
  onOpenGuestAccess?: () => void;
  onToggleMobileSidebar: () => void;
  devices?: Device[];
  onSelectDevice?: (device: Device) => void;
  onSelectView?: (view: string) => void;
}

export const TopNavbar: React.FC<TopNavbarProps> = ({
  searchQuery,
  onSearchChange,
  tenants,
  selectedTenantId,
  onTenantChange,
  onDownloadInstaller,
  onOpenGuestAccess,
  onToggleMobileSidebar,
  devices = [],
  onSelectDevice,
  onSelectView
}) => {
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [actingId, setActingId] = useState<string | null>(null);
  const [searchFocused, setSearchFocused] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchWrapperRef = useRef<HTMLDivElement>(null);

  const loadNotifications = async () => {
    try {
      const data = await fetchNotifications();
      if (Array.isArray(data)) {
        setNotifications(data);
      }
    } catch (err) {
      console.error('Failed to load notifications:', err);
    }
  };

  useEffect(() => {
    loadNotifications();
    const interval = setInterval(loadNotifications, 30000);
    return () => clearInterval(interval);
  }, []);

  // Ctrl+K / Cmd+K Quick Jump Shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
        setSearchFocused(true);
      } else if (e.key === 'Escape') {
        setSearchFocused(false);
        setIsOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Close dropdowns on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
      if (searchWrapperRef.current && !searchWrapperRef.current.contains(e.target as Node)) {
        setSearchFocused(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const unreadCount = notifications.filter((n) => !n.is_read).length;

  const handleMarkAsRead = async (id: string) => {
    await markNotificationRead(id);
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, is_read: 1 } : n)));
  };

  const handleExecuteAction = async (notifId: string, actionKey: string, tenantId?: string) => {
    setActingId(notifId);
    try {
      await executeNotificationAction(notifId, actionKey, tenantId);
      await loadNotifications();
    } catch (err) {
      console.error('Failed to execute notification action:', err);
    } finally {
      setActingId(null);
    }
  };

  const quickMatchingDevices = searchQuery.trim()
    ? devices
        .filter((d) => {
          const q = searchQuery.toLowerCase();
          return (
            d.hostname.toLowerCase().includes(q) ||
            d.ip_address.toLowerCase().includes(q) ||
            d.serial_number.toLowerCase().includes(q) ||
            d.device_role.toLowerCase().includes(q)
          );
        })
        .slice(0, 5)
    : [];

  return (
    <header className="topbar" id="app-topbar">
      <div className="topbar-left">
        <button
          className="mobile-menu-btn btn-glass"
          onClick={onToggleMobileSidebar}
          id="mobile-menu-toggle-btn"
          aria-label="Toggle Navigation Menu"
        >
          <Menu size={20} />
        </button>
        <div className="topbar-search" ref={searchWrapperRef} style={{ position: 'relative' }}>
          <Search size={16} />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Quick search endpoints, IP, BitLocker, role... (Ctrl+K)"
            value={searchQuery}
            onFocus={() => setSearchFocused(true)}
            onChange={(e) => {
              onSearchChange(e.target.value);
              setSearchFocused(true);
            }}
            id="global-search-input"
          />
          {searchQuery && (
            <button
              onClick={() => onSearchChange('')}
              style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', padding: '0 4px' }}
              title="Clear search"
            >
              <X size={14} />
            </button>
          )}

          {searchFocused && searchQuery.trim().length > 0 && (
            <div
              style={{
                position: 'absolute',
                top: 'calc(100% + 8px)',
                left: 0,
                right: 0,
                background: 'rgba(15, 23, 42, 0.97)',
                backdropFilter: 'blur(20px)',
                border: '1px solid rgba(255, 255, 255, 0.14)',
                borderRadius: '10px',
                boxShadow: '0 18px 36px rgba(0, 0, 0, 0.65)',
                zIndex: 1100,
                padding: '0.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.25rem'
              }}
            >
              <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', padding: '0.25rem 0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Quick Endpoint Jump ({quickMatchingDevices.length})
              </div>
              {quickMatchingDevices.length === 0 ? (
                <div style={{ padding: '0.65rem', fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                  No matching endpoints for &ldquo;{searchQuery}&rdquo;
                </div>
              ) : (
                quickMatchingDevices.map((d) => (
                  <button
                    key={d.id}
                    onClick={() => {
                      if (onSelectDevice) onSelectDevice(d);
                      setSearchFocused(false);
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '0.55rem 0.75rem',
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid rgba(255, 255, 255, 0.06)',
                      borderRadius: '6px',
                      color: '#fff',
                      cursor: 'pointer',
                      textAlign: 'left'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <Monitor size={14} color="var(--primary)" />
                      <div>
                        <div style={{ fontSize: '0.82rem', fontWeight: 600 }}>{d.hostname}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                          {d.ip_address} • {d.tenant_name || d.device_role}
                        </div>
                      </div>
                    </div>
                    <span className={`status-pill status-${d.status === 'online' ? 'online' : 'isolated'}`} style={{ fontSize: '0.68rem' }}>
                      {d.status}
                    </span>
                  </button>
                ))
              )}
              {onSelectView && (
                <button
                  onClick={() => {
                    onSelectView('dashboard');
                    setSearchFocused(false);
                  }}
                  style={{
                    marginTop: '0.25rem',
                    padding: '0.45rem 0.75rem',
                    background: 'rgba(0, 242, 254, 0.1)',
                    border: '1px solid rgba(0, 242, 254, 0.25)',
                    borderRadius: '6px',
                    color: 'var(--primary)',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    textAlign: 'center'
                  }}
                >
                  View all filtered results in Fleet Dashboard →
                </button>
              )}
            </div>
          )}
        </div>

        <select
          className="glass-select"
          style={{ width: '220px', padding: '0.45rem 0.85rem' }}
          value={selectedTenantId}
          onChange={(e) => onTenantChange(e.target.value)}
          id="tenant-filter-select"
        >
          <option value="all">🏢 All Clients (MSP View)</option>
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} ({t.device_count} devices)
            </option>
          ))}
        </select>
      </div>

      <div className="topbar-right">
        <div className="mesh-status-indicator" title="Connected to MeshCentral 2 Core via WebSocket Relay">
          <div className="pulse-dot" />
          <span>MeshCentral Engine Live</span>
        </div>

        <button
          className="btn-glass"
          onClick={onDownloadInstaller}
          title="Generate on-demand tokenized agent installer"
          id="btn-gen-installer"
        >
          <Download size={15} />
          <span>Agent Installer</span>
        </button>

        {onOpenGuestAccess && (
          <button
            className="btn-glass"
            onClick={onOpenGuestAccess}
            title="Manage Vendor / Guest Temporary Access Passes"
            id="btn-vendor-access"
          >
            <UserCheck size={15} />
            <span>Vendor Access</span>
          </button>
        )}

        {/* Notification Bell with Badge and Interactive Popup */}
        <div style={{ position: 'relative' }} ref={notifRef}>
          <button
            className="btn-glass btn-icon"
            title="System & Sync Notifications"
            id="btn-alerts"
            onClick={() => setIsOpen(!isOpen)}
            style={{ position: 'relative' }}
          >
            <Bell size={16} />
            {unreadCount > 0 && (
              <span
                style={{
                  position: 'absolute',
                  top: '-4px',
                  right: '-4px',
                  background: 'linear-gradient(135deg, #f59e0b, #ef4444)',
                  color: '#fff',
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  width: '18px',
                  height: '18px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 8px rgba(239, 68, 68, 0.6)'
                }}
              >
                {unreadCount}
              </span>
            )}
          </button>

          {isOpen && (
            <div
              style={{
                position: 'absolute',
                top: 'calc(100% + 10px)',
                right: 0,
                width: '420px',
                maxHeight: '520px',
                background: 'rgba(15, 23, 42, 0.95)',
                backdropFilter: 'blur(20px)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: '12px',
                boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)',
                zIndex: 1000,
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden'
              }}
              id="notifications-dropdown-menu"
            >
              {/* Header */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '1rem 1.25rem',
                  borderBottom: '1px solid rgba(255, 255, 255, 0.08)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Bell size={16} color="var(--accent-primary, #00f2fe)" />
                  <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>Notifications</span>
                  {unreadCount > 0 && (
                    <span
                      style={{
                        fontSize: '0.7rem',
                        padding: '0.15rem 0.5rem',
                        background: 'rgba(239, 68, 68, 0.2)',
                        color: '#f87171',
                        borderRadius: '9999px',
                        border: '1px solid rgba(239, 68, 68, 0.3)'
                      }}
                    >
                      {unreadCount} new
                    </span>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  {unreadCount > 0 && (
                    <button
                      onClick={async () => {
                        for (const n of notifications.filter((x) => !x.is_read)) {
                          await markNotificationRead(n.id);
                        }
                        setNotifications((prev) => prev.map((n) => ({ ...n, is_read: 1 })));
                      }}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-dim)',
                        fontSize: '0.75rem',
                        cursor: 'pointer',
                        textDecoration: 'underline'
                      }}
                    >
                      Mark all read
                    </button>
                  )}
                  <button
                    onClick={() => setIsOpen(false)}
                    style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}
                  >
                    <X size={16} />
                  </button>
                </div>
              </div>

              {/* Body */}
              <div style={{ overflowY: 'auto', padding: '0.75rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                {notifications.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-dim)' }}>
                    <CheckCircle size={32} style={{ margin: '0 auto 0.5rem', color: 'var(--accent-success, #10b981)' }} />
                    <p style={{ margin: 0, fontSize: '0.85rem' }}>All caught up! No active alerts.</p>
                  </div>
                ) : (
                  notifications.map((notif) => {
                    let parsedActions: Array<{ action: string; label: string; tenantId?: string; primary?: boolean; danger?: boolean }> = [];
                    if (notif.actions_json) {
                      try {
                        parsedActions = JSON.parse(notif.actions_json);
                      } catch {
                        parsedActions = [];
                      }
                    }

                    const isDanger = notif.severity === 'danger' || notif.severity === 'error' || notif.severity === 'critical';
                    const severityColor = isDanger ? '#ef4444' : notif.severity === 'warning' ? '#f59e0b' : '#38bdf8';

                    return (
                      <div
                        key={notif.id}
                        style={{
                          background: notif.is_read ? 'rgba(255, 255, 255, 0.02)' : 'rgba(255, 255, 255, 0.06)',
                          borderLeft: `3px solid ${severityColor}`,
                          borderRadius: '8px',
                          padding: '0.85rem',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.45rem',
                          transition: 'all 0.2s'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.5rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            {notif.type === 'mesh_sync_conflict' ? (
                              <RefreshCw size={15} color={severityColor} />
                            ) : isDanger ? (
                              <AlertTriangle size={15} color={severityColor} />
                            ) : (
                              <Info size={15} color={severityColor} />
                            )}
                            <span style={{ fontWeight: 600, fontSize: '0.85rem', color: '#fff' }}>{notif.title}</span>
                          </div>
                          {!notif.is_read && (
                            <button
                              onClick={() => handleMarkAsRead(notif.id)}
                              title="Mark as read"
                              style={{
                                background: 'none',
                                border: 'none',
                                color: 'var(--text-dim)',
                                cursor: 'pointer',
                                padding: '2px'
                              }}
                            >
                              <CheckCircle size={14} />
                            </button>
                          )}
                        </div>

                        <p style={{ margin: 0, fontSize: '0.78rem', color: 'rgba(255, 255, 255, 0.8)', lineHeight: 1.4 }}>
                          {notif.message}
                        </p>

                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.2rem' }}>
                          <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>
                            {new Date(notif.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • {notif.type}
                          </span>

                          {parsedActions.length > 0 && (
                            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                              {parsedActions.map((act, idx) => (
                                <button
                                  key={idx}
                                  disabled={actingId === notif.id}
                                  onClick={() => handleExecuteAction(notif.id, act.action, act.tenantId)}
                                  className={act.danger ? 'btn-danger' : 'btn-glass'}
                                  style={{
                                    fontSize: '0.72rem',
                                    padding: '0.25rem 0.55rem',
                                    borderRadius: '4px',
                                    fontWeight: 500
                                  }}
                                >
                                  {actingId === notif.id ? 'Processing...' : act.label}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginLeft: '0.5rem' }}>
          <div
            style={{
              width: '34px',
              height: '34px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #00f2fe 0%, #7f00ff 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#fff'
            }}
          >
            <User size={18} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>TylerHats</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>MSP Super Admin</span>
          </div>
        </div>
      </div>
    </header>
  );
};
