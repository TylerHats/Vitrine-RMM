import React, { useState, useEffect, useCallback } from 'react';
import {
  BookOpen,
  Plus,
  Search,
  Pin,
  Edit3,
  Trash2,
  Play,
  Code2,
  Save,
  X,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Copy,
  Check,
  AlertCircle
} from 'lucide-react';
import { DocumentationArticle, Tenant, ScriptItem, Device, AuthUser } from '../types/index.js';
import {
  fetchDocumentation,
  createDocumentationArticle,
  updateDocumentationArticle,
  deleteDocumentationArticle,
  revealDocumentationSecrets,
  fetchScripts,
  runScript
} from '../services/api.js';
import { canMutateFleet } from '../utils/permissions.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { MfaChallengeModal } from '../components/MfaChallengeModal.js';

interface DocumentationViewProps {
  tenants: Tenant[];
  devices: Device[];
  selectedTenantId: string;
  currentUser?: AuthUser | null;
}

export const DocumentationView: React.FC<DocumentationViewProps> = ({
  tenants,
  devices,
  selectedTenantId,
  currentUser
}) => {
  const [articles, setArticles] = useState<DocumentationArticle[]>([]);
  const [scripts, setScripts] = useState<ScriptItem[]>([]);
  const [selectedArticleId, setSelectedArticleId] = useState<string | null>(null);
  const [searchText, setSearchText] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [isEditing, setIsEditing] = useState(false);
  const [creatingNew, setCreatingNew] = useState(false);

  // Editor state
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('SOP Runbook');
  const [docTenantId, setDocTenantId] = useState('');
  const [tagsInput, setTagsInput] = useState('');
  const [isPinned, setIsPinned] = useState(false);
  const [linkedScriptId, setLinkedScriptId] = useState('');
  const [contentMarkdown, setContentMarkdown] = useState('');
  const [secretsDraft, setSecretsDraft] = useState<Array<{ label: string; value: string }>>([]);
  const [secretsModified, setSecretsModified] = useState(false);
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, Array<{ label: string; value: string }>>>({});
  const [copiedSecretIdx, setCopiedSecretIdx] = useState<number | null>(null);
  const [mfaPending, setMfaPending] = useState<{
    mode: 'reveal_reader' | 'unlock_editor' | 'save_article';
    articleId?: string;
  } | null>(null);

  // Quick-run linked script state
  const [targetDeviceId, setTargetDeviceId] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [noticeIsError, setNoticeIsError] = useState(false);

  const allowEdit = canMutateFleet(currentUser);

  const loadDocs = useCallback(async () => {
    const [docs, scList] = await Promise.all([
      fetchDocumentation({
        tenant_id: selectedTenantId !== 'all' ? selectedTenantId : undefined,
        category: categoryFilter !== 'all' ? categoryFilter : undefined,
        search: searchText.trim() || undefined
      }),
      currentUser?.role !== 'client_admin' ? fetchScripts().catch(() => []) : Promise.resolve([])
    ]);
    setArticles(docs);
    setScripts(scList);
    if (docs.length > 0) {
      setSelectedArticleId((prev) => prev || (docs[0]?.id ?? null));
    }
  }, [selectedTenantId, categoryFilter, searchText, currentUser?.role]);

  useEffect(() => {
    loadDocs();
  }, [loadDocs]);

  const activeArticle = articles.find((a) => a.id === selectedArticleId) || null;
  const isVaultLockedInEditor = Boolean(
    !creatingNew && activeArticle && activeArticle.has_encrypted_secrets && !revealedSecrets[activeArticle.id]
  );

  const startNewArticle = () => {
    setCreatingNew(true);
    setIsEditing(true);
    setTitle('');
    setCategory('SOP Runbook');
    setDocTenantId(selectedTenantId !== 'all' ? selectedTenantId : '');
    setTagsInput('network, recovery');
    setIsPinned(false);
    setLinkedScriptId('');
    setSecretsDraft([]);
    setSecretsModified(false);
    setContentMarkdown(
      '# Standard Operating Procedure\n\n## Overview\nDocument architecture, escalation contacts, and verification steps here.\n\n## Remediation Steps\n1. Verify endpoint telemetry.\n2. Run linked automation script if applicable.'
    );
  };

  const startEditSelected = () => {
    if (!activeArticle) return;
    setCreatingNew(false);
    setIsEditing(true);
    setTitle(activeArticle.title);
    setCategory(activeArticle.category);
    setDocTenantId(activeArticle.tenant_id || '');
    setTagsInput((activeArticle.tags || []).join(', '));
    setIsPinned(Boolean(activeArticle.is_pinned));
    setLinkedScriptId(activeArticle.linked_script_id || '');
    setSecretsDraft(revealedSecrets[activeArticle.id] ? [...revealedSecrets[activeArticle.id]] : []);
    setSecretsModified(false);
    setContentMarkdown(activeArticle.content_markdown);
  };

  const performRevealSecrets = async (articleId: string, populateEditorDraft: boolean) => {
    setNotice(null);
    setNoticeIsError(false);
    try {
      const res = await revealDocumentationSecrets(articleId);
      if (res.mfaRequired) {
        setMfaPending({ mode: populateEditorDraft ? 'unlock_editor' : 'reveal_reader', articleId });
        return;
      }
      if (res.success && res.secrets) {
        setRevealedSecrets((prev) => ({ ...prev, [articleId]: res.secrets! }));
        if (populateEditorDraft) {
          setSecretsDraft(res.secrets.map((s) => ({ ...s })));
          setSecretsModified(false);
        }
      } else {
        setNoticeIsError(true);
        setNotice(res.error || 'Failed to decrypt runbook vault credentials.');
      }
    } catch (err: any) {
      setNoticeIsError(true);
      setNotice(err?.message || 'Failed to decrypt runbook vault credentials.');
    }
  };

  const performSaveArticle = async () => {
    setNotice(null);
    setNoticeIsError(false);
    if (!title.trim() || !contentMarkdown.trim()) {
      setNoticeIsError(true);
      setNotice('Title and Markdown content are required.');
      return;
    }
    const tags = tagsInput
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    const validSecrets = secretsDraft
      .map((s) => ({ label: s.label.trim(), value: s.value.trim() }))
      .filter((s) => s.label && s.value);

    if (creatingNew) {
      const res = await createDocumentationArticle({
        title: title.trim(),
        category,
        tenant_id: docTenantId || null,
        tags,
        is_pinned: isPinned,
        linked_script_id: linkedScriptId || null,
        content_markdown: contentMarkdown,
        secrets: validSecrets.length > 0 ? validSecrets : undefined
      });
      if (res.mfaRequired) {
        setMfaPending({ mode: 'save_article' });
        return;
      }
      if (res.success && res.article) {
        setCreatingNew(false);
        setIsEditing(false);
        setSecretsModified(false);
        setSelectedArticleId(res.article.id);
        setNoticeIsError(false);
        setNotice(`✓ Created runbook "${res.article.title}".`);
        loadDocs();
      } else {
        setNoticeIsError(true);
        setNotice(`Failed to save article: ${res.error || 'Unknown error'}`);
      }
    } else if (activeArticle) {
      const updates: Record<string, any> = {
        title: title.trim(),
        category,
        tenant_id: docTenantId || null,
        tags,
        is_pinned: isPinned,
        linked_script_id: linkedScriptId || null,
        content_markdown: contentMarkdown
      };
      if (secretsModified) {
        updates.secrets = validSecrets;
      }
      const res = await updateDocumentationArticle(activeArticle.id, updates);
      if (res.mfaRequired) {
        setMfaPending({ mode: 'save_article', articleId: activeArticle.id });
        return;
      }
      if (res.success) {
        if (secretsModified) {
          setRevealedSecrets((prev) => {
            const copy = { ...prev };
            if (validSecrets.length > 0) {
              copy[activeArticle.id] = validSecrets;
            } else {
              delete copy[activeArticle.id];
            }
            return copy;
          });
        }
        setSecretsModified(false);
        setIsEditing(false);
        setNoticeIsError(false);
        setNotice(`✓ Updated runbook "${title.trim()}".`);
        loadDocs();
      } else {
        setNoticeIsError(true);
        setNotice(`Failed to update article: ${res.error || 'Unknown error'}`);
      }
    }
  };

  const handleSaveArticle = async (e: React.FormEvent) => {
    e.preventDefault();
    await performSaveArticle();
  };

  const handleRunLinkedScript = async () => {
    if (!activeArticle?.linked_script_id || !targetDeviceId) return;
    setNotice(null);
    setNoticeIsError(false);
    const res = await runScript(activeArticle.linked_script_id, [targetDeviceId]);
    if (res.success) {
      setNoticeIsError(false);
      setNotice(`✓ Dispatched linked runbook script to endpoint (Execution ID: ${res.executionId}).`);
    } else {
      setNoticeIsError(true);
      setNotice(`Script dispatch failed: ${res.error || 'Unknown error'}`);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }} id="documentation-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>
            MSP Documentation, SOPs &amp; Runbooks
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Tenant-scoped knowledge base, architecture notes &amp; executable runbook links (NinjaOne Docs / IT Glue parity)
          </span>
        </div>

        {allowEdit && (
          <button type="button" className="btn-glass btn-primary" onClick={startNewArticle} id="btn-new-doc-article">
            <Plus size={15} /> New Runbook / Article
          </button>
        )}
      </div>

      {notice && (
        <div
          className="glass-card"
          style={{
            padding: '0.75rem 1.15rem',
            background: noticeIsError ? 'rgba(239, 68, 68, 0.14)' : 'rgba(16, 185, 129, 0.12)',
            borderColor: noticeIsError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)',
            color: noticeIsError ? '#f87171' : '#34d399',
            display: 'flex',
            alignItems: 'center',
            gap: '0.55rem',
            fontSize: '0.82rem'
          }}
        >
          {noticeIsError && <AlertCircle size={15} style={{ flexShrink: 0 }} />}
          <span>{notice}</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: '1.25rem', alignItems: 'start' }}>
        {/* Left Sidebar: Search & Article Index */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: '0.75rem', top: '0.68rem', color: 'var(--text-dim)' }} />
            <input
              type="text"
              className="glass-input"
              style={{ paddingLeft: '2.1rem', fontSize: '0.8rem' }}
              placeholder="Search titles, markdown, tags..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
            />
          </div>

          <select
            className="glass-select"
            style={{ fontSize: '0.78rem' }}
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
          >
            <option value="all">All Categories</option>
            <option value="SOP Runbook">SOP Runbook</option>
            <option value="Network & Firewall">Network &amp; Firewall</option>
            <option value="Active Directory & Identity">Active Directory &amp; Identity</option>
            <option value="Backup & Disaster Recovery">Backup &amp; Disaster Recovery</option>
            <option value="Vendor & Licensing">Vendor &amp; Licensing</option>
          </select>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', maxHeight: '540px', overflowY: 'auto' }}>
            {articles.length === 0 ? (
              <div style={{ padding: '1.5rem 0.75rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                No documentation articles yet. Create your first Global or Client SOP runbook.
              </div>
            ) : (
              articles.map((art) => {
                const selected = art.id === selectedArticleId && !creatingNew;
                return (
                  <button
                    key={art.id}
                    type="button"
                    onClick={() => {
                      setCreatingNew(false);
                      setIsEditing(false);
                      setSelectedArticleId(art.id);
                    }}
                    style={{
                      textAlign: 'left',
                      padding: '0.7rem 0.85rem',
                      borderRadius: '8px',
                      border: `1px solid ${selected ? 'var(--primary)' : 'var(--glass-border)'}`,
                      background: selected ? 'rgba(0, 242, 254, 0.1)' : 'rgba(148, 163, 184, 0.05)',
                      color: 'var(--text-main)',
                      cursor: 'pointer'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.4rem' }}>
                      <strong style={{ fontSize: '0.84rem' }}>{art.title}</strong>
                      {Boolean(art.is_pinned) && <Pin size={13} color="#fbbf24" />}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                      {art.category} • {art.tenant_name || 'Global MSP'}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right Pane: Article Reader or Editor */}
        <div className="glass-card" style={{ minHeight: '460px' }}>
          {isEditing ? (
            <form onSubmit={handleSaveArticle} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0 }}>
                  {creatingNew ? 'Create Documentation Runbook' : 'Edit Documentation Runbook'}
                </h3>
                <button
                  type="button"
                  className="btn-glass btn-icon"
                  onClick={() => {
                    setIsEditing(false);
                    setCreatingNew(false);
                  }}
                >
                  <X size={16} />
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label className="form-label">Article Title</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="e.g. Domain Controller Emergency Recovery SOP"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label">Category</label>
                  <select className="glass-select" value={category} onChange={(e) => setCategory(e.target.value)}>
                    <option value="SOP Runbook">SOP Runbook</option>
                    <option value="Network & Firewall">Network &amp; Firewall</option>
                    <option value="Active Directory & Identity">Active Directory &amp; Identity</option>
                    <option value="Backup & Disaster Recovery">Backup &amp; Disaster Recovery</option>
                    <option value="Vendor & Licensing">Vendor &amp; Licensing</option>
                  </select>
                </div>
                <div>
                  <label className="form-label">Client Scope</label>
                  <select className="glass-select" value={docTenantId} onChange={(e) => setDocTenantId(e.target.value)}>
                    <option value="">Global MSP Knowledge Base</option>
                    {tenants.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr auto', gap: '0.85rem', alignItems: 'end' }}>
                <div>
                  <label className="form-label">Linked Automation Script (1-Click Runbook)</label>
                  <select
                    className="glass-select"
                    value={linkedScriptId}
                    onChange={(e) => setLinkedScriptId(e.target.value)}
                  >
                    <option value="">-- Optional Linked Script --</option>
                    {scripts.map((sc) => (
                      <option key={sc.id} value={sc.id}>
                        {sc.name} ({sc.language})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="form-label">Tags (comma-separated)</label>
                  <input
                    type="text"
                    className="glass-input"
                    placeholder="vpn, firewall, escalation"
                    value={tagsInput}
                    onChange={(e) => setTagsInput(e.target.value)}
                  />
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', cursor: 'pointer', fontSize: '0.82rem', paddingBottom: '0.5rem' }}>
                  <input type="checkbox" checked={isPinned} onChange={(e) => setIsPinned(e.target.checked)} />
                  <span>Pin SOP</span>
                </label>
              </div>

              <div>
                <label className="form-label">Markdown Runbook Body</label>
                <textarea
                  className="glass-input"
                  rows={12}
                  style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeight: 1.55 }}
                  value={contentMarkdown}
                  onChange={(e) => setContentMarkdown(e.target.value)}
                />
              </div>

              <div
                style={{
                  padding: '0.85rem 1rem',
                  borderRadius: '8px',
                  border: '1px solid rgba(251, 191, 36, 0.3)',
                  background: 'rgba(251, 191, 36, 0.06)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.6rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <Lock size={14} color="#fbbf24" /> AES-256-GCM Encrypted Vault Credentials (Step-Up MFA Protected)
                  </span>
                  {!isVaultLockedInEditor && (
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem' }}
                      onClick={() => {
                        setSecretsDraft((prev) => [...prev, { label: '', value: '' }]);
                        setSecretsModified(true);
                      }}
                    >
                      <Plus size={12} /> Add Secret
                    </button>
                  )}
                </div>

                {isVaultLockedInEditor && activeArticle ? (
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '0.75rem',
                      padding: '0.65rem 0.85rem',
                      borderRadius: '6px',
                      background: 'rgba(15, 23, 42, 0.55)',
                      border: '1px solid rgba(251, 191, 36, 0.35)'
                    }}
                  >
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      Existing encrypted credentials are protected in the vault. Unlock them with Step-Up MFA before adding, editing, or removing secrets (markdown edits can still be saved safely without unlocking).
                    </span>
                    <button
                      type="button"
                      className="btn-glass"
                      style={{ fontSize: '0.75rem', borderColor: 'rgba(251, 191, 36, 0.45)', color: '#fbbf24' }}
                      onClick={() => performRevealSecrets(activeArticle.id, true)}
                    >
                      <Unlock size={13} /> Unlock Existing Secrets (MFA) to Edit
                    </button>
                  </div>
                ) : (
                  secretsDraft.map((sec, idx) => (
                    <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr auto', gap: '0.5rem' }}>
                      <input
                        type="text"
                        className="glass-input"
                        placeholder="Credential Label (e.g. Firewall Admin)"
                        value={sec.label}
                        onChange={(e) => {
                          setSecretsDraft((prev) =>
                            prev.map((it, i) => (i === idx ? { ...it, label: e.target.value } : it))
                          );
                          setSecretsModified(true);
                        }}
                      />
                      <input
                        type="password"
                        className="glass-input"
                        placeholder="Secret Value / Recovery Token"
                        value={sec.value}
                        onChange={(e) => {
                          setSecretsDraft((prev) =>
                            prev.map((it, i) => (i === idx ? { ...it, value: e.target.value } : it))
                          );
                          setSecretsModified(true);
                        }}
                      />
                      <button
                        type="button"
                        className="btn-glass btn-icon"
                        onClick={() => {
                          setSecretsDraft((prev) => prev.filter((_, i) => i !== idx));
                          setSecretsModified(true);
                        }}
                      >
                        <Trash2 size={13} color="#ef4444" />
                      </button>
                    </div>
                  ))
                )}
              </div>

              <div style={{ display: 'flex', gap: '0.6rem' }}>
                <button type="submit" className="btn-glass btn-primary">
                  <Save size={15} /> Save Runbook
                </button>
                <button
                  type="button"
                  className="btn-glass"
                  onClick={() => {
                    setIsEditing(false);
                    setCreatingNew(false);
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : activeArticle ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap', borderBottom: '1px solid var(--glass-border)', paddingBottom: '0.9rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
                    <BookOpen size={20} color="var(--primary)" />
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0 }}>{activeArticle.title}</h3>
                    {Boolean(activeArticle.is_pinned) && (
                      <span className="status-pill status-reboot" style={{ fontSize: '0.66rem' }}>
                        PINNED SOP
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
                    Category: <strong>{activeArticle.category}</strong> • Scope:{' '}
                    <strong>{activeArticle.tenant_name || 'Global MSP'}</strong> • Updated{' '}
                    {new Date(activeArticle.updated_at).toLocaleString()} by {activeArticle.last_edited_by || activeArticle.author}
                  </div>
                  {(activeArticle.tags || []).length > 0 && (
                    <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginTop: '0.45rem' }}>
                      {activeArticle.tags.map((t) => (
                        <span
                          key={t}
                          style={{
                            fontSize: '0.68rem',
                            padding: '0.12rem 0.5rem',
                            borderRadius: '999px',
                            background: 'rgba(56, 189, 248, 0.12)',
                            color: '#38bdf8'
                          }}
                        >
                          #{t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {allowEdit && (
                  <div style={{ display: 'flex', gap: '0.45rem' }}>
                    <button type="button" className="btn-glass" style={{ fontSize: '0.76rem' }} onClick={startEditSelected}>
                      <Edit3 size={14} /> Edit
                    </button>
                    <button
                      type="button"
                      className="btn-glass btn-icon"
                      onClick={async () => {
                        if (!confirm(`Delete documentation article "${activeArticle.title}"?`)) return;
                        await deleteDocumentationArticle(activeArticle.id);
                        setSelectedArticleId(null);
                        loadDocs();
                      }}
                    >
                      <Trash2 size={14} color="#ef4444" />
                    </button>
                  </div>
                )}
              </div>

              {activeArticle.linked_script_id && allowEdit && (
                <div
                  style={{
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid rgba(16, 185, 129, 0.35)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '0.75rem'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem' }}>
                    <Code2 size={16} color="#34d399" />
                    <span>
                      Linked Executable Runbook:{' '}
                      <strong>{activeArticle.linked_script_name || activeArticle.linked_script_id}</strong>
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <select
                      className="glass-select"
                      style={{ width: 'auto', fontSize: '0.76rem' }}
                      value={targetDeviceId}
                      onChange={(e) => setTargetDeviceId(e.target.value)}
                    >
                      <option value="">-- Select Target Endpoint --</option>
                      {devices.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.hostname} ({d.ip_address})
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      className="btn-glass btn-primary"
                      style={{ fontSize: '0.76rem' }}
                      disabled={!targetDeviceId}
                      onClick={handleRunLinkedScript}
                    >
                      <Play size={13} /> Execute Runbook
                    </button>
                  </div>
                </div>
              )}

              {Boolean(activeArticle.has_encrypted_secrets) && (
                <div
                  style={{
                    padding: '0.8rem 1rem',
                    borderRadius: '8px',
                    background: 'rgba(251, 191, 36, 0.08)',
                    border: '1px solid rgba(251, 191, 36, 0.35)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.6rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.82rem', fontWeight: 600 }}>
                      <Lock size={15} color="#fbbf24" /> Encrypted Runbook Credentials Attached (AES-256-GCM)
                    </span>
                    {revealedSecrets[activeArticle.id] ? (
                      <button
                        type="button"
                        className="btn-glass"
                        style={{ fontSize: '0.75rem' }}
                        onClick={() =>
                          setRevealedSecrets((prev) => {
                            const copy = { ...prev };
                            delete copy[activeArticle.id];
                            return copy;
                          })
                        }
                      >
                        <EyeOff size={13} /> Hide Vault Secrets
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="btn-glass"
                        style={{ fontSize: '0.75rem' }}
                        onClick={() => performRevealSecrets(activeArticle.id, false)}
                      >
                        <Eye size={13} /> Reveal Vault Secrets
                      </button>
                    )}
                  </div>
                  {revealedSecrets[activeArticle.id] && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                      {revealedSecrets[activeArticle.id].map((sec, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            gap: '0.5rem',
                            padding: '0.45rem 0.7rem',
                            borderRadius: '6px',
                            background: 'rgba(15, 23, 42, 0.5)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.78rem'
                          }}
                        >
                          <span style={{ color: 'var(--text-muted)' }}>{sec.label}</span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <strong style={{ color: '#fde68a' }}>{sec.value}</strong>
                            <button
                              type="button"
                              className="btn-glass btn-icon"
                              style={{ padding: '0.2rem 0.35rem' }}
                              title="Copy credential"
                              onClick={async () => {
                                const ok = await copyToClipboard(sec.value);
                                if (ok) {
                                  setCopiedSecretIdx(idx);
                                  setTimeout(() => setCopiedSecretIdx(null), 1800);
                                }
                              }}
                            >
                              {copiedSecretIdx === idx ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <pre
                style={{
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                  fontFamily: 'var(--font-sans)',
                  fontSize: '0.88rem',
                  lineHeight: 1.65,
                  color: 'var(--text-main)'
                }}
              >
                {activeArticle.content_markdown}
              </pre>
            </div>
          ) : (
            <div style={{ padding: '3rem 1.5rem', textAlign: 'center', color: 'var(--text-dim)' }}>
              <BookOpen size={36} style={{ opacity: 0.45, marginBottom: '0.75rem' }} />
              <div style={{ fontSize: '0.92rem' }}>Select an SOP Runbook on the left or create a new article.</div>
            </div>
          )}
        </div>
      </div>

      <MfaChallengeModal
        isOpen={Boolean(mfaPending)}
        onClose={() => setMfaPending(null)}
        onSuccess={() => {
          const pending = mfaPending;
          setMfaPending(null);
          if (!pending) return;
          if (pending.mode === 'reveal_reader' && pending.articleId) {
            performRevealSecrets(pending.articleId, false);
          } else if (pending.mode === 'unlock_editor' && pending.articleId) {
            performRevealSecrets(pending.articleId, true);
          } else if (pending.mode === 'save_article') {
            performSaveArticle();
          }
        }}
        title="Step-Up MFA: Documentation Vault Credentials"
        description="Enter your 6-digit TOTP authenticator code or recovery code to decrypt or modify AES-256-GCM runbook secrets."
        secretType="documentation_vault"
      />
    </div>
  );
};
